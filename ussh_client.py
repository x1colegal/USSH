import argparse
import hashlib
import os
import select
import signal
import socket
import sys
import termios
import threading
import time
import tty

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_DATA, TYPE_HELLO as USTP_TYPE_HELLO, TYPE_RETRANSMIT_REQUEST
from ustp import USTPReceiver, USTPSender, parse_packet
from ussh_proto import HEADER_SIZE, TYPE_CLOSE, TYPE_EXIT, TYPE_HELLO, TYPE_PING, TYPE_PONG, TYPE_READY, TYPE_STDOUT, TYPE_STDIN, TYPE_RESIZE, mkp, USHPacket
from ussh_proto import TYPE_AUTH_FAIL


def derive_session_psk(base_psk: str, password: str, client_nonce: bytes, server_nonce: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"USSH-session-v1\0")
    h.update(base_psk.encode("utf-8"))
    h.update(b"\0")
    h.update(password.encode("utf-8"))
    h.update(b"\0")
    h.update(client_nonce)
    h.update(server_nonce)
    return h.digest()


def resolve_host_ips(host: str) -> set[str]:
    ips = set()
    for item in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM):
        sockaddr = item[4]
        if sockaddr:
            ips.add(sockaddr[0])
    if not ips:
        ips.add(socket.gethostbyname(host))
    return ips


def get_winsize():
    try:
        import fcntl
        import struct
        import termios as t

        packed = fcntl.ioctl(sys.stdin.fileno(), t.TIOCGWINSZ, b"\x00\x00\x00\x00")
        rows, cols, _, _ = struct.unpack("HHHH", packed)
        return rows, cols
    except Exception:
        return 24, 80


def main() -> None:
    ap = argparse.ArgumentParser(description="USSH client")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=5322)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=0)
    ap.add_argument("--psk", required=True)
    ap.add_argument("--password", required=True, help="USSH login password")
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--connect-timeout", type=float, default=8.0)
    ap.add_argument("--session-timeout", type=float, default=12.0)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    args = ap.parse_args()

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    resolved_peer_ip = sorted(resolved_peer_ips)[0]
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, psk=args.psk, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))
    peer = (resolved_peer_ip, args.peer_port)
    session_addr = None
    sender = USTPSender(sock=sock, peer=peer, window=args.window, rto=args.rto, quiet=True)
    receiver = USTPReceiver(sock=sock, peer=peer)
    sender.start()
    client_nonce = os.urandom(16)

    running = True
    ready = threading.Event()
    last_rx = time.time()

    def send(pkt_type: int, payload: bytes = b"") -> None:
        chunk_size = MAX_PAYLOAD - HEADER_SIZE
        if not payload:
            sender.queue_payload(mkp(pkt_type, payload=b"").to_bytes())
            return
        for i in range(0, len(payload), chunk_size):
            sender.queue_payload(mkp(pkt_type, payload=payload[i : i + chunk_size]).to_bytes())

    def stdin_loop() -> None:
        while running:
            try:
                r, _, _ = select.select([sys.stdin.fileno()], [], [], 0.2)
            except Exception:
                continue
            if sys.stdin.fileno() not in r:
                continue
            try:
                data = os.read(sys.stdin.fileno(), 4096)
            except OSError:
                break
            if not data:
                break
            send(TYPE_STDIN, data)

    def nack_loop() -> None:
        while running:
            receiver.maybe_nack()
            time.sleep(0.03)

    print(
        f"[USSH-CLIENT] local={sock.getsockname()} peer={args.peer_ip}:{args.peer_port} "
        f"resolved={','.join(sorted(resolved_peer_ips))} aead={normalize_cipher_name(args.cipher)}"
    )
    send(TYPE_HELLO, b"USSH-AUTH1\0" + client_nonce + args.password.encode("utf-8"))

    def sigwinch(_signum, _frame):
        rows, cols = get_winsize()
        send(TYPE_RESIZE, rows.to_bytes(2, "big") + cols.to_bytes(2, "big"))

    signal.signal(signal.SIGWINCH, sigwinch)

    old = termios.tcgetattr(sys.stdin.fileno())
    stdin_started = False
    try:
        deadline = time.time() + args.connect_timeout
        threading.Thread(target=nack_loop, daemon=True).start()
        while running:
            if not ready.is_set() and time.time() >= deadline:
                raise SystemExit("USSH server did not reply with READY")
            if ready.is_set() and (time.time() - last_rx) >= args.session_timeout:
                raise SystemExit("USSH session timed out")
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                if not ready.is_set():
                    send(TYPE_HELLO, b"USSH-AUTH1\0" + client_nonce + args.password.encode("utf-8"))
                continue
            if session_addr is not None and addr != session_addr:
                continue
            try:
                ustp_pkt = parse_packet(rawp)
            except Exception:
                continue
            if not ustp_pkt:
                continue
            if ustp_pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, USTP_TYPE_HELLO):
                sender.on_control(ustp_pkt)
                continue
            if ustp_pkt.pkt_type != TYPE_DATA:
                continue
            payload = receiver.handle_data(ustp_pkt)
            if not payload:
                continue
            try:
                pkt = USHPacket.from_bytes(payload)
            except Exception:
                continue
            last_rx = time.time()
            if pkt.pkt_type == TYPE_AUTH_FAIL:
                raise SystemExit("USSH authentication failed")
            if pkt.pkt_type == TYPE_READY:
                if not pkt.payload.startswith(b"USSH-READY1\0") or len(pkt.payload) < len(b"USSH-READY1\0") + 16:
                    raise SystemExit("USSH server sent an invalid READY packet")
                rest = pkt.payload[len(b"USSH-READY1\0") :]
                server_nonce = rest[:16]
                session_cipher = rest[16:].decode("ascii", "replace") or normalize_cipher_name(args.cipher)
                session_addr = addr
                sender.peer = addr
                receiver.peer = addr
                sock.set_peer_psk(addr, derive_session_psk(args.psk, args.password, client_nonce, server_nonce), session_cipher)
                ready.set()
                print(f"[USSH-CLIENT] READY from {addr[0]}:{addr[1]} session-aead={session_cipher}")
                tty.setraw(sys.stdin.fileno())
                sigwinch(None, None)
                if not stdin_started:
                    threading.Thread(target=stdin_loop, daemon=True).start()
                    stdin_started = True
                continue
            if pkt.pkt_type == TYPE_STDOUT:
                os.write(sys.stdout.fileno(), pkt.payload)
                continue
            if pkt.pkt_type == TYPE_PING:
                if session_addr is None:
                    session_addr = addr
                send(TYPE_PONG, b"pong")
                continue
            if pkt.pkt_type == TYPE_EXIT:
                running = False
                break
            if pkt.pkt_type == TYPE_CLOSE:
                running = False
                break
        send(TYPE_CLOSE, b"")
    except KeyboardInterrupt:
        send(TYPE_CLOSE, b"")
    except SystemExit as exc:
        print(f"\n[USSH-CLIENT] {exc}", file=sys.stderr)
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        running = False
        sender.stop()


if __name__ == "__main__":
    main()
