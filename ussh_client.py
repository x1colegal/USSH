import argparse
import getpass
import os
import select
import signal
import socket
import sys
import termios
import threading
import time
import tty

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_DATA, TYPE_HELLO as USTP_TYPE_HELLO, TYPE_RETRANSMIT_REQUEST
from packet import mkp as ustp_mkp
from ustp import USTPReceiver, USTPSender, parse_packet
from ussh_proto import HEADER_SIZE, TYPE_CLOSE, TYPE_EXIT, TYPE_HELLO, TYPE_PING, TYPE_PONG, TYPE_READY, TYPE_STDOUT, TYPE_STDIN, TYPE_RESIZE, USHPacket
from ussh_proto import mkp as ush_mkp
from ussh_proto import TYPE_AUTH_FAIL


KEX_PREFIX = b"USSH-KEX1\0"
SESSION_PREFIX = b"USSH-SESSION1\0"


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USSH-X25519-session-v1",
    ).derive(shared)


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
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--connect-timeout", type=float, default=8.0)
    ap.add_argument("--session-timeout", type=float, default=10.0)
    ap.add_argument("--keepalive-interval", type=float, default=5.0)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    args = ap.parse_args()
    password = getpass.getpass(f"{args.peer_ip}'s password: ")

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    resolved_peer_ip = sorted(resolved_peer_ips)[0]
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))
    peer = (resolved_peer_ip, args.peer_port)
    session_addr = None
    sender = USTPSender(sock=sock, peer=peer, window=args.window, rto=args.rto, quiet=True)
    receiver = USTPReceiver(sock=sock, peer=peer)
    receiver.quiet_recv = True
    sender.start()
    client_private = x25519.X25519PrivateKey.generate()
    client_pub = public_bytes(client_private.public_key())

    running = True
    ready = threading.Event()
    kex_ready = False
    last_rx = time.time()
    stdout_next_pos = 0
    stdout_buffer: dict[int, bytes] = {}

    def send(pkt_type: int, payload: bytes = b"") -> None:
        chunk_size = MAX_PAYLOAD - HEADER_SIZE
        if not payload:
            sender.queue_payload(ush_mkp(pkt_type, payload=b"").to_bytes())
            return
        for i in range(0, len(payload), chunk_size):
            sender.queue_payload(ush_mkp(pkt_type, payload=payload[i : i + chunk_size]).to_bytes())

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

    def keepalive_loop() -> None:
        while running:
            sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=KEX_PREFIX + client_pub).to_bytes(), peer)
            if kex_ready and ready.is_set():
                send(TYPE_PING, b"keepalive")
            time.sleep(args.keepalive_interval)

    print(
        f"[USSH-CLIENT] local={sock.getsockname()} peer={args.peer_ip}:{args.peer_port} "
        f"resolved={','.join(sorted(resolved_peer_ips))} aead={normalize_cipher_name(args.cipher)}"
    )
    sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=KEX_PREFIX + client_pub).to_bytes(), peer)

    def sigwinch(_signum, _frame):
        rows, cols = get_winsize()
        send(TYPE_RESIZE, rows.to_bytes(2, "big") + cols.to_bytes(2, "big"))

    signal.signal(signal.SIGWINCH, sigwinch)

    old = termios.tcgetattr(sys.stdin.fileno())
    stdin_started = False
    tty_raw = False
    try:
        deadline = time.time() + args.connect_timeout
        threading.Thread(target=keepalive_loop, daemon=True).start()
        threading.Thread(target=nack_loop, daemon=True).start()
        while running:
            if not ready.is_set() and time.time() >= deadline:
                raise SystemExit("USSH server did not reply with READY")
            if ready.is_set() and (time.time() - last_rx) >= args.session_timeout:
                raise SystemExit("USSH session timed out")
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=KEX_PREFIX + client_pub).to_bytes(), peer)
                if kex_ready and not ready.is_set():
                    send(TYPE_HELLO, b"USSH-AUTH1\0" + password.encode("utf-8"))
                continue
            if session_addr is not None and addr != session_addr:
                continue
            try:
                ustp_pkt = parse_packet(rawp)
            except Exception:
                continue
            if not ustp_pkt:
                continue
            if ustp_pkt.pkt_type == USTP_TYPE_HELLO and ustp_pkt.payload.startswith(SESSION_PREFIX):
                rest = ustp_pkt.payload[len(SESSION_PREFIX) :]
                if len(rest) >= 64:
                    echoed_client_pub = rest[:32]
                    server_pub = rest[32:64]
                    if echoed_client_pub != client_pub:
                        continue
                    session_cipher = rest[64:].decode("ascii", "replace") or normalize_cipher_name(args.cipher)
                    server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                    sock.set_peer_psk(
                        addr,
                        derive_session_key(client_private.exchange(server_public), client_pub, server_pub),
                        session_cipher,
                    )
                    session_addr = addr
                    sender.peer = addr
                    receiver.peer = addr
                    kex_ready = True
                    print(f"[USSH-CLIENT] secure session from {addr[0]}:{addr[1]} aead={session_cipher}")
                    send(TYPE_HELLO, b"USSH-AUTH1\0" + password.encode("utf-8"))
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
                ready.set()
                print(f"[USSH-CLIENT] READY from {addr[0]}:{addr[1]}")
                tty.setraw(sys.stdin.fileno())
                tty_raw = True
                sigwinch(None, None)
                if not stdin_started:
                    threading.Thread(target=stdin_loop, daemon=True).start()
                    stdin_started = True
                continue
            if pkt.pkt_type == TYPE_STDOUT:
                if len(pkt.payload) < 8:
                    continue
                pos = int.from_bytes(pkt.payload[:8], "big")
                data = pkt.payload[8:]
                if not data:
                    continue
                if pos not in stdout_buffer:
                    stdout_buffer[pos] = data
                while stdout_next_pos in stdout_buffer:
                    chunk = stdout_buffer.pop(stdout_next_pos)
                    os.write(sys.stdout.fileno(), chunk)
                    stdout_next_pos += len(chunk)
                continue
            if pkt.pkt_type == TYPE_PING:
                if session_addr is None:
                    session_addr = addr
                send(TYPE_PONG, b"pong")
                continue
            if pkt.pkt_type == TYPE_PONG:
                continue
            if pkt.pkt_type == TYPE_EXIT:
                if tty_raw:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
                    tty_raw = False
                running = False
                break
            if pkt.pkt_type == TYPE_CLOSE:
                if tty_raw:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
                    tty_raw = False
                running = False
                break
        send(TYPE_CLOSE, b"")
    except KeyboardInterrupt:
        send(TYPE_CLOSE, b"")
    except SystemExit as exc:
        print(f"\n[USSH-CLIENT] {exc}", file=sys.stderr)
    finally:
        if tty_raw:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        running = False
        sender.stop()


if __name__ == "__main__":
    main()
