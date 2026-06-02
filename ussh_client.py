import argparse
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
from ussh_proto import TYPE_CLOSE, TYPE_EXIT, TYPE_HELLO, TYPE_PING, TYPE_PONG, TYPE_READY, TYPE_STDOUT, TYPE_STDIN, TYPE_RESIZE, mkp, USHPacket


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
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--connect-timeout", type=float, default=8.0)
    args = ap.parse_args()

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    resolved_peer_ip = sorted(resolved_peer_ips)[0]
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, psk=args.psk, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))
    peer = (resolved_peer_ip, args.peer_port)
    session_addr = None

    seq = 1
    running = True
    ready = threading.Event()

    def send(pkt_type: int, payload: bytes = b"") -> None:
        nonlocal seq
        sock.sendto(mkp(pkt_type, payload=payload, seq=seq).to_bytes(), peer)
        seq += 1

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

    print(
        f"[USSH-CLIENT] local={sock.getsockname()} peer={args.peer_ip}:{args.peer_port} "
        f"resolved={','.join(sorted(resolved_peer_ips))} aead={normalize_cipher_name(args.cipher)}"
    )
    send(TYPE_HELLO, b"hello")

    def sigwinch(_signum, _frame):
        rows, cols = get_winsize()
        send(TYPE_RESIZE, rows.to_bytes(2, "big") + cols.to_bytes(2, "big"))

    signal.signal(signal.SIGWINCH, sigwinch)

    old = termios.tcgetattr(sys.stdin.fileno())
    stdin_started = False
    try:
        deadline = time.time() + args.connect_timeout
        while running:
            if not ready.is_set() and time.time() >= deadline:
                raise SystemExit("USSH server did not reply with READY")
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                if not ready.is_set():
                    send(TYPE_HELLO, b"hello")
                continue
            if session_addr is not None and addr != session_addr:
                continue
            try:
                pkt = USHPacket.from_bytes(rawp)
            except Exception:
                continue
            if pkt.pkt_type == TYPE_READY:
                session_addr = addr
                ready.set()
                print(f"[USSH-CLIENT] READY from {addr[0]}:{addr[1]}")
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
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        running = False


if __name__ == "__main__":
    main()
