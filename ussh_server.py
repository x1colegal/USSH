import argparse
import os
import pty
import select
import signal
import socket
import subprocess
import threading
import time

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from ussh_proto import USHPacket
from ussh_proto import (
    TYPE_CLOSE,
    TYPE_EXIT,
    TYPE_HELLO,
    TYPE_PING,
    TYPE_PONG,
    TYPE_READY,
    TYPE_RESIZE,
    TYPE_STDOUT,
    TYPE_STDIN,
    mkp,
)


def resolve_host_ips(host: str) -> set[str]:
    ips = set()
    for item in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM):
        sockaddr = item[4]
        if sockaddr:
            ips.add(sockaddr[0])
    if not ips:
        ips.add(socket.gethostbyname(host))
    return ips


def main() -> None:
    ap = argparse.ArgumentParser(description="USSH server")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=5322)
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=0)
    ap.add_argument("--psk", required=True)
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--shell", default="/bin/sh")
    args = ap.parse_args()

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    resolved_peer_ip = sorted(resolved_peer_ips)[0]
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, psk=args.psk, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))

    peer = (resolved_peer_ip, args.peer_port if args.peer_port > 0 else 0)
    pty_fd = None
    proc = None
    running = True
    seq = 1
    client_ready = False
    last_rx = time.time()

    def send(pkt_type: int, payload: bytes = b"") -> None:
        nonlocal seq
        sock.sendto(mkp(pkt_type, payload=payload, seq=seq).to_bytes(), peer)
        seq += 1

    def shell_loop(master_fd: int) -> None:
        while running:
            try:
                r, _, _ = select.select([master_fd], [], [], 0.2)
            except Exception:
                continue
            if master_fd not in r:
                continue
            try:
                data = os.read(master_fd, 4096)
            except OSError:
                break
            if not data:
                break
            send(TYPE_STDOUT, data)
        send(TYPE_EXIT, b"")

    print(
        f"[USSH-SERVER] listen {args.bind_ip}:{args.bind_port} peer={args.peer_ip} "
        f"resolved={','.join(sorted(resolved_peer_ips))} shell={args.shell}"
    )
    try:
        while running:
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                if client_ready and proc and proc.poll() is None and time.time() - last_rx > 10:
                    send(TYPE_PING, b"")
                continue
            last_rx = time.time()
            if addr[0] not in resolved_peer_ips:
                continue
            if args.peer_port == 0:
                peer = addr
            try:
                pkt = USHPacket.from_bytes(rawp)
            except Exception:
                continue
            if pkt.pkt_type == TYPE_HELLO:
                if not client_ready:
                    print(f"[USSH-SERVER] HELLO from {addr[0]}:{addr[1]}")
                    client_ready = True
                    send(TYPE_READY, b"ready")
                    master_fd, slave_fd = pty.openpty()
                    proc = subprocess.Popen(
                        [args.shell, "-i"],
                        stdin=slave_fd,
                        stdout=slave_fd,
                        stderr=slave_fd,
                        close_fds=True,
                        preexec_fn=os.setsid,
                    )
                    os.close(slave_fd)
                    pty_fd = master_fd
                    threading.Thread(target=shell_loop, args=(master_fd,), daemon=True).start()
                continue
            if pkt.pkt_type == TYPE_PING:
                send(TYPE_PONG, b"pong")
                continue
            if pkt.pkt_type == TYPE_RESIZE:
                if len(pkt.payload) >= 4:
                    rows = int.from_bytes(pkt.payload[:2], "big")
                    cols = int.from_bytes(pkt.payload[2:4], "big")
                    try:
                        import fcntl
                        import termios
                        import struct

                        winsz = struct.pack("HHHH", rows, cols, 0, 0)
                        if pty_fd is not None:
                            fcntl.ioctl(pty_fd, termios.TIOCSWINSZ, winsz)
                    except Exception:
                        pass
                continue
            if pkt.pkt_type == TYPE_STDIN:
                if pty_fd is not None:
                    os.write(pty_fd, pkt.payload)
                continue
            if pkt.pkt_type == TYPE_CLOSE:
                running = False
                break
            if pkt.pkt_type == TYPE_EXIT:
                running = False
                break
    except KeyboardInterrupt:
        print("[USSH-SERVER] interrupted")
    finally:
        running = False
        try:
            if proc and proc.poll() is None:
                proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()
