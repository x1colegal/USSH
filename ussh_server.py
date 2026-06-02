import argparse
import os
import pty
import pwd
import shutil
import select
import signal
import socket
import subprocess
import sys
import threading
import time

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_DATA, TYPE_HELLO as USTP_TYPE_HELLO, TYPE_RETRANSMIT_REQUEST
from ustp import USTPReceiver, USTPSender, parse_packet
from ussh_proto import USHPacket
from ussh_proto import (
    HEADER_SIZE,
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


def maybe_install_systemd(args) -> None:
    if args.no_systemd_prompt or not sys.stdin.isatty() or not shutil.which("systemctl"):
        return
    answer = input("Install USSH server as a systemd service? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        return
    if os.geteuid() != 0:
        print("[USSH-SERVER] systemd install needs root; continuing without installing")
        return

    script = os.path.abspath(__file__)
    cmd = [
        sys.executable,
        script,
        "--peer-ip",
        args.peer_ip,
        "--peer-port",
        str(args.peer_port),
        "--bind-ip",
        args.bind_ip,
        "--bind-port",
        str(args.bind_port),
        "--psk",
        args.psk,
        "--cipher",
        args.cipher,
        "--no-systemd-prompt",
    ]
    if args.shell:
        cmd += ["--shell", args.shell]
    service = "\n".join(
        [
            "[Unit]",
            "Description=USSH server",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            f"WorkingDirectory={os.path.dirname(script)}",
            "ExecStart=" + " ".join(cmd),
            "Restart=always",
            "RestartSec=3",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    path = "/etc/systemd/system/ussh.service"
    with open(path, "w", encoding="utf-8") as f:
        f.write(service)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "--now", "ussh.service"], check=False)
    print(f"[USSH-SERVER] installed systemd service at {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="USSH server")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=5322)
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=0)
    ap.add_argument("--psk", required=True)
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--shell", default=None)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--no-systemd-prompt", action="store_true")
    args = ap.parse_args()
    maybe_install_systemd(args)

    pw = pwd.getpwuid(os.getuid())
    login_home = pw.pw_dir
    login_user = pw.pw_name
    login_shell = args.shell or pw.pw_shell or os.environ.get("SHELL") or "/bin/sh"
    login_shell = os.path.abspath(login_shell)

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    resolved_peer_ip = sorted(resolved_peer_ips)[0]
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, psk=args.psk, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))

    peer = (resolved_peer_ip, args.peer_port if args.peer_port > 0 else 0)
    session_addr = None
    sender = USTPSender(sock=sock, peer=peer, window=args.window, rto=args.rto)
    receiver = USTPReceiver(sock=sock, peer=peer)
    sender.start()
    pty_fd = None
    proc = None
    running = True
    client_ready = False
    last_rx = time.time()

    def send(pkt_type: int, payload: bytes = b"") -> None:
        chunk_size = MAX_PAYLOAD - HEADER_SIZE
        if not payload:
            sender.queue_payload(mkp(pkt_type, payload=b"").to_bytes())
            return
        for i in range(0, len(payload), chunk_size):
            sender.queue_payload(mkp(pkt_type, payload=payload[i : i + chunk_size]).to_bytes())

    def shell_loop(master_fd: int) -> None:
        nonlocal client_ready, session_addr, pty_fd, proc
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
        try:
            os.close(master_fd)
        except OSError:
            pass
        pty_fd = None
        proc = None
        client_ready = False
        session_addr = None

    def nack_loop() -> None:
        while running:
            receiver.maybe_nack()
            time.sleep(0.03)

    print(
        f"[USSH-SERVER] listen {args.bind_ip}:{args.bind_port} peer={args.peer_ip} "
        f"resolved={','.join(sorted(resolved_peer_ips))} user={login_user} "
        f"home={login_home} shell={login_shell}"
    )
    threading.Thread(target=nack_loop, daemon=True).start()
    try:
        while running:
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                if client_ready and proc and proc.poll() is None and time.time() - last_rx > 10:
                    send(TYPE_PING, b"")
                continue
            last_rx = time.time()
            if session_addr is not None and addr != session_addr:
                continue
            if args.peer_port == 0:
                peer = addr
                sender.peer = addr
                receiver.peer = addr
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
            if pkt.pkt_type == TYPE_HELLO:
                if not client_ready:
                    session_addr = addr
                    print(f"[USSH-SERVER] HELLO from {addr[0]}:{addr[1]}")
                    client_ready = True
                    send(TYPE_READY, b"ready")
                    master_fd, slave_fd = pty.openpty()
                    env = os.environ.copy()
                    env["HOME"] = login_home
                    env["USER"] = login_user
                    env["LOGNAME"] = login_user
                    env["SHELL"] = login_shell
                    env.setdefault("TERM", "xterm-256color")
                    proc = subprocess.Popen(
                        [f"-{os.path.basename(login_shell)}"],
                        executable=login_shell,
                        stdin=slave_fd,
                        stdout=slave_fd,
                        stderr=slave_fd,
                        cwd=login_home,
                        env=env,
                        close_fds=True,
                        preexec_fn=os.setsid,
                    )
                    os.close(slave_fd)
                    pty_fd = master_fd
                    threading.Thread(target=shell_loop, args=(master_fd,), daemon=True).start()
                continue
            if pkt.pkt_type == TYPE_PING:
                if session_addr is None:
                    session_addr = addr
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
        sender.stop()
        try:
            if proc and proc.poll() is None:
                proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()
