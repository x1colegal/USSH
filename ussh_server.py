import argparse
import getpass
import hmac
import os
import pty
import pwd
import random
import shutil
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aead_udp import AEADDatagramSocket, normalize_cipher_name
from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_DATA, TYPE_HELLO as USTP_TYPE_HELLO, TYPE_RETRANSMIT_REQUEST
from packet import mkp as ustp_mkp
from ustp import USTPReceiver, USTPSender, parse_packet
from ussh_proto import USHPacket
from ussh_proto import (
    HEADER_SIZE,
    TYPE_AUTH_FAIL,
    TYPE_CLOSE,
    TYPE_EXIT,
    TYPE_HELLO,
    TYPE_PING,
    TYPE_PONG,
    TYPE_READY,
    TYPE_RESIZE,
    TYPE_STDOUT,
    TYPE_STDIN,
    mkp as ush_mkp,
)


SUPPORTED_CIPHERS = ("chacha20", "aes-256-gcm", "aes-128-gcm")
KEX_PREFIX = b"USSH-KEX1\0"
SESSION_PREFIX = b"USSH-SESSION1\0"


@dataclass
class ClientSession:
    addr: tuple[str, int]
    sender: USTPSender
    receiver: USTPReceiver
    cipher: str
    session_psk: bytes | None = None
    pty_fd: int | None = None
    proc: subprocess.Popen | None = None
    ready: bool = False
    last_rx: float = 0.0
    closed: bool = False
    stdout_pos: int = 0


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USSH-X25519-session-v1",
    ).derive(shared)


def parse_kex(payload: bytes) -> bytes | None:
    if not payload.startswith(KEX_PREFIX):
        return None
    rest = payload[len(KEX_PREFIX) :]
    if len(rest) < 32:
        return None
    return rest[:32]


def parse_hello(payload: bytes) -> str | None:
    if not payload.startswith(b"USSH-AUTH1\0"):
        return None
    rest = payload[len(b"USSH-AUTH1\0") :]
    if not rest:
        return None
    return rest.decode("utf-8", "replace")


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


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
        "--password",
        args.password or "",
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
    ap.add_argument("--peer-ip", default="0.0.0.0")
    ap.add_argument("--peer-port", type=int, default=0)
    ap.add_argument("--password", default=None, help="USSH login password; prompts if omitted")
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--shell", default=None)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--no-systemd-prompt", action="store_true")
    args = ap.parse_args()
    if args.password is None:
        args.password = getpass.getpass("USSH server password: ")
    maybe_install_systemd(args)

    pw = pwd.getpwuid(os.getuid())
    login_home = pw.pw_dir
    login_user = pw.pw_name
    login_shell = args.shell or pw.pw_shell or os.environ.get("SHELL") or "/bin/sh"
    login_shell = os.path.abspath(login_shell)

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, cipher_name=normalize_cipher_name(args.cipher))
    sock.bind((args.bind_ip, args.bind_port))

    running = True
    sessions: dict[tuple[str, int], ClientSession] = {}
    sessions_lock = threading.Lock()

    def new_session(addr: tuple[str, int], client_pub_raw: bytes) -> ClientSession:
        cipher = random.choice(SUPPORTED_CIPHERS)
        server_private = x25519.X25519PrivateKey.generate()
        server_pub = public_bytes(server_private.public_key())
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_raw)
        session_psk = derive_session_key(server_private.exchange(client_pub), client_pub_raw, server_pub)
        sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=SESSION_PREFIX + client_pub_raw + server_pub + cipher.encode("ascii")).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, cipher)
        sender = USTPSender(sock=sock, peer=addr, window=args.window, rto=args.rto, quiet=True)
        receiver = USTPReceiver(sock=sock, peer=addr)
        sender.start()
        session = ClientSession(
            addr=addr,
            sender=sender,
            receiver=receiver,
            cipher=cipher,
            session_psk=session_psk,
            last_rx=time.time(),
        )
        sessions[addr] = session
        print(f"[USSH-SERVER] client joined {addr[0]}:{addr[1]} cipher={cipher}")
        return session

    def send(session: ClientSession, pkt_type: int, payload: bytes = b"") -> None:
        chunk_size = MAX_PAYLOAD - HEADER_SIZE
        try:
            if not payload:
                session.sender.queue_payload(ush_mkp(pkt_type, payload=b"").to_bytes())
                return
            if pkt_type == TYPE_STDOUT:
                data_chunk = max(1, chunk_size - 8)
                pos = session.stdout_pos
                for i in range(0, len(payload), data_chunk):
                    part = payload[i : i + data_chunk]
                    framed = pos.to_bytes(8, "big") + part
                    session.sender.queue_payload(ush_mkp(pkt_type, payload=framed).to_bytes())
                    pos += len(part)
                session.stdout_pos = pos
                return
            for i in range(0, len(payload), chunk_size):
                session.sender.queue_payload(ush_mkp(pkt_type, payload=payload[i : i + chunk_size]).to_bytes())
        except Exception:
            print(f"[USSH-SERVER] send error {session.addr[0]}:{session.addr[1]}:")
            traceback.print_exc()

    def send_exit_and_linger(session: ClientSession) -> None:
        # The final EXIT packet must actually leave the async sender queue before
        # we tear the session down, otherwise the client stays in raw mode until timeout.
        for _ in range(3):
            send(session, TYPE_EXIT, b"")
            if session.sender.wait_idle(timeout=max(0.6, session.sender.rto * 4.0)):
                return
            time.sleep(0.05)

    def close_session(session: ClientSession) -> None:
        if session.closed:
            return
        session.closed = True
        with sessions_lock:
            sessions.pop(session.addr, None)
        try:
            sock.clear_peer(session.addr)
        except Exception:
            pass
        session.sender.stop()
        try:
            if session.proc and session.proc.poll() is None:
                session.proc.terminate()
        except Exception:
            pass
        try:
            if session.pty_fd is not None:
                os.close(session.pty_fd)
        except OSError:
            pass

    def shell_loop(session: ClientSession) -> None:
        master_fd = session.pty_fd
        if master_fd is None:
            return
        try:
            while running:
                try:
                    r, _, _ = select.select([master_fd], [], [], 0.2)
                except OSError:
                    break
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
                send(session, TYPE_STDOUT, data)
            send_exit_and_linger(session)
        except Exception:
            print(f"[USSH-SERVER] shell-loop error {session.addr[0]}:{session.addr[1]}:")
            traceback.print_exc()
        finally:
            close_session(session)

    def nack_loop() -> None:
        while running:
            with sessions_lock:
                current = list(sessions.values())
            for session in current:
                session.receiver.maybe_nack()
            time.sleep(0.03)

    print(
        f"[USSH-SERVER] listen {args.bind_ip}:{args.bind_port} allowed-peer={args.peer_ip} "
        f"resolved={','.join(sorted(resolved_peer_ips))} multi-client=on user={login_user} "
        f"home={login_home} shell={login_shell}"
    )
    threading.Thread(target=nack_loop, daemon=True).start()
    try:
        while running:
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                with sessions_lock:
                    current = list(sessions.values())
                now = time.time()
                for session in current:
                    if session.ready and session.proc and session.proc.poll() is None and (now - session.last_rx) > 10:
                        send(session, TYPE_PING, b"")
                continue
            try:
                ustp_pkt = parse_packet(rawp)
            except Exception:
                continue
            if not ustp_pkt:
                continue
            try:
                with sessions_lock:
                    session = sessions.get(addr)
                    if session is None and ustp_pkt.pkt_type == USTP_TYPE_HELLO:
                        client_pub = parse_kex(ustp_pkt.payload)
                        if client_pub is None:
                            continue
                        session = new_session(addr, client_pub)
                    if session is None:
                        continue
                    session.last_rx = time.time()
                if ustp_pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, USTP_TYPE_HELLO):
                    session.sender.on_control(ustp_pkt)
                    continue
                if ustp_pkt.pkt_type != TYPE_DATA:
                    continue
                payload = session.receiver.handle_data(ustp_pkt)
                if not payload:
                    continue
                try:
                    pkt = USHPacket.from_bytes(payload)
                except Exception:
                    continue
                if pkt.pkt_type == TYPE_HELLO:
                    if not session.ready:
                        password = parse_hello(pkt.payload)
                        if password is None:
                            send(session, TYPE_AUTH_FAIL, b"bad hello")
                            time.sleep(0.1)
                            close_session(session)
                            continue
                        if not hmac_compare(password, args.password):
                            print(f"[USSH-SERVER] auth failed from {addr[0]}:{addr[1]}")
                            send(session, TYPE_AUTH_FAIL, b"bad password")
                            time.sleep(0.1)
                            close_session(session)
                            continue
                        print(f"[USSH-SERVER] HELLO from {addr[0]}:{addr[1]}")
                        session.ready = True
                        send(session, TYPE_READY, b"ready")
                        master_fd, slave_fd = pty.openpty()
                        env = os.environ.copy()
                        env["HOME"] = login_home
                        env["USER"] = login_user
                        env["LOGNAME"] = login_user
                        env["SHELL"] = login_shell
                        env.setdefault("TERM", "xterm-256color")
                        session.proc = subprocess.Popen(
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
                        session.pty_fd = master_fd
                        threading.Thread(target=shell_loop, args=(session,), daemon=True).start()
                    continue
                if pkt.pkt_type == TYPE_PING:
                    send(session, TYPE_PONG, b"pong")
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
                            if session.pty_fd is not None:
                                fcntl.ioctl(session.pty_fd, termios.TIOCSWINSZ, winsz)
                        except Exception:
                            pass
                    continue
                if pkt.pkt_type == TYPE_STDIN:
                    if session.pty_fd is not None:
                        try:
                            os.write(session.pty_fd, pkt.payload)
                        except OSError:
                            close_session(session)
                    continue
                if pkt.pkt_type == TYPE_CLOSE:
                    close_session(session)
                    continue
                if pkt.pkt_type == TYPE_EXIT:
                    close_session(session)
                    continue
            except Exception:
                print(f"[USSH-SERVER] session error {addr[0]}:{addr[1]}:")
                traceback.print_exc()
                try:
                    close_session(session)
                except Exception:
                    pass
    except KeyboardInterrupt:
        print("[USSH-SERVER] interrupted")
    finally:
        running = False
        with sessions_lock:
            current = list(sessions.values())
        for session in current:
            close_session(session)


if __name__ == "__main__":
    main()
