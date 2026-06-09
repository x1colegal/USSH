import argparse
import faulthandler
import getpass
import hmac
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
import traceback
from dataclasses import dataclass
from pathlib import Path

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
    TYPE_FILE_CHUNK,
    TYPE_FILE_DONE,
    TYPE_FILE_FAIL,
    TYPE_FILE_META,
    TYPE_FILE_OK,
    TYPE_FILE_PROGRESS,
    TYPE_HELLO,
    TYPE_PING,
    TYPE_PONG,
    TYPE_READY,
    TYPE_RESIZE,
    TYPE_STDOUT,
    TYPE_STDIN,
    mkp as ush_mkp,
)


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
    client_pub: bytes | None = None
    server_pub: bytes | None = None
    next_stdin_seq: int = 1
    stdin_buffer: dict[int, bytes] | None = None
    mode: str = "shell"
    transfer_enabled: bool = True
    transfer_name: str | None = None
    transfer_size: int = 0
    transfer_tmp_path: str | None = None
    transfer_final_path: str | None = None
    transfer_file: object | None = None
    transfer_chunks: dict[int, int] | None = None
    transfer_contiguous: int = 0
    transfer_done: bool = False
    transfer_last_keepalive: float = 0.0
    transfer_progress_sent: int = 0
    transfer_last_progress_ts: float = 0.0


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USSH-X25519-session-v1",
    ).derive(shared)


def parse_kex(payload: bytes) -> tuple[bytes, str | None] | None:
    if not payload.startswith(KEX_PREFIX):
        return None
    rest = payload[len(KEX_PREFIX) :]
    if len(rest) < 32:
        return None
    client_pub = rest[:32]
    cipher = None
    if len(rest) > 32:
        try:
            cipher = normalize_cipher_name(rest[32:].decode("ascii", "replace"))
        except Exception:
            cipher = None
    return client_pub, cipher


def load_or_create_host_key(path: str) -> x25519.X25519PrivateKey:
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) == 32:
            return x25519.X25519PrivateKey.from_private_bytes(raw)
    except FileNotFoundError:
        pass
    key = x25519.X25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def create_new_host_key(path: str) -> x25519.X25519PrivateKey:
    key = x25519.X25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def maybe_regen_host_key(path: str, enabled: bool) -> None:
    if not enabled:
        return
    if not os.isatty(0):
        raise SystemExit("--regen-key requires interactive confirmation")
    answer = input(f"Regenerate USSH host key at {path}? Existing clients will see a TOFU mismatch. [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        raise SystemExit("USSH host key regeneration cancelled")
    create_new_host_key(path)
    print(f"[USSH-SERVER] regenerated host key at {path}")


def parse_hello(payload: bytes) -> tuple[str, str, str | None, int | None, int | None] | None:
    if payload.startswith(b"USSH-AUTH3\0"):
        rest = payload[len(b"USSH-AUTH3\0") :]
        parts = rest.split(b"\0", 4)
        if len(parts) != 5 or not parts[0] or not parts[1]:
            return None
        try:
            rows = int(parts[3].decode("ascii", "replace"))
            cols = int(parts[4].decode("ascii", "replace"))
        except ValueError:
            rows, cols = None, None
        mode = parts[1].decode("ascii", "replace") or "shell"
        term_name = parts[2].decode("utf-8", "replace") or None
        return parts[0].decode("utf-8", "replace"), mode, term_name, rows, cols
    if payload.startswith(b"USSH-AUTH2\0"):
        rest = payload[len(b"USSH-AUTH2\0") :]
        parts = rest.split(b"\0", 3)
        if len(parts) != 4 or not parts[0]:
            return None
        try:
            rows = int(parts[2].decode("ascii", "replace"))
            cols = int(parts[3].decode("ascii", "replace"))
        except ValueError:
            rows, cols = None, None
        term_name = parts[1].decode("utf-8", "replace") or None
        return parts[0].decode("utf-8", "replace"), "shell", term_name, rows, cols
    if payload.startswith(b"USSH-AUTH1\0"):
        rest = payload[len(b"USSH-AUTH1\0") :]
        if not rest:
            return None
        return rest.decode("utf-8", "replace"), "shell", None, None, None
    return None


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
    faulthandler.enable(all_threads=True)
    ap = argparse.ArgumentParser(description="USSH server")
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=5322)
    ap.add_argument("--peer-ip", default="0.0.0.0")
    ap.add_argument("--peer-port", type=int, default=0)
    ap.add_argument("--password", default=None, help="USSH login password; prompts if omitted")
    ap.add_argument("--cipher", default="auto")
    ap.add_argument("--host-key-file", default=os.path.expanduser("~/.ussh_host_key"))
    ap.add_argument("--regen-key", action="store_true", help="Regenerate the persistent server host key after interactive confirmation")
    ap.add_argument("--shell", default=None)
    ap.add_argument("--term", default="vt100")
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--no-systemd-prompt", action="store_true")
    ap.add_argument("--no-file-transfer", action="store_true", help="Disable file transfer support")
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
    maybe_regen_host_key(args.host_key_file, args.regen_key)
    host_private = load_or_create_host_key(args.host_key_file)
    host_public = public_bytes(host_private.public_key())
    selected_cipher = None if args.cipher == "auto" else normalize_cipher_name(args.cipher)
    sock = AEADDatagramSocket(raw, cipher_name=selected_cipher or "chacha20")
    sock.bind((args.bind_ip, args.bind_port))

    running = True
    sessions: dict[tuple[str, int], ClientSession] = {}
    sessions_lock = threading.Lock()
    def new_session(addr: tuple[str, int], client_pub_raw: bytes, requested_cipher: str | None) -> ClientSession:
        cipher = selected_cipher or requested_cipher or "chacha20"
        client_pub = x25519.X25519PublicKey.from_public_bytes(client_pub_raw)
        session_psk = derive_session_key(host_private.exchange(client_pub), client_pub_raw, host_public)
        sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=SESSION_PREFIX + client_pub_raw + host_public + cipher.encode("ascii")).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, cipher)
        sender = USTPSender(sock=sock, peer=addr, window=args.window, rto=args.rto, quiet=True)
        receiver = USTPReceiver(sock=sock, peer=addr)
        receiver.quiet_recv = True
        sender.start()
        session = ClientSession(
            addr=addr,
            sender=sender,
            receiver=receiver,
            cipher=cipher,
            session_psk=session_psk,
            client_pub=client_pub_raw,
            server_pub=host_public,
            stdin_buffer={},
            last_rx=time.time(),
            transfer_enabled=not args.no_file_transfer,
            transfer_chunks={},
            transfer_contiguous=0,
        )
        sessions[addr] = session
        print(f"[USSH-SERVER] client joined {addr[0]}:{addr[1]} cipher={cipher}")
        return session

    def find_session_by_client_pub(client_pub_raw: bytes) -> tuple[tuple[str, int], ClientSession] | tuple[None, None]:
        for existing_addr, existing_session in sessions.items():
            if existing_session.client_pub == client_pub_raw:
                return existing_addr, existing_session
        return None, None

    def migrate_session(old_addr: tuple[str, int], new_addr: tuple[str, int], session: ClientSession) -> None:
        if old_addr == new_addr:
            return
        sock.clear_peer(old_addr)
        sock.set_peer_psk(new_addr, session.session_psk, session.cipher)
        session.sender.peer = new_addr
        session.receiver.peer = new_addr
        session.addr = new_addr
        sessions.pop(old_addr, None)
        sessions[new_addr] = session
        print(f"[USSH-SERVER] client migrated {old_addr[0]}:{old_addr[1]} -> {new_addr[0]}:{new_addr[1]}")

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

    def finish_transfer(session: ClientSession, ok: bool, message: bytes = b"") -> None:
        try:
            send(session, TYPE_FILE_OK if ok else TYPE_FILE_FAIL, message)
            session.sender.wait_idle(timeout=max(0.6, session.sender.rto * 4.0))
        finally:
            close_session(session)

    def maybe_complete_transfer(session: ClientSession) -> bool:
        if not session.transfer_done:
            return False
        if session.transfer_contiguous != session.transfer_size:
            return False
        try:
            if session.transfer_file is not None:
                session.transfer_file.flush()
                session.transfer_file.close()
                session.transfer_file = None
            if session.transfer_tmp_path and session.transfer_final_path:
                os.replace(session.transfer_tmp_path, session.transfer_final_path)
            finish_transfer(session, True, f"stored:{session.transfer_final_path}".encode("utf-8", "replace"))
            return True
        except Exception as exc:
            finish_transfer(session, False, f"store-failed:{exc}".encode("utf-8", "replace"))
            return True

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
            if session.transfer_file is not None:
                session.transfer_file.close()
                session.transfer_file = None
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
                        parsed = parse_kex(ustp_pkt.payload)
                        if parsed is None:
                            continue
                        client_pub, requested_cipher = parsed
                        old_addr, old_session = find_session_by_client_pub(client_pub)
                        if old_session is not None:
                            migrate_session(old_addr, addr, old_session)
                            session = old_session
                            session.last_rx = time.time()
                        else:
                            session = new_session(addr, client_pub, requested_cipher)
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
                        hello = parse_hello(pkt.payload)
                        if hello is None:
                            send(session, TYPE_AUTH_FAIL, b"bad hello")
                            time.sleep(0.1)
                            close_session(session)
                            continue
                        password, mode, client_term, client_rows, client_cols = hello
                        if not hmac_compare(password, args.password):
                            print(f"[USSH-SERVER] auth failed from {addr[0]}:{addr[1]}")
                            send(session, TYPE_AUTH_FAIL, b"bad password")
                            time.sleep(0.1)
                            close_session(session)
                            continue
                        print(f"[USSH-SERVER] HELLO from {addr[0]}:{addr[1]} mode={mode}")
                        session.ready = True
                        session.mode = mode
                        send(session, TYPE_READY, b"ready")
                        if mode == "file":
                            if args.no_file_transfer:
                                send(session, TYPE_FILE_FAIL, b"file transfer disabled")
                                time.sleep(0.1)
                                close_session(session)
                            continue
                        master_fd, slave_fd = pty.openpty()
                        env = os.environ.copy()
                        env["HOME"] = login_home
                        env["USER"] = login_user
                        env["LOGNAME"] = login_user
                        env["SHELL"] = login_shell
                        env["TERM"] = client_term or args.term
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
                        if client_rows and client_cols:
                            try:
                                import fcntl
                                import struct
                                import termios

                                winsz = struct.pack("HHHH", client_rows, client_cols, 0, 0)
                                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsz)
                            except Exception:
                                pass
                        threading.Thread(target=shell_loop, args=(session,), daemon=True).start()
                    continue
                if pkt.pkt_type == TYPE_FILE_META:
                    if not session.transfer_enabled:
                        finish_transfer(session, False, b"file transfer disabled")
                        continue
                    if len(pkt.payload) < 10:
                        finish_transfer(session, False, b"bad file meta")
                        continue
                    name_len = int.from_bytes(pkt.payload[:2], "big")
                    if len(pkt.payload) < 10 + name_len:
                        finish_transfer(session, False, b"bad file meta")
                        continue
                    session.transfer_size = int.from_bytes(pkt.payload[2:10], "big")
                    raw_name = pkt.payload[10:10 + name_len].decode("utf-8", "replace")
                    safe_name = Path(raw_name).name or "upload.bin"
                    final_path = os.path.join(login_home, safe_name)
                    tmp_path = final_path + ".part"
                    session.transfer_name = safe_name
                    session.transfer_final_path = final_path
                    session.transfer_tmp_path = tmp_path
                    session.transfer_chunks = {}
                    session.transfer_contiguous = 0
                    session.transfer_progress_sent = 0
                    session.transfer_last_progress_ts = 0.0
                    try:
                        if session.transfer_file is not None:
                            session.transfer_file.close()
                        session.transfer_file = open(tmp_path, "w+b")
                        session.transfer_file.truncate(session.transfer_size)
                    except Exception as exc:
                        finish_transfer(session, False, f"open-failed:{exc}".encode("utf-8", "replace"))
                    continue
                if pkt.pkt_type == TYPE_FILE_CHUNK:
                    if session.transfer_file is None or len(pkt.payload) < 8:
                        finish_transfer(session, False, b"file chunk before meta")
                        continue
                    offset = int.from_bytes(pkt.payload[:8], "big")
                    data = pkt.payload[8:]
                    if offset < 0 or (offset + len(data)) > session.transfer_size:
                        finish_transfer(session, False, b"invalid file chunk")
                        continue
                    if session.transfer_chunks is None:
                        session.transfer_chunks = {}
                    if offset not in session.transfer_chunks:
                        session.transfer_file.seek(offset)
                        session.transfer_file.write(data)
                        session.transfer_chunks[offset] = len(data)
                        while True:
                            ln = session.transfer_chunks.get(session.transfer_contiguous)
                            if ln is None:
                                break
                            session.transfer_contiguous += ln
                        contiguous = session.transfer_contiguous
                        now = time.time()
                        advanced = contiguous - session.transfer_progress_sent
                        if (
                            contiguous > session.transfer_progress_sent
                            and (
                                advanced >= 256 * 1024
                                or (now - session.transfer_last_progress_ts) >= 0.25
                                or contiguous == session.transfer_size
                            )
                        ):
                            send(session, TYPE_FILE_PROGRESS, contiguous.to_bytes(8, "big"))
                            session.transfer_progress_sent = contiguous
                            session.transfer_last_progress_ts = now
                    now = time.time()
                    if now - session.transfer_last_keepalive >= 1.0:
                        send(session, TYPE_PONG, b"transfer")
                        session.transfer_last_keepalive = now
                    if session.transfer_done and maybe_complete_transfer(session):
                        continue
                    continue
                if pkt.pkt_type == TYPE_FILE_DONE:
                    if len(pkt.payload) >= 8:
                        declared_size = int.from_bytes(pkt.payload[:8], "big")
                        if session.transfer_size and declared_size != session.transfer_size:
                            finish_transfer(session, False, b"size mismatch")
                            continue
                    session.transfer_done = True
                    if maybe_complete_transfer(session):
                        continue
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
                        if session.stdin_buffer is None:
                            session.stdin_buffer = {}
                        if pkt.seq not in session.stdin_buffer:
                            session.stdin_buffer[pkt.seq] = pkt.payload
                        while session.next_stdin_seq in session.stdin_buffer:
                            chunk = session.stdin_buffer.pop(session.next_stdin_seq)
                            try:
                                os.write(session.pty_fd, chunk)
                            except OSError:
                                close_session(session)
                                break
                            session.next_stdin_seq += 1
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
