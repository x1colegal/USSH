import argparse
import base64
import errno
import faulthandler
import getpass
import hmac
import ipaddress
import os
import pty
import secrets
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

KEX_PREFIX = b"USSH-KEX1\0"
CHALLENGE_PREFIX = b"USSH-CHALLENGE1\0"
RESPONSE_PREFIX = b"USSH-CHALLENGE-REPLY1\0"
RESUME_PREFIX = b"USSH-RESUME1\0"
SESSION_PREFIX = b"USSH-SESSION1\0"
DATA_PORT_PREFIX = b"USSH-DATA1\0"
UDP_BUFFER_BYTES = 4 * 1024 * 1024


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
    session_id: str | None = None
    session_reply: bytes | None = None
    ustp2beta: bool = False
    data_addr: tuple[str, int] | None = None
    data_ready: bool = False
    next_stdin_seq: int = 1
    stdin_buffer: dict[int, bytes] | None = None


@dataclass
class PendingChallenge:
    addr: tuple[str, int]
    client_pub: bytes
    cipher: str
    congestion_control: str
    ustp2beta: str
    session_id: str
    token: str
    created_ts: float


def public_bytes(pubkey) -> bytes:
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def derive_session_key(shared: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=client_pub + server_pub,
        info=b"USSH-X25519-session-v1",
    ).derive(shared)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def parse_hello_options(raw: bytes) -> tuple[str | None, str | None, str | None]:
    if not raw:
        return None, None, None
    try:
        text = raw.decode("ascii", "replace")
    except Exception:
        return None, None, None
    parts = text.split("\0")
    cipher_text = parts[0] if parts else ""
    cipher = None
    if cipher_text:
        try:
            cipher = normalize_cipher_name(cipher_text)
        except Exception:
            cipher = None
    cc_mode = None
    ustp2beta = None
    for part in parts[1:]:
        if part.startswith("cc="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                cc_mode = value
        elif part.startswith("u2="):
            value = part[3:].strip().lower()
            if value in {"on", "off"}:
                ustp2beta = value
    return cipher, cc_mode, ustp2beta


def resolve_server_cc_mode(server_mode: str, client_mode: str | None) -> str:
    if server_mode == "on":
        return "on"
    if server_mode == "off":
        return "off"
    return "on" if client_mode == "on" else "off"


def resolve_server_ustp2beta_mode(server_mode: str, client_mode: str | None) -> str:
    if server_mode == "on":
        return "on"
    if server_mode == "off":
        return "off"
    return "on" if client_mode == "on" else "off"


def parse_kex(payload: bytes):
    if payload.startswith(KEX_PREFIX):
        rest = payload[len(KEX_PREFIX) :]
        if len(rest) < 32:
            return None
        client_pub = rest[:32]
        cipher = None
        congestion_control = None
        if len(rest) > 32:
            cipher, congestion_control, ustp2beta = parse_hello_options(rest[32:])
        else:
            ustp2beta = None
        return ("init", client_pub, cipher, congestion_control, ustp2beta)
    if payload.startswith(RESPONSE_PREFIX):
        rest = payload[len(RESPONSE_PREFIX) :]
        parts = rest.split(b"\0", 5)
        if len(parts) != 6 or len(parts[5]) != 32:
            return None
        try:
            token = parts[0].decode("ascii", "replace")
            session_id = parts[1].decode("ascii", "replace")
            cipher, congestion_control, ustp2beta = parse_hello_options(parts[2] + b"\0" + parts[3] + b"\0" + parts[4])
            if cipher is None:
                return None
        except Exception:
            return None
        return ("challenge_reply", token, session_id, parts[5], cipher, congestion_control, ustp2beta)
    if payload.startswith(DATA_PORT_PREFIX):
        try:
            return ("data_ready", payload[len(DATA_PORT_PREFIX):].decode("ascii", "replace"))
        except Exception:
            return None
    if payload.startswith(RESUME_PREFIX):
        try:
            return ("resume", payload[len(RESUME_PREFIX):].decode("ascii", "replace"))
        except Exception:
            return None
    return None


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


def parse_hello(payload: bytes) -> tuple[str, str | None, int | None, int | None] | None:
    if payload.startswith(b"USSH-AUTH3\0"):
        rest = payload[len(b"USSH-AUTH3\0") :]
        parts = rest.split(b"\0", 4)
        if len(parts) != 5 or not parts[0]:
            return None
        try:
            rows = int(parts[3].decode("ascii", "replace"))
            cols = int(parts[4].decode("ascii", "replace"))
        except ValueError:
            rows, cols = None, None
        term_name = parts[2].decode("utf-8", "replace") or None
        return parts[0].decode("utf-8", "replace"), term_name, rows, cols
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
        return parts[0].decode("utf-8", "replace"), term_name, rows, cols
    if payload.startswith(b"USSH-AUTH1\0"):
        rest = payload[len(b"USSH-AUTH1\0") :]
        if not rest:
            return None
        return rest.decode("utf-8", "replace"), None, None, None
    return None


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def resolve_host_ips(host: str) -> set[str]:
    normalized = host.strip().strip("[]")
    ips = set()
    try:
        ips.add(str(ipaddress.ip_address(normalized)))
        return ips
    except ValueError:
        pass
    for item in socket.getaddrinfo(normalized, None, socket.AF_UNSPEC, socket.SOCK_DGRAM):
        sockaddr = item[4]
        if sockaddr:
            ips.add(sockaddr[0])
    return ips


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


def create_server_udp_socket(bind_ip: str, bind_port: int) -> socket.socket:
    bind_host = bind_ip
    if bind_host == "0.0.0.0":
        bind_host = "::"
    infos = socket.getaddrinfo(bind_host, bind_port, socket.AF_UNSPEC, socket.SOCK_DGRAM, 0, socket.AI_PASSIVE)
    last_error = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            sock = socket.socket(family, socktype, proto)
            if family == socket.AF_INET6:
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            tune_udp_socket(sock)
            sock.bind(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            try:
                sock.close()
            except Exception:
                pass
    if last_error is not None:
        raise last_error
    raise OSError(errno.EADDRNOTAVAIL, "unable to bind UDP socket")


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
        "--ustp2beta",
        args.ustp2beta,
        "--no-systemd-prompt",
    ]
    if args.shell:
        cmd += ["--shell", args.shell]
    service = "\n".join([
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
    ])
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
    ap.add_argument("--congestion-control", choices=["auto", "on", "off"], default="auto", help="Server-side USTPS Congestion policy")
    ap.add_argument("--ustp2beta", choices=["auto", "on", "off"], default="auto", help="Server-side USTP/2 Beta policy")
    ap.add_argument("--host-key-file", default=os.path.expanduser("~/.ussh_host_key"))
    ap.add_argument("--regen-key", action="store_true", help="Regenerate the persistent server host key after interactive confirmation")
    ap.add_argument("--shell", default=None)
    ap.add_argument("--term", default="vt100")
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
    raw = create_server_udp_socket(args.bind_ip, args.bind_port)
    raw.settimeout(0.2)
    maybe_regen_host_key(args.host_key_file, args.regen_key)
    host_private = load_or_create_host_key(args.host_key_file)
    host_public = public_bytes(host_private.public_key())
    selected_cipher = None if args.cipher == "auto" else normalize_cipher_name(args.cipher)
    sock = AEADDatagramSocket(raw, cipher_name=selected_cipher or "chacha20")
    running = True
    sessions: dict[tuple[str, int], ClientSession] = {}
    sessions_by_id: dict[str, ClientSession] = {}
    pending_challenges: dict[tuple[str, int], PendingChallenge] = {}
    sessions_lock = threading.Lock()

    def prepare_shell_process() -> None:
        os.setsid()
        # Keep detached/background jobs alive when the USSH PTY disappears.
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    def send_challenge(addr: tuple[str, int], client_pub_raw: bytes, requested_cipher: str | None, requested_cc: str | None, requested_u2: str | None) -> None:
        cipher = selected_cipher or requested_cipher or "chacha20"
        cc_mode = resolve_server_cc_mode(args.congestion_control, requested_cc)
        u2_mode = resolve_server_ustp2beta_mode(args.ustp2beta, requested_u2)
        challenge = pending_challenges.get(addr)
        if (
            challenge is None
            or challenge.client_pub != client_pub_raw
            or challenge.cipher != cipher
            or challenge.congestion_control != cc_mode
            or challenge.ustp2beta != u2_mode
        ):
            challenge = PendingChallenge(
                addr=addr,
                client_pub=client_pub_raw,
                cipher=cipher,
                congestion_control=cc_mode,
                ustp2beta=u2_mode,
                session_id=b64u(secrets.token_bytes(18)),
                token=b64u(secrets.token_bytes(18)),
                created_ts=time.time(),
            )
            pending_challenges[addr] = challenge
        payload = CHALLENGE_PREFIX + challenge.token.encode("ascii") + b"\0" + challenge.session_id.encode("ascii") + b"\0" + challenge.cipher.encode("ascii") + b"\0cc=" + challenge.congestion_control.encode("ascii") + b"\0u2=" + challenge.ustp2beta.encode("ascii") + b"\0" + host_public
        sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=payload).to_bytes(), addr)

    def new_session(addr: tuple[str, int], challenge: PendingChallenge) -> ClientSession:
        client_pub = x25519.X25519PublicKey.from_public_bytes(challenge.client_pub)
        session_psk = derive_session_key(host_private.exchange(client_pub), challenge.client_pub, host_public)
        session_reply = (
            SESSION_PREFIX
            + challenge.session_id.encode("ascii")
            + b"\0"
            + challenge.cipher.encode("ascii")
            + b"\0cc="
            + challenge.congestion_control.encode("ascii")
            + b"\0u2="
            + challenge.ustp2beta.encode("ascii")
            + b"\0"
            + host_public
        )
        sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=session_reply).to_bytes(), addr)
        sock.set_peer_psk(addr, session_psk, challenge.cipher)
        sender = USTPSender(sock=sock, peer=addr, window=args.window, rto=args.rto, quiet=True, congestion_control=(challenge.congestion_control == "on"))
        receiver = USTPReceiver(sock=sock, peer=addr)
        receiver.quiet_recv = True
        sender.start()
        session = ClientSession(
            addr=addr,
            sender=sender,
            receiver=receiver,
            cipher=challenge.cipher,
            session_psk=session_psk,
            client_pub=challenge.client_pub,
            server_pub=host_public,
            session_id=challenge.session_id,
            session_reply=session_reply,
            ustp2beta=(challenge.ustp2beta == "on"),
            stdin_buffer={},
            last_rx=time.time(),
        )
        sessions[addr] = session
        sessions_by_id[challenge.session_id] = session
        pending_challenges.pop(addr, None)
        print(f"[USSH-SERVER] client joined {addr[0]}:{addr[1]} cipher={challenge.cipher} cc={challenge.congestion_control} session={challenge.session_id}")
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
            if session.session_id:
                sessions_by_id.pop(session.session_id, None)
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
                # Background jobs may keep the PTY open after the interactive
                # shell exits. The session lifetime follows the shell itself.
                if session.proc is not None and session.proc.poll() is not None:
                    break
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
                try:
                    session.receiver.maybe_nack()
                except OSError:
                    pass
                except Exception:
                    pass
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
                    if ustp_pkt.pkt_type == USTP_TYPE_HELLO:
                        parsed = parse_kex(ustp_pkt.payload)
                        if parsed is not None:
                            kind = parsed[0]
                            if kind == "init":
                                _, client_pub, requested_cipher, requested_cc, requested_u2 = parsed
                                if session is not None and session.client_pub == client_pub:
                                    session.last_rx = time.time()
                                    if session.session_reply is not None:
                                        sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=session.session_reply).to_bytes(), addr)
                                elif session is None:
                                    send_challenge(addr, client_pub, requested_cipher, requested_cc, requested_u2)
                                    continue
                            elif kind == "challenge_reply":
                                _, token, session_id, client_pub, requested_cipher, requested_cc, requested_u2 = parsed
                                pending = pending_challenges.get(addr)
                                if (
                                    pending
                                    and pending.token == token
                                    and pending.session_id == session_id
                                    and pending.client_pub == client_pub
                                    and pending.cipher == requested_cipher
                                    and pending.congestion_control == resolve_server_cc_mode(args.congestion_control, requested_cc)
                                    and pending.ustp2beta == resolve_server_ustp2beta_mode(args.ustp2beta, requested_u2)
                                ):
                                    session = new_session(addr, pending)
                                else:
                                    continue
                            elif kind == "data_ready":
                                _, ready_session_id = parsed
                                data_session = sessions_by_id.get(ready_session_id)
                                if data_session is not None and data_session.ustp2beta and data_session.addr[0] == addr[0]:
                                    data_session.data_addr = addr
                                    data_session.data_ready = True
                                    data_session.sender.peer = addr
                                    sock.set_peer_psk(addr, data_session.session_psk, data_session.cipher)
                                    continue
                            elif kind == "resume":
                                _, session_id = parsed
                                resume_session = sessions_by_id.get(session_id)
                                if resume_session is not None and resume_session.addr == addr:
                                    session = resume_session
                                    if session.session_reply is not None:
                                        sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=session.session_reply).to_bytes(), addr)
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
                        password, client_term, client_rows, client_cols = hello
                        if not hmac_compare(password, args.password):
                            print(f"[USSH-SERVER] auth failed from {addr[0]}:{addr[1]}")
                            send(session, TYPE_AUTH_FAIL, b"bad password")
                            time.sleep(0.1)
                            close_session(session)
                            continue
                        print(f"[USSH-SERVER] HELLO from {addr[0]}:{addr[1]} mode=shell")
                        master_fd = None
                        slave_fd = None
                        try:
                            master_fd, slave_fd = pty.openpty()
                            env = os.environ.copy()
                            env["HOME"] = login_home
                            env["USER"] = login_user
                            env["LOGNAME"] = login_user
                            env["SHELL"] = login_shell
                            env["TERM"] = client_term or args.term
                            shell_argv = [f"-{os.path.basename(login_shell)}"]
                            shell_executable = login_shell
                            if os.environ.get("INVOCATION_ID") and shutil.which("systemd-run"):
                                # Keep session jobs outside ussh.service. A
                                # daemonized child retains its cgroup even after
                                # its parent shell exits.
                                scope_name = f"ussh-session-{session.session_id or secrets.token_hex(8)}"
                                shell_argv = [
                                    "systemd-run",
                                    "--scope",
                                    "--quiet",
                                    "--collect",
                                    f"--unit={scope_name}",
                                    login_shell,
                                    "-l",
                                ]
                                shell_executable = None
                            proc = subprocess.Popen(
                                shell_argv,
                                executable=shell_executable,
                                stdin=slave_fd,
                                stdout=slave_fd,
                                stderr=slave_fd,
                                cwd=login_home,
                                env=env,
                                close_fds=True,
                                preexec_fn=prepare_shell_process,
                            )
                            os.close(slave_fd)
                            slave_fd = None
                            session.proc = proc
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

                            # READY means the PTY and login shell are actually usable.
                            session.ready = True
                            send(session, TYPE_READY, b"ready")
                            threading.Thread(target=shell_loop, args=(session,), daemon=True).start()
                        except Exception:
                            print(f"[USSH-SERVER] shell startup failed {addr[0]}:{addr[1]}:")
                            traceback.print_exc()
                            send(session, TYPE_AUTH_FAIL, b"shell startup failed")
                            if slave_fd is not None:
                                try:
                                    os.close(slave_fd)
                                except OSError:
                                    pass
                            if master_fd is not None and session.pty_fd is None:
                                try:
                                    os.close(master_fd)
                                except OSError:
                                    pass
                            close_session(session)
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
