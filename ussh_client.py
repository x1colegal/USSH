import argparse
import base64
import errno
import faulthandler
import getpass
import ipaddress
import json
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
    USHPacket,
)
from ussh_proto import mkp as ush_mkp


KEX_PREFIX = b"USSH-KEX1 "
CHALLENGE_PREFIX = b"USSH-CHALLENGE1 "
RESPONSE_PREFIX = b"USSH-CHALLENGE-REPLY1 "
RESUME_PREFIX = b"USSH-RESUME1 "
SESSION_PREFIX = b"USSH-SESSION1 "
UDP_BUFFER_BYTES = 4 * 1024 * 1024


def tune_udp_socket(sock: socket.socket) -> None:
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, UDP_BUFFER_BYTES)
        except OSError:
            pass


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


def b64u_decode(text: str) -> bytes:
    padded = text + ("=" * (-len(text) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def encode_ascii_record(prefix: bytes, **fields: str) -> bytes:
    parts = [prefix.rstrip()]
    for key, value in fields.items():
        parts.append(f"{key}={value}".encode("ascii"))
    return b" ".join(parts)


def parse_ascii_record(payload: bytes, prefix: bytes) -> dict[str, str] | None:
    if not payload.startswith(prefix):
        return None
    try:
        text = payload[len(prefix) :].decode("ascii")
    except Exception:
        return None
    out: dict[str, str] = {}
    for token in text.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        out[key] = value
    return out


def encode_transport_hello(client_pub: bytes, cipher: str, cc_mode: str) -> bytes:
    return encode_ascii_record(KEX_PREFIX, pub=b64u(client_pub), cipher=cipher, cc=cc_mode)


def load_tofu(path: str) -> dict[str, str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}
    return {}


def save_tofu(path: str, data: dict[str, str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def confirm_regen(peer_label: str) -> bool:
    if not os.isatty(0):
        return False
    answer = input(f"TOFU key changed for {peer_label}. Accept and replace stored key? [y/N] ").strip().lower()
    return answer in ("y", "yes")


def check_tofu(path: str, peer_label: str, server_pub: bytes, allow_regen: bool = False) -> None:
    db = load_tofu(path)
    fp = server_pub.hex()
    known = db.get(peer_label)
    if known is None:
        db[peer_label] = fp
        save_tofu(path, db)
        print(f"[USSH-CLIENT] TOFU trust established for {peer_label}")
        return
    if known != fp:
        if allow_regen and confirm_regen(peer_label):
            db[peer_label] = fp
            save_tofu(path, db)
            print(f"[USSH-CLIENT] TOFU key replaced for {peer_label}")
            return
        raise SystemExit(f"TOFU mismatch for {peer_label}: possible MITM or server key change")


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


def resolve_peer_candidates(host: str, port: int):
    normalized = host.strip().strip("[]")
    infos = socket.getaddrinfo(normalized, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    candidates = []
    seen = set()
    for family in (socket.AF_INET6, socket.AF_INET):
        for fam, _, _, _, sockaddr in infos:
            if fam != family:
                continue
            key = (fam, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((fam, sockaddr))
    return candidates


def bind_udp_socket(bind_ip: str, bind_port: int, family: int) -> socket.socket:
    bind_host = bind_ip
    if family == socket.AF_INET6 and bind_host == "0.0.0.0":
        bind_host = "::"
    if family == socket.AF_INET and bind_host == "::":
        bind_host = "0.0.0.0"
    sock = socket.socket(family, socket.SOCK_DGRAM)
    tune_udp_socket(sock)
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
        sock.bind((bind_host, bind_port, 0, 0))
    else:
        sock.bind((bind_host, bind_port))
    return sock


def is_temporary_network_error(exc: OSError) -> bool:
    return exc.errno in (
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENETDOWN,
        errno.EADDRNOTAVAIL,
        errno.ENODEV,
    )


def is_recoverable_socket_error(exc: BaseException) -> bool:
    if isinstance(exc, socket.timeout):
        return True
    if not isinstance(exc, OSError):
        return False
    return is_temporary_network_error(exc) or exc.errno in (
        errno.EBADF,
        errno.ENOTCONN,
        errno.ECONNRESET,
        errno.ECONNREFUSED,
        errno.EPIPE,
    )


def get_winsize():
    for fd in (sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()):
        try:
            size = os.get_terminal_size(fd)
            if size.lines > 0 and size.columns > 0:
                return size.lines, size.columns
        except Exception:
            pass
    rows = int(os.environ.get("LINES", "24") or "24")
    cols = int(os.environ.get("COLUMNS", "80") or "80")
    return rows, cols


def enter_client_tty_mode(fd: int):
    attrs = termios.tcgetattr(fd)
    tty.setcbreak(fd, termios.TCSADRAIN)
    new = termios.tcgetattr(fd)
    new[0] &= ~(termios.IXON | termios.IXOFF | termios.ICRNL | termios.INLCR | termios.IGNCR)
    new[1] |= termios.OPOST
    new[3] &= ~(termios.ECHO | termios.ISIG)
    termios.tcsetattr(fd, termios.TCSADRAIN, new)
    return attrs


def make_auth_payload(password: str, term_name: str, rows: int, cols: int) -> bytes:
    return (
        b"USSH-AUTH3\0"
        + password.encode("utf-8")
        + b"\0shell\0"
        + term_name.encode("utf-8", "replace")
        + b"\0"
        + str(rows).encode("ascii")
        + b"\0"
        + str(cols).encode("ascii")
    )


def main() -> None:
    faulthandler.enable(all_threads=True)
    ap = argparse.ArgumentParser(description="USSH client")
    ap.add_argument("--peer-ip", required=True)
    ap.add_argument("--peer-port", type=int, default=5322)
    ap.add_argument("--bind-ip", default="0.0.0.0")
    ap.add_argument("--bind-port", type=int, default=0)
    ap.add_argument("--cipher", default="chacha20")
    ap.add_argument("--congestion-control", choices=["on", "off"], default="off", help="Request USTPS Congestion from the server")
    ap.add_argument("--connect-timeout", type=float, default=8.0)
    ap.add_argument("--session-timeout", type=float, default=10.0)
    ap.add_argument("--keepalive-interval", type=float, default=1.0)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--tofu-file", default=os.path.expanduser("~/.ussh_known_hosts.json"))
    ap.add_argument("--regen-key", action="store_true", help="Allow replacing a stored TOFU server key after interactive confirmation")
    args = ap.parse_args()

    password = getpass.getpass(f"{args.peer_ip}'s password: ")
    term_name = os.environ.get("TERM", "xterm-256color")
    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    selected_cipher = normalize_cipher_name(args.cipher)
    tofu_label = f"{args.peer_ip}:{args.peer_port}"
    candidates = resolve_peer_candidates(args.peer_ip, args.peer_port)
    if not candidates:
        raise SystemExit(f"Could not resolve {args.peer_ip}")

    client_private = x25519.X25519PrivateKey.generate()
    client_pub = public_bytes(client_private.public_key())

    running = True
    ready = threading.Event()
    shell_ready = False
    kex_ready = False
    last_rx = time.time()
    last_ready_rx = 0.0
    stdout_next_pos = 0
    stdout_buffer: dict[int, bytes] = {}
    stdin_seq = 1
    raw = None
    sock = None
    peer = None
    session_addr = None
    sender = None
    receiver = None
    active_family = None
    session_id = None
    challenge_token = None
    state_lock = threading.RLock()
    reconnect_lock = threading.Lock()
    recovery_in_progress = False
    last_recovery_attempt_ts = 0.0
    last_recovery_log_ts = 0.0
    last_temporary_network_error_ts = 0.0
    tty_raw = False

    def client_log(message: str) -> None:
        if tty_raw:
            return
        print(message)

    def recovery_log(message: str) -> None:
        prefix = "\r\n" if tty_raw else ""
        suffix = "\r\n" if tty_raw else "\n"
        try:
            os.write(sys.stderr.fileno(), f"{prefix}{message}{suffix}".encode("utf-8", "replace"))
        except Exception:
            pass

    def connect_transport(prefer_resume: bool) -> bool:
        nonlocal raw, sock, peer, session_addr, sender, receiver, active_family
        nonlocal session_id, challenge_token, kex_ready, last_rx, last_ready_rx, last_temporary_network_error_ts
        nonlocal stdout_next_pos, stdout_buffer, stdin_seq
        nonlocal shell_ready
        previous_session_id = session_id
        local_session_id = session_id
        local_challenge_token = challenge_token
        temp_network_blocked = False
        for idx, (family, sockaddr) in enumerate(candidates):
            raw_candidate = None
            sender_candidate = None
            try:
                raw_candidate = bind_udp_socket(args.bind_ip, args.bind_port, family)
                raw_candidate.settimeout(0.2)
                sock_candidate = AEADDatagramSocket(raw_candidate, cipher_name=selected_cipher)
                sender_candidate = USTPSender(sock=sock_candidate, peer=sockaddr, window=args.window, rto=args.rto, quiet=True)
                receiver_candidate = USTPReceiver(sock=sock_candidate, peer=sockaddr)
                receiver_candidate.quiet_recv = True
                sender_candidate.start()
                deadline = time.time() + (0.9 if prefer_resume else 2.0)
                while time.time() < deadline and running:
                    try:
                        if prefer_resume and local_session_id:
                            hello_payload = encode_ascii_record(RESUME_PREFIX, session=local_session_id)
                        elif local_challenge_token and local_session_id:
                            hello_payload = encode_ascii_record(
                                RESPONSE_PREFIX,
                                token=local_challenge_token,
                                session=local_session_id,
                                cipher=selected_cipher,
                                cc=args.congestion_control,
                                pub=b64u(client_pub),
                            )
                        else:
                            hello_payload = encode_transport_hello(client_pub, selected_cipher, args.congestion_control)
                        sock_candidate.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=hello_payload).to_bytes(), sockaddr)
                    except OSError as exc:
                        if is_temporary_network_error(exc):
                            temp_network_blocked = True
                            last_temporary_network_error_ts = time.time()
                            break
                        raise
                    try:
                        rawp, addr = sock_candidate.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        if is_recoverable_socket_error(exc):
                            temp_network_blocked = True
                            last_temporary_network_error_ts = time.time()
                            break
                        raise
                    if addr != sockaddr:
                        continue
                    ustp_pkt = parse_packet(rawp)
                    if not ustp_pkt:
                        continue
                    if ustp_pkt.pkt_type == USTP_TYPE_HELLO and ustp_pkt.payload.startswith(CHALLENGE_PREFIX):
                        fields = parse_ascii_record(ustp_pkt.payload, CHALLENGE_PREFIX)
                        if not fields:
                            continue
                        token = fields.get("token", "")
                        new_session_id = fields.get("session", "")
                        session_cipher = normalize_cipher_name(fields.get("cipher", selected_cipher))
                        negotiated_cc = fields.get("cc") or "off"
                        try:
                            server_pub = b64u_decode(fields["pub"])
                        except Exception:
                            continue
                        if session_cipher != selected_cipher:
                            raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                        if negotiated_cc not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                        check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                        try:
                            sock_candidate.send_plain(
                                ustp_mkp(
                                    USTP_TYPE_HELLO,
                                    payload=encode_ascii_record(
                                        RESPONSE_PREFIX,
                                        token=token,
                                        session=new_session_id,
                                        cipher=selected_cipher,
                                        cc=args.congestion_control,
                                        pub=b64u(client_pub),
                                    ),
                                ).to_bytes(),
                                sockaddr,
                            )
                        except OSError as exc:
                            if is_temporary_network_error(exc):
                                temp_network_blocked = True
                                last_temporary_network_error_ts = time.time()
                                break
                            raise
                        local_session_id = new_session_id
                        local_challenge_token = token
                        continue
                    if ustp_pkt.pkt_type == USTP_TYPE_HELLO and ustp_pkt.payload.startswith(SESSION_PREFIX):
                        fields = parse_ascii_record(ustp_pkt.payload, SESSION_PREFIX)
                        if not fields:
                            continue
                        new_session_id = fields.get("session", "")
                        session_cipher = normalize_cipher_name(fields.get("cipher", selected_cipher))
                        negotiated_cc = fields.get("cc") or "off"
                        try:
                            server_pub = b64u_decode(fields["pub"])
                        except Exception:
                            continue
                        if session_cipher != selected_cipher:
                            raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                        if negotiated_cc not in ("on", "off"):
                            raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                        check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                        server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                        sock_candidate.set_peer_psk(
                            addr,
                            derive_session_key(client_private.exchange(server_public), client_pub, server_pub),
                            session_cipher,
                        )
                        print(f"[USSH-CLIENT] transport ready cipher={session_cipher} cc={negotiated_cc} session={new_session_id}")
                        sender_candidate.peer = addr
                        receiver_candidate.peer = addr
                        resume_ack = prefer_resume and previous_session_id == new_session_id
                        if not resume_ack:
                            rows, cols = get_winsize()
                            sender_candidate.queue_payload(ush_mkp(TYPE_HELLO, payload=make_auth_payload(password, term_name, rows, cols)).to_bytes())
                        local_session_id = new_session_id
                        local_challenge_token = None
                        kex_ready = True
                        if resume_ack:
                            sender_candidate.queue_payload(ush_mkp(TYPE_PING, payload=b"resume-check").to_bytes())
                        while time.time() < deadline and running:
                            try:
                                rawp2, addr2 = sock_candidate.recvfrom(65535)
                            except socket.timeout:
                                continue
                            except OSError as exc:
                                if is_recoverable_socket_error(exc):
                                    temp_network_blocked = True
                                    last_temporary_network_error_ts = time.time()
                                    break
                                raise
                            if addr2 != addr:
                                continue
                            ctrl = parse_packet(rawp2)
                            if not ctrl:
                                continue
                            if ctrl.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, USTP_TYPE_HELLO):
                                sender_candidate.on_control(ctrl)
                                continue
                            if ctrl.pkt_type != TYPE_DATA:
                                continue
                            payload = receiver_candidate.handle_data(ctrl)
                            if not payload:
                                continue
                            pkt = USHPacket.from_bytes(payload)
                            if pkt.pkt_type == TYPE_AUTH_FAIL:
                                raise SystemExit("USSH authentication failed")
                            if resume_ack and shell_ready and pkt.pkt_type in (TYPE_PONG, TYPE_READY, TYPE_STDOUT):
                                with state_lock:
                                    old_raw = raw
                                    raw = raw_candidate
                                    sock = sock_candidate
                                    peer = addr
                                    session_addr = addr
                                    sender = sender_candidate
                                    receiver = receiver_candidate
                                    active_family = family
                                    session_id = local_session_id
                                    challenge_token = None
                                    last_rx = time.time()
                                    last_ready_rx = time.time()
                                if old_raw is not None and old_raw is not raw_candidate:
                                    try:
                                        old_raw.close()
                                    except Exception:
                                        pass
                                if pkt.pkt_type == TYPE_STDOUT and len(pkt.payload) >= 8:
                                    pos = int.from_bytes(pkt.payload[:8], "big")
                                    data = pkt.payload[8:]
                                    if data and pos not in stdout_buffer:
                                        stdout_buffer[pos] = data
                                return True
                            if not resume_ack and pkt.pkt_type == TYPE_READY:
                                ready.set()
                                shell_ready = True
                                with state_lock:
                                    old_raw = raw
                                    raw = raw_candidate
                                    sock = sock_candidate
                                    peer = addr
                                    session_addr = addr
                                    sender = sender_candidate
                                    receiver = receiver_candidate
                                    active_family = family
                                    session_id = local_session_id
                                    challenge_token = None
                                    last_rx = time.time()
                                    last_ready_rx = time.time()
                                    if previous_session_id != local_session_id:
                                        stdout_next_pos = 0
                                        stdout_buffer.clear()
                                        stdin_seq = 1
                                if old_raw is not None and old_raw is not raw_candidate:
                                    try:
                                        old_raw.close()
                                    except Exception:
                                        pass
                                client_log(f"[USSH-CLIENT] secure session from {addr[0]}:{addr[1]} aead={session_cipher}")
                                client_log(f"[USSH-CLIENT] READY from {addr[0]}:{addr[1]}")
                                return True
                        continue
                    if ustp_pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, USTP_TYPE_HELLO):
                        sender_candidate.on_control(ustp_pkt)
                        continue
                sender_candidate.stop()
            except OSError as exc:
                if is_temporary_network_error(exc):
                    temp_network_blocked = True
                    last_temporary_network_error_ts = time.time()
                else:
                    raise
            finally:
                if raw_candidate is not None:
                    with state_lock:
                        keep_candidate = raw_candidate is raw
                    if not keep_candidate:
                        try:
                            raw_candidate.close()
                        except Exception:
                            pass
                if sender_candidate is not None:
                    with state_lock:
                        keep_sender = sender_candidate is sender
                    if not keep_sender:
                        sender_candidate.stop()
            if temp_network_blocked:
                break
            if idx + 1 < len(candidates):
                client_log(f"[USSH-CLIENT] fallback to next address after trying {sockaddr[0]}")
        return False

    if not connect_transport(prefer_resume=False):
        raise SystemExit("USSH server did not reply with READY")
    if not ready.is_set() or raw is None or sock is None or peer is None or sender is None or receiver is None:
        raise SystemExit("USSH server did not reply with READY")

    def send(pkt_type: int, payload: bytes = b"", seq: int = 0) -> int:
        nonlocal last_temporary_network_error_ts
        with state_lock:
            local_sender = sender
        if local_sender is None:
            return 0
        chunk_size = max(1, MAX_PAYLOAD - HEADER_SIZE)
        try:
            if not payload:
                local_sender.queue_payload(ush_mkp(pkt_type, payload=b"", seq=seq).to_bytes())
                return 1
            sent = 0
            for i in range(0, len(payload), chunk_size):
                chunk_seq = seq + sent if pkt_type == TYPE_STDIN and seq else seq
                local_sender.queue_payload(ush_mkp(pkt_type, payload=payload[i : i + chunk_size], seq=chunk_seq).to_bytes())
                sent += 1
            return sent
        except OSError as exc:
            if is_recoverable_socket_error(exc):
                last_temporary_network_error_ts = time.time()
                return 0
            return 0
        except Exception:
            return 0

    def stdin_loop() -> None:
        nonlocal stdin_seq
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
            sent = send(TYPE_STDIN, data, seq=stdin_seq)
            stdin_seq += sent

    def nack_loop() -> None:
        while running:
            with state_lock:
                local_receiver = receiver
            if local_receiver is not None:
                try:
                    local_receiver.maybe_nack()
                except OSError as exc:
                    if is_recoverable_socket_error(exc):
                        pass
                    else:
                        pass
                except Exception:
                    pass
            time.sleep(0.03)

    def keepalive_loop() -> None:
        nonlocal last_temporary_network_error_ts
        while running:
            with state_lock:
                local_sock = sock
                local_peer = peer
                local_kex_ready = kex_ready
                local_session_id = session_id
                local_challenge_token = challenge_token
            if local_sock is None or local_peer is None:
                time.sleep(args.keepalive_interval)
                continue
            if local_kex_ready and ready.is_set():
                send(TYPE_PING, b"keepalive")
                time.sleep(args.keepalive_interval)
                continue
            if local_challenge_token and local_session_id:
                hello_payload = encode_ascii_record(
                    RESPONSE_PREFIX,
                    token=local_challenge_token,
                    session=local_session_id,
                    cipher=selected_cipher,
                    cc=args.congestion_control,
                    pub=b64u(client_pub),
                )
            else:
                hello_payload = encode_transport_hello(client_pub, selected_cipher, args.congestion_control, KEX_PREFIX)
            try:
                local_sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=hello_payload).to_bytes(), local_peer)
            except OSError as exc:
                if is_temporary_network_error(exc):
                    last_temporary_network_error_ts = time.time()
                    time.sleep(args.keepalive_interval)
                    continue
                time.sleep(args.keepalive_interval)
                continue
            time.sleep(args.keepalive_interval)

    print(
        f"[USSH-CLIENT] local={sock.getsockname()} peer={args.peer_ip}:{args.peer_port} "
        f"resolved={peer[0]} family={'IPv6' if active_family == socket.AF_INET6 else 'IPv4'} aead={selected_cipher}"
    )

    def sigwinch(_signum, _frame):
        rows, cols = get_winsize()
        try:
            send(TYPE_RESIZE, rows.to_bytes(2, "big") + cols.to_bytes(2, "big"))
        except Exception:
            pass

    signal.signal(signal.SIGWINCH, sigwinch)

    old = termios.tcgetattr(sys.stdin.fileno())
    stdin_started = False
    try:
        if ready.is_set() and not tty_raw:
            enter_client_tty_mode(sys.stdin.fileno())
            tty_raw = True
            sigwinch(None, None)
            if not stdin_started:
                threading.Thread(target=stdin_loop, daemon=True).start()
                stdin_started = True
        threading.Thread(target=keepalive_loop, daemon=True).start()
        threading.Thread(target=nack_loop, daemon=True).start()
        while running:
            if ready.is_set() and (time.time() - last_rx) >= args.session_timeout:
                print("\n[USSH-CLIENT] no data from server; closing session", file=sys.stderr)
                running = False
                break
            try:
                with state_lock:
                    local_sock = sock
                    local_session_addr = session_addr
                    local_sender = sender
                    local_receiver = receiver
                if local_sock is None or local_sender is None or local_receiver is None:
                    time.sleep(0.1)
                    continue
                rawp, addr = local_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if is_temporary_network_error(exc) or exc.errno in (errno.EBADF, errno.ENOTCONN, errno.ECONNRESET):
                    last_temporary_network_error_ts = time.time()
                    print(f"\n[USSH-CLIENT] network/socket unavailable: {exc}; closing session", file=sys.stderr)
                    running = False
                    break
                continue
            if local_session_addr is not None and addr != local_session_addr:
                continue
            try:
                ustp_pkt = parse_packet(rawp)
            except Exception:
                continue
            if not ustp_pkt:
                continue
            if ustp_pkt.pkt_type == USTP_TYPE_HELLO and ustp_pkt.payload.startswith(CHALLENGE_PREFIX):
                fields = parse_ascii_record(ustp_pkt.payload, CHALLENGE_PREFIX)
                if fields is None:
                    continue
                try:
                    token = fields["token"]
                    new_session_id = fields["session"]
                    session_cipher = fields.get("cipher", selected_cipher) or selected_cipher
                    negotiated_cc = fields.get("cc", "off") or "off"
                    server_pub = b64u_decode(fields["pub"])
                except Exception:
                    continue
                if session_cipher != selected_cipher:
                    raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                if negotiated_cc not in ("on", "off"):
                    raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                try:
                    local_sock.send_plain(
                        ustp_mkp(
                            USTP_TYPE_HELLO,
                            payload=encode_ascii_record(
                                RESPONSE_PREFIX,
                                token=token,
                                session=new_session_id,
                                cipher=selected_cipher,
                                cc=args.congestion_control,
                                pub=b64u(client_pub),
                            ),
                        ).to_bytes(),
                        peer,
                    )
                except OSError as exc:
                    if is_temporary_network_error(exc):
                        last_temporary_network_error_ts = time.time()
                        continue
                    raise
                session_id = new_session_id
                challenge_token = token
                continue
            if ustp_pkt.pkt_type == USTP_TYPE_HELLO and ustp_pkt.payload.startswith(SESSION_PREFIX):
                fields = parse_ascii_record(ustp_pkt.payload, SESSION_PREFIX)
                if fields is not None:
                    previous_session_id = session_id
                    try:
                        new_session_id = fields["session"]
                        session_cipher = fields.get("cipher", selected_cipher) or selected_cipher
                        negotiated_cc = fields.get("cc", "off") or "off"
                        server_pub = b64u_decode(fields["pub"])
                    except Exception:
                        continue
                    if session_cipher != selected_cipher:
                        raise SystemExit(f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}")
                    if negotiated_cc not in ("on", "off"):
                        raise SystemExit(f"Server negotiated invalid congestion-control mode {negotiated_cc}")
                    check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
                    server_public = x25519.X25519PublicKey.from_public_bytes(server_pub)
                    same_session = session_id == new_session_id
                    local_sock.set_peer_psk(addr, derive_session_key(client_private.exchange(server_public), client_pub, server_pub), session_cipher)
                    session_addr = addr
                    local_sender.peer = addr
                    local_receiver.peer = addr
                    kex_ready = True
                    session_id = new_session_id
                    if not same_session:
                        stdout_next_pos = 0
                        stdout_buffer.clear()
                        stdin_seq = 1
                        client_log(f"[USSH-CLIENT] secure session from {addr[0]}:{addr[1]} session={session_id} aead={session_cipher} cc={negotiated_cc}")
                        rows, cols = get_winsize()
                        send(TYPE_HELLO, make_auth_payload(password, term_name, rows, cols))
                continue
            if ustp_pkt.pkt_type in (TYPE_ACK, TYPE_RETRANSMIT_REQUEST, USTP_TYPE_HELLO):
                local_sender.on_control(ustp_pkt)
                continue
            if ustp_pkt.pkt_type != TYPE_DATA:
                continue
            payload = local_receiver.handle_data(ustp_pkt)
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
                shell_ready = True
                last_ready_rx = time.time()
                client_log(f"[USSH-CLIENT] READY from {addr[0]}:{addr[1]}")
                enter_client_tty_mode(sys.stdin.fileno())
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
                running = False
                break
            if pkt.pkt_type == TYPE_CLOSE:
                running = False
                break
        send(TYPE_CLOSE, b"")
    except KeyboardInterrupt:
        send(TYPE_CLOSE, b"")
    except OSError as exc:
        if not is_recoverable_socket_error(exc):
            print(f"\n[USSH-CLIENT] socket error ignored: {exc}", file=sys.stderr)
    except SystemExit as exc:
        print(f"\n[USSH-CLIENT] {exc}", file=sys.stderr)
    finally:
        if tty_raw:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        running = False
        sender.stop()


if __name__ == "__main__":
    main()
