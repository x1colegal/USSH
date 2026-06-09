import argparse
import faulthandler
import getpass
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
    USHPacket,
)
from ussh_proto import mkp as ush_mkp
from ussh_proto import TYPE_AUTH_FAIL


KEX_PREFIX = b"USSH-KEX1\0"
SESSION_PREFIX = b"USSH-SESSION1\0"
UDP_BUFFER_BYTES = 4 * 1024 * 1024


def human_bytes(value: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(max(0.0, value))
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def human_eta(seconds: float) -> str:
    if seconds <= 0:
        return "0s"
    total = int(seconds)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h}h{m:02d}m{s:02d}s"
    if m > 0:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def fit_progress_line(line: str) -> str:
    try:
        columns = os.get_terminal_size(sys.stdout.fileno()).columns
    except Exception:
        columns = int(os.environ.get("COLUMNS", "120") or "120")
    columns = max(40, columns)
    if len(line) <= columns - 1:
        return line
    keep = max(8, columns - 4)
    return line[:keep] + "..."


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
    ips = set()
    for item in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM):
        sockaddr = item[4]
        if sockaddr:
            ips.add(sockaddr[0])
    if not ips:
        ips.add(socket.gethostbyname(host))
    return ips


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


def make_auth_payload(password: str, mode: str, term_name: str, rows: int, cols: int) -> bytes:
    return (
        b"USSH-AUTH3\0"
        + password.encode("utf-8")
        + b"\0"
        + mode.encode("ascii")
        + b"\0"
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
    ap.add_argument("--connect-timeout", type=float, default=8.0)
    ap.add_argument("--session-timeout", type=float, default=10.0)
    ap.add_argument("--keepalive-interval", type=float, default=5.0)
    ap.add_argument("--window", type=int, default=512)
    ap.add_argument("--rto", type=float, default=0.25)
    ap.add_argument("--tofu-file", default=os.path.expanduser("~/.ussh_known_hosts.json"))
    ap.add_argument("--regen-key", action="store_true", help="Allow replacing a stored TOFU server key after interactive confirmation")
    ap.add_argument("--transfer-file", default=None, help="Upload a file to the server instead of opening an interactive shell")
    args = ap.parse_args()
    password = getpass.getpass(f"{args.peer_ip}'s password: ")
    term_name = os.environ.get("TERM", "xterm-256color")
    transfer_mode = bool(args.transfer_file)
    transfer_path = os.path.abspath(args.transfer_file) if args.transfer_file else None
    transfer_name = os.path.basename(transfer_path) if transfer_path else None
    transfer_size = os.path.getsize(transfer_path) if transfer_path else 0
    effective_window = max(args.window, 8192) if transfer_mode else args.window

    resolved_peer_ips = resolve_host_ips(args.peer_ip)
    resolved_peer_ip = sorted(resolved_peer_ips)[0]
    selected_cipher = normalize_cipher_name(args.cipher)
    tofu_label = f"{args.peer_ip}:{args.peer_port}"
    raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tune_udp_socket(raw)
    raw.settimeout(0.2)
    sock = AEADDatagramSocket(raw, cipher_name=selected_cipher)
    sock.bind((args.bind_ip, args.bind_port))
    peer = (resolved_peer_ip, args.peer_port)
    session_addr = None
    sender = USTPSender(sock=sock, peer=peer, window=effective_window, rto=args.rto, quiet=True)
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
    stdin_seq = 1
    transfer_done = threading.Event()
    transfer_ok = False
    transfer_sent_bytes = 0
    transfer_confirmed_bytes = 0
    transfer_started_at = 0.0
    transfer_buffer_cap_packets = max(1024, effective_window * 2)
    transfer_buffer_cap_bytes = max(2 * 1024 * 1024, transfer_buffer_cap_packets * MAX_PAYLOAD)
    transfer_stats_lock = threading.Lock()
    progress_last_len = 0
    progress_is_tty = sys.stdout.isatty()

    def send(pkt_type: int, payload: bytes = b"", seq: int = 0) -> int:
        if pkt_type == TYPE_FILE_CHUNK:
            sender.queue_payload(ush_mkp(pkt_type, payload=payload, seq=seq).to_bytes())
            return 1
        chunk_size = max(1, MAX_PAYLOAD - HEADER_SIZE)
        if not payload:
            sender.queue_payload(ush_mkp(pkt_type, payload=b"", seq=seq).to_bytes())
            return 1
        sent = 0
        for i in range(0, len(payload), chunk_size):
            chunk_seq = seq + sent if pkt_type == TYPE_STDIN and seq else seq
            sender.queue_payload(ush_mkp(pkt_type, payload=payload[i : i + chunk_size], seq=chunk_seq).to_bytes())
            sent += 1
        return sent

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

    def transfer_file_loop() -> None:
        nonlocal transfer_sent_bytes, transfer_started_at
        if not transfer_path or not transfer_name:
            return
        name_raw = transfer_name.encode("utf-8")
        meta = len(name_raw).to_bytes(2, "big") + transfer_size.to_bytes(8, "big") + name_raw
        send(TYPE_FILE_META, meta)
        chunk_size = max(1, MAX_PAYLOAD - HEADER_SIZE - 8)
        offset = 0
        with transfer_stats_lock:
            transfer_sent_bytes = 0
            transfer_started_at = time.time()
        with open(transfer_path, "rb") as f:
            while running:
                while running:
                    pending_packets, pending_bytes, inflight_packets, retx_packets = sender.get_backlog()
                    if (
                        pending_packets < transfer_buffer_cap_packets
                        and pending_bytes < transfer_buffer_cap_bytes
                        and (inflight_packets + retx_packets) < max(64, effective_window + (effective_window // 2))
                    ):
                        break
                    time.sleep(0.003)
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                send(TYPE_FILE_CHUNK, offset.to_bytes(8, "big") + chunk)
                offset += len(chunk)
                with transfer_stats_lock:
                    transfer_sent_bytes = offset
        send(TYPE_FILE_DONE, transfer_size.to_bytes(8, "big"))

    def transfer_progress_loop() -> None:
        nonlocal progress_last_len
        last_line = ""
        while running and transfer_mode and not transfer_done.is_set():
            if not transfer_name:
                time.sleep(0.2)
                continue
            with transfer_stats_lock:
                sent = transfer_confirmed_bytes if transfer_confirmed_bytes > 0 else transfer_sent_bytes
                started = transfer_started_at
            if started <= 0.0:
                time.sleep(0.2)
                continue
            elapsed = max(0.001, time.time() - started)
            rate = sent / elapsed
            remaining = max(0, transfer_size - sent)
            eta = human_eta(remaining / rate) if rate > 0 else "?"
            line = fit_progress_line(
                f"{human_bytes(sent)} / {human_bytes(transfer_size)}, {human_bytes(rate)}/s, ETA {eta}, {transfer_name}"
            )
            if line != last_line:
                if progress_is_tty:
                    padded = "\r" + line
                    if len(line) < progress_last_len:
                        padded += " " * (progress_last_len - len(line))
                    sys.stdout.write(padded)
                else:
                    sys.stdout.write(line + "\n")
                sys.stdout.flush()
                progress_last_len = len(line)
                last_line = line
            time.sleep(0.25)

    def nack_loop() -> None:
        while running:
            receiver.maybe_nack()
            time.sleep(0.03)

    def keepalive_loop() -> None:
        while running:
            sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=KEX_PREFIX + client_pub + selected_cipher.encode("ascii")).to_bytes(), peer)
            if kex_ready and ready.is_set():
                send(TYPE_PING, b"keepalive")
            time.sleep(args.keepalive_interval)

    print(
        f"[USSH-CLIENT] local={sock.getsockname()} peer={args.peer_ip}:{args.peer_port} "
        f"resolved={','.join(sorted(resolved_peer_ips))} aead={selected_cipher}"
    )
    sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=KEX_PREFIX + client_pub + selected_cipher.encode("ascii")).to_bytes(), peer)

    def sigwinch(_signum, _frame):
        rows, cols = get_winsize()
        send(TYPE_RESIZE, rows.to_bytes(2, "big") + cols.to_bytes(2, "big"))

    signal.signal(signal.SIGWINCH, sigwinch)

    old = termios.tcgetattr(sys.stdin.fileno()) if not transfer_mode else None
    stdin_started = False
    tty_raw = False
    try:
        deadline = time.time() + args.connect_timeout
        threading.Thread(target=keepalive_loop, daemon=True).start()
        threading.Thread(target=nack_loop, daemon=True).start()
        if transfer_mode:
            threading.Thread(target=transfer_progress_loop, daemon=True).start()
        while running:
            if not ready.is_set() and time.time() >= deadline:
                raise SystemExit("USSH server did not reply with READY")
            if ready.is_set() and (time.time() - last_rx) >= (max(args.session_timeout, 60.0) if transfer_mode else args.session_timeout):
                raise SystemExit("USSH session timed out")
            try:
                rawp, addr = sock.recvfrom(65535)
            except socket.timeout:
                sock.send_plain(ustp_mkp(USTP_TYPE_HELLO, payload=KEX_PREFIX + client_pub + selected_cipher.encode("ascii")).to_bytes(), peer)
                if kex_ready and not ready.is_set():
                    rows, cols = get_winsize()
                    send(TYPE_HELLO, make_auth_payload(password, "file" if transfer_mode else "shell", term_name, rows, cols))
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
                    session_cipher = rest[64:].decode("ascii", "replace") or selected_cipher
                    if session_cipher != selected_cipher:
                        raise SystemExit(
                            f"Server negotiated unexpected cipher {session_cipher}; expected {selected_cipher}"
                        )
                    check_tofu(args.tofu_file, tofu_label, server_pub, allow_regen=args.regen_key)
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
                    rows, cols = get_winsize()
                    send(TYPE_HELLO, make_auth_payload(password, "file" if transfer_mode else "shell", term_name, rows, cols))
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
                if transfer_mode:
                    threading.Thread(target=transfer_file_loop, daemon=True).start()
                else:
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
            if pkt.pkt_type == TYPE_FILE_OK:
                transfer_ok = True
                transfer_done.set()
                running = False
                break
            if pkt.pkt_type == TYPE_FILE_PROGRESS:
                if len(pkt.payload) >= 8:
                    with transfer_stats_lock:
                        transfer_confirmed_bytes = int.from_bytes(pkt.payload[:8], "big")
                continue
            if pkt.pkt_type == TYPE_FILE_FAIL:
                print(f"[USSH-CLIENT] file transfer failed: {pkt.payload.decode('utf-8', 'replace')}", file=sys.stderr)
                transfer_done.set()
                running = False
                break
            if pkt.pkt_type == TYPE_EXIT:
                if tty_raw and old is not None:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
                    tty_raw = False
                running = False
                break
            if pkt.pkt_type == TYPE_CLOSE:
                if tty_raw and old is not None:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
                    tty_raw = False
                running = False
                break
        send(TYPE_CLOSE, b"")
        if transfer_mode and transfer_done.is_set() and transfer_ok:
            with transfer_stats_lock:
                sent = transfer_confirmed_bytes if transfer_confirmed_bytes > 0 else transfer_sent_bytes
                started = transfer_started_at
            elapsed = max(0.001, time.time() - started) if started > 0.0 else 0.001
            rate = sent / elapsed
            line = fit_progress_line(
                f"{human_bytes(sent)} / {human_bytes(transfer_size)}, {human_bytes(rate)}/s, ETA 0s, {transfer_name}"
            )
            if progress_is_tty:
                padded = "\r" + line
                if len(line) < progress_last_len:
                    padded += " " * (progress_last_len - len(line))
                sys.stdout.write(padded + "\n")
            else:
                sys.stdout.write(line + "\n")
            sys.stdout.flush()
    except KeyboardInterrupt:
        send(TYPE_CLOSE, b"")
    except SystemExit as exc:
        print(f"\n[USSH-CLIENT] {exc}", file=sys.stderr)
    finally:
        if tty_raw and old is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        running = False
        sender.stop()


if __name__ == "__main__":
    main()
