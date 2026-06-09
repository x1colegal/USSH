import socket
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Set, Tuple

from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, USTPPacket, mkp


@dataclass
class SentItem:
    pkt: USTPPacket
    raw: bytes
    last_sent: float


class USTPSender:
    def __init__(
        self,
        sock: socket.socket,
        peer: Tuple[str, int],
        window: int = 512,
        rto: float = 0.25,
        loss_percent: int = 0,
        quiet: bool = False,
        max_burst: int = 256,
        pump_interval: float = 0.002,
    ):
        self.sock = sock
        self.peer = peer
        self.window = window
        self.rto = rto
        self.loss_percent = max(0, min(100, loss_percent))
        self.quiet = quiet
        self.max_burst = max(32, max_burst)
        self.pump_interval = max(0.0005, pump_interval)

        self.next_seq = 1
        self.next_stream_pos = 0
        self.pending: Deque[Tuple[bytes, Optional[int]]] = deque()
        self.pending_bytes = 0
        self.sent: Dict[int, SentItem] = {}
        self.retx_queue: Deque[int] = deque()
        self.retx_set: Set[int] = set()

        self.lock = threading.Lock()
        self.running = False
        self.wakeup = threading.Event()
        self.stats_acks = 0
        self.stats_rto = 0
        self.nack_ts: Dict[int, float] = {}

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._pump_loop, daemon=True).start()
        threading.Thread(target=self._retx_loop, daemon=True).start()
        if not self.quiet:
            print("[USTP-SENDER] started")

    def stop(self) -> None:
        self.running = False
        self.wakeup.set()

    def reset_session(self) -> None:
        with self.lock:
            self.next_seq = 1
            self.next_stream_pos = 0
            self.pending.clear()
            self.pending_bytes = 0
            self.sent.clear()
            self.retx_queue.clear()
            self.retx_set.clear()
        if not self.quiet:
            print("[USTP-SENDER] session reset")

    def queue_payload(self, payload: bytes, stream_pos: Optional[int] = None) -> None:
        if not payload:
            return
        with self.lock:
            self.pending.append((payload, stream_pos))
            self.pending_bytes += len(payload)
        self.wakeup.set()

    def _send_raw(self, raw: bytes) -> None:
        if self.loss_percent > 0:
            if __import__("random").randint(1, 100) <= self.loss_percent:
                return
        try:
            self.sock.sendto(raw, self.peer)
        except OSError as exc:
            if not self.quiet:
                print(f"[USTP-SENDER] send failed peer={self.peer[0]}:{self.peer[1]} error={exc}")
        except Exception as exc:
            if not self.quiet:
                print(f"[USTP-SENDER] unexpected send error peer={self.peer[0]}:{self.peer[1]} error={exc}")

    def flush(self) -> None:
        burst = 0
        while burst < self.max_burst:
            with self.lock:
                in_flight = len(self.sent)
                if in_flight >= self.window:
                    return

                # retransmit priority (can send 5,6,4,7,8 physically)
                seq = None
                if self.retx_queue:
                    seq = self.retx_queue.popleft()
                    self.retx_set.discard(seq)
                    it = self.sent.get(seq)
                    if not it:
                        continue
                    raw = it.raw
                    it.last_sent = time.time()
                elif self.pending:
                    payload, ext_stream_pos = self.pending.popleft()
                    self.pending_bytes -= len(payload)
                    seq = self.next_seq
                    self.next_seq += 1
                    if ext_stream_pos is None:
                        sp = self.next_stream_pos
                        self.next_stream_pos += len(payload)
                    else:
                        sp = ext_stream_pos
                    pkt = mkp(TYPE_DATA, seq=seq, stream_pos=sp, payload=payload)
                    raw = pkt.to_bytes()
                    self.sent[seq] = SentItem(pkt=pkt, raw=raw, last_sent=time.time())
                else:
                    return

            self._send_raw(raw)
            burst += 1

    def _pump_loop(self) -> None:
        while self.running:
            self.wakeup.wait(self.pump_interval)
            self.wakeup.clear()
            self.flush()

    def on_control(self, pkt: USTPPacket) -> None:
        if pkt.pkt_type == TYPE_ACK:
            removed = False
            with self.lock:
                if pkt.seq in self.sent:
                    del self.sent[pkt.seq]
                    removed = True
                    self.stats_acks += 1
            if removed:
                self.wakeup.set()
            return

        if pkt.pkt_type == TYPE_RETRANSMIT_REQUEST:
            missing = pkt.seq
            with self.lock:
                now = time.time()
                last = self.nack_ts.get(missing, 0.0)
                if now - last < 0.2:
                    return
                self.nack_ts[missing] = now
                if missing in self.sent and missing not in self.retx_set:
                    self.retx_set.add(missing)
                    self.retx_queue.append(missing)
                    if not self.quiet:
                        print(f"[USTP-SENDER] peer requested retransmit of seq={missing}")
            self.wakeup.set()

    def _retx_loop(self) -> None:
        while self.running:
            now = time.time()
            timed_out = []
            with self.lock:
                for seq, it in self.sent.items():
                    if now - it.last_sent >= self.rto and seq not in self.retx_set:
                        timed_out.append(seq)
                for seq in timed_out:
                    self.retx_set.add(seq)
                    self.retx_queue.append(seq)
            if timed_out:
                with self.lock:
                    self.stats_rto += len(timed_out)
                if not self.quiet:
                    print(f"[USTP-SENDER] RTO queued {len(timed_out)}")
                self.wakeup.set()
            time.sleep(0.03)

    def get_stats(self) -> Dict[str, float]:
        with self.lock:
            return {
                "acks": float(self.stats_acks),
                "rto": float(self.stats_rto),
                "inflight": float(len(self.sent)),
                "pending_packets": float(len(self.pending)),
                "pending_bytes": float(self.pending_bytes),
            }

    def get_backlog(self) -> Tuple[int, int, int, int]:
        with self.lock:
            return len(self.pending), self.pending_bytes, len(self.sent), len(self.retx_queue)

    def wait_idle(self, timeout: float = 1.5) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if not self.pending and not self.sent and not self.retx_queue:
                    return True
            self.wakeup.set()
            time.sleep(0.02)
        with self.lock:
            return not self.pending and not self.sent and not self.retx_queue


class USTPReceiver:
    def __init__(self, sock: socket.socket, peer: Tuple[str, int]):
        self.sock = sock
        self.peer = peer

        self.buffer_by_pos: Dict[int, bytes] = {}
        self.seq_to_pos: Dict[int, int] = {}
        self.next_pos = 0
        self.contiguous_max_pos = -1

        self.received_seq: Set[int] = set()
        self.nack_ts: Dict[int, float] = {}
        self.last_data_ts = 0.0
        self.data_count = 0
        self.last_max_seq = 0
        self.idle_clear_after = 8.0
        self.cleanup_every = 128
        self.seq_history_limit = 4096
        self.pos_history_limit = MAX_PAYLOAD * 4096

    def _trim_state(self) -> None:
        if len(self.received_seq) > self.seq_history_limit:
            min_seq = max(0, self.last_max_seq - self.seq_history_limit)
            stale_seq = [seq for seq in self.received_seq if seq < min_seq]
            for seq in stale_seq:
                self.received_seq.discard(seq)
                self.seq_to_pos.pop(seq, None)
                self.nack_ts.pop(seq, None)

        stale_pos_cutoff = max(0, self.next_pos - self.pos_history_limit)
        if self.buffer_by_pos:
            stale_pos = [pos for pos in self.buffer_by_pos if pos < stale_pos_cutoff]
            for pos in stale_pos:
                self.buffer_by_pos.pop(pos, None)

    def handle_data(self, pkt: USTPPacket) -> bytes:
        seq = pkt.seq
        pos = pkt.stream_pos

        # ACK every unique seq quickly
        if seq not in self.received_seq:
            self.received_seq.add(seq)
            ack = mkp(TYPE_ACK, seq=seq)
            self.sock.sendto(ack.to_bytes(), self.peer)

        if seq in self.seq_to_pos:
            return b""

        self.seq_to_pos[seq] = pos
        self.buffer_by_pos[pos] = pkt.payload
        self.last_data_ts = time.time()
        self.data_count += 1
        if seq > self.last_max_seq:
            self.last_max_seq = seq

        # USTP design: deliver immediately (unordered live), never block waiting for gaps.
        # The application must use stream_pos metadata to restore logical order if needed.
        out = pkt.payload

        # Track contiguous range growth for debugging/reorder visibility.
        while self.next_pos in self.buffer_by_pos:
            chunk = self.buffer_by_pos.pop(self.next_pos)
            self.contiguous_max_pos = self.next_pos + len(chunk) - 1
            self.next_pos += len(chunk)

        if self.data_count % self.cleanup_every == 0:
            self._trim_state()

        return out

    def maybe_nack(self) -> None:
        # gap detection by seq continuity around observed set
        if not self.received_seq:
            return
        # Warm-up guard: avoid early false-positive NACK storms.
        if self.data_count < 12:
            return
        now = time.time()
        # In USSH, bursts like "ls" can finish before a lost packet is recovered.
        # Keep retrying for longer instead of clearing state after just 1 second of silence.
        if self.last_data_ts and (now - self.last_data_ts) > self.idle_clear_after:
            self.received_seq.clear()
            self.nack_ts.clear()
            self.seq_to_pos.clear()
            self.buffer_by_pos.clear()
            return
        mn = min(self.received_seq)
        mx = max(self.received_seq)
        # Only request near-head losses; old holes become stale quickly in striped mode.
        mn = max(mn, mx - 96)
        # Limit scan window to recent sequence space to avoid storms.
        if mx - mn > 512:
            mn = mx - 512
        sent = 0
        for s in range(mn, mx):
            if s in self.received_seq:
                continue
            last = self.nack_ts.get(s, 0.0)
            if now - last < 0.5:
                continue
            self.nack_ts[s] = now
            nack = mkp(TYPE_RETRANSMIT_REQUEST, seq=s)
            self.sock.sendto(nack.to_bytes(), self.peer)
            if not getattr(self, "quiet_recv", False):
                print(f"[USTP-RECV] missing seq={s}, requesting retransmit")
            sent += 1
            if sent >= 6:
                break


def parse_packet(raw: bytes) -> Optional[USTPPacket]:
    try:
        return USTPPacket.from_bytes(raw)
    except Exception:
        return None
