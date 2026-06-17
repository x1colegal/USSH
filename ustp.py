import math
import socket
import threading
import time
import struct
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Set, Tuple

from packet import MAX_PAYLOAD, TYPE_ACK, TYPE_CLOSE, TYPE_DATA, TYPE_HELLO, TYPE_RETRANSMIT_REQUEST, USTPPacket, mkp


ACK_BATCH_MAX = 128
ACK_FLUSH_INTERVAL = 0.012


@dataclass
class SentItem:
    pkt: USTPPacket
    raw: bytes
    last_sent: float
    first_sent: float
    retransmitted: bool = False


class USTPSender:
    def __init__(
        self,
        sock: socket.socket,
        peer: Tuple[str, int],
        window: int = 512,
        rto: float = 0.25,
        loss_percent: int = 0,
        quiet: bool = False,
        max_burst: int = 768,
        pump_interval: float = 0.0008,
        congestion_control: bool = False,
    ):
        self.sock = sock
        self.peer = peer
        self.window = window
        self.rto = rto
        self.loss_percent = max(0, min(100, loss_percent))
        self.quiet = quiet
        self.max_burst = max(32, max_burst)
        self.pump_interval = max(0.0005, pump_interval)
        self.congestion_control = congestion_control
        # USTPS Congestion starts at the normal transport speed and only backs off
        # after real congestion signals show up.
        self.cc_window = float(self.window)
        self.cc_burst = float(self.max_burst)
        self.cc_min_srtt: float | None = None
        self.cc_stable_window_floor = float(max(32, min(self.window, int(self.window * 0.6))))
        self.cc_stable_burst_floor = float(max(32, min(self.max_burst, int(self.max_burst * 0.6))))
        self.cc_last_sample_ts = time.time()
        self.cc_last_acks = 0
        self.cc_last_rto = 0
        self.cc_last_nack = 0
        self.cc_consecutive_bad = 0
        self.cc_consecutive_good = 0
        self.stats_nack = 0

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
        self.srtt: float | None = None
        self.rttvar: float | None = None

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._pump_loop, daemon=True).start()
        threading.Thread(target=self._retx_loop, daemon=True).start()
        if self.congestion_control:
            threading.Thread(target=self._cc_loop, daemon=True).start()
        if not self.quiet:
            print(f"[USTP-SENDER] started cc={'on' if self.congestion_control else 'off'}")

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

    def _send_control(self, raw: bytes) -> None:
        try:
            sender = getattr(self.sock, "send_plain", None)
            if sender is not None:
                sender(raw, self.peer)
            else:
                self.sock.sendto(raw, self.peer)
        except OSError as exc:
            if not self.quiet:
                print(f"[USTP-SENDER] control send failed peer={self.peer[0]}:{self.peer[1]} error={exc}")
        except Exception as exc:
            if not self.quiet:
                print(f"[USTP-SENDER] unexpected control send error peer={self.peer[0]}:{self.peer[1]} error={exc}")

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
        while True:
            with self.lock:
                burst_limit = self._effective_burst_locked()
                if burst >= burst_limit:
                    return
                in_flight = len(self.sent)
                if in_flight >= self._effective_window_locked():
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
                    now = time.time()
                    it.last_sent = now
                    it.retransmitted = True
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
                    now = time.time()
                    self.sent[seq] = SentItem(pkt=pkt, raw=raw, last_sent=now, first_sent=now)
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
            acked = [pkt.seq]
            if pkt.payload:
                extra = len(pkt.payload) // 4
                if extra:
                    acked.extend(struct.unpack(f"!{extra}I", pkt.payload[: extra * 4]))
            with self.lock:
                for seq in acked:
                    item = self.sent.pop(seq, None)
                    if item is not None:
                        if not item.retransmitted:
                            sample = time.time() - item.first_sent
                            self._update_rto(sample)
                        removed = True
                        self.stats_acks += 1
                if self.srtt is not None:
                    if self.cc_min_srtt is None:
                        self.cc_min_srtt = self.srtt
                    else:
                        self.cc_min_srtt = min(self.cc_min_srtt, self.srtt)
            if removed:
                self.wakeup.set()
            return

        if pkt.pkt_type == TYPE_RETRANSMIT_REQUEST:
            missing_items = [pkt.seq]
            if pkt.payload:
                extra = len(pkt.payload) // 4
                if extra:
                    missing_items.extend(struct.unpack(f"!{extra}I", pkt.payload[: extra * 4]))
            with self.lock:
                now = time.time()
                queued = 0
                for missing in missing_items:
                    last = self.nack_ts.get(missing, 0.0)
                    if now - last < 0.2:
                        continue
                    self.nack_ts[missing] = now
                    if missing in self.sent and missing not in self.retx_set:
                        self.retx_set.add(missing)
                        self.retx_queue.append(missing)
                        queued += 1
                if queued:
                    self.stats_nack += queued
                if queued and not self.quiet:
                    print(f"[USTP-SENDER] peer requested retransmit count={queued}")
            self.wakeup.set()

    def _update_rto(self, sample: float) -> None:
        sample = max(0.005, min(10.0, sample))
        if self.srtt is None or self.rttvar is None:
            self.srtt = sample
            self.rttvar = sample / 2.0
        else:
            alpha = 1.0 / 8.0
            beta = 1.0 / 4.0
            self.rttvar = (1.0 - beta) * self.rttvar + beta * abs(self.srtt - sample)
            self.srtt = (1.0 - alpha) * self.srtt + alpha * sample
        self.rto = max(0.05, min(3.0, self.srtt + 4.0 * self.rttvar))


    def _effective_window_locked(self) -> int:
        if not self.congestion_control:
            return self.window
        return max(8, min(self.window, int(self.cc_window)))

    def _effective_burst_locked(self) -> int:
        if not self.congestion_control:
            return self.max_burst
        return max(8, min(self.max_burst, int(self.cc_burst)))

    def _cc_backoff_locked(self) -> None:
        floor_window = max(32.0, self.cc_stable_window_floor)
        floor_burst = max(32.0, self.cc_stable_burst_floor)
        self.cc_window = max(floor_window, self.cc_window * 0.85)
        self.cc_burst = max(floor_burst, self.cc_burst * 0.88)

    def _cc_grow_locked(self) -> None:
        step = max(1.0, self.window * 0.03)
        self.cc_window = min(float(self.window), self.cc_window + step)
        if self.cc_burst < self.max_burst:
            self.cc_burst = min(float(self.max_burst), self.cc_burst + max(4.0, self.max_burst * 0.04))
        if self.cc_window >= self.window * 0.9:
            self.cc_stable_window_floor = min(float(self.window), max(self.cc_stable_window_floor, self.cc_window * 0.75))
        if self.cc_burst >= self.max_burst * 0.9:
            self.cc_stable_burst_floor = min(float(self.max_burst), max(self.cc_stable_burst_floor, self.cc_burst * 0.75))

    def _cc_loop(self) -> None:
        while self.running:
            time.sleep(0.25)
            with self.lock:
                if not self.congestion_control:
                    continue
                now = time.time()
                ack_delta = self.stats_acks - self.cc_last_acks
                rto_delta = self.stats_rto - self.cc_last_rto
                nack_delta = self.stats_nack - self.cc_last_nack
                srtt = self.srtt or 0.0
                min_srtt = self.cc_min_srtt or srtt or 0.0
                inflight = len(self.sent)
                pending = len(self.pending)
                loss_events = rto_delta + nack_delta
                stable_rtt = (srtt <= 0.0 or min_srtt <= 0.0 or srtt <= min_srtt * 1.20)
                mild_rtt_pressure = srtt > 0.0 and min_srtt > 0.0 and srtt > min_srtt * 1.35
                hard_rtt_pressure = srtt > 0.0 and min_srtt > 0.0 and srtt > min_srtt * 1.60
                progress = ack_delta > 0

                bad_signal = hard_rtt_pressure or loss_events >= 3 or (loss_events >= 2 and mild_rtt_pressure)
                good_signal = progress and stable_rtt and loss_events == 0

                if bad_signal:
                    self.cc_consecutive_bad += 1
                    self.cc_consecutive_good = 0
                elif good_signal:
                    self.cc_consecutive_good += 1
                    self.cc_consecutive_bad = 0
                else:
                    self.cc_consecutive_bad = max(0, self.cc_consecutive_bad - 1)
                    self.cc_consecutive_good = max(0, self.cc_consecutive_good - 1)

                if self.cc_consecutive_bad >= 2:
                    self._cc_backoff_locked()
                    self.cc_consecutive_bad = 0
                elif self.cc_consecutive_good >= 2:
                    self._cc_grow_locked()
                    self.cc_consecutive_good = 0
                elif pending > 0 and inflight < self._effective_window_locked() and stable_rtt and loss_events == 0:
                    self._cc_grow_locked()
                self.cc_last_sample_ts = now
                self.cc_last_acks = self.stats_acks
                self.cc_last_rto = self.stats_rto
                self.cc_last_nack = self.stats_nack

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
                "nack": float(self.stats_nack),
                "rto_events": float(self.stats_rto),
                "inflight": float(len(self.sent)),
                "pending_packets": float(len(self.pending)),
                "pending_bytes": float(self.pending_bytes),
                "rto": float(self.rto),
                "srtt": float(self.srtt or 0.0),
                "cc_enabled": 1.0 if self.congestion_control else 0.0,
                "cc_window": float(self.cc_window),
                "cc_burst": float(self.cc_burst),
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
        self.pending_ack: list[int] = []
        self.pending_ack_set: Set[int] = set()
        self.last_ack_flush_ts = time.time()
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

        # ACK in small batches to reduce control overhead.
        if seq not in self.received_seq:
            self.received_seq.add(seq)
            if seq not in self.pending_ack_set:
                self.pending_ack.append(seq)
                self.pending_ack_set.add(seq)
            now = time.time()
            if len(self.pending_ack) >= ACK_BATCH_MAX or (now - self.last_ack_flush_ts) >= ACK_FLUSH_INTERVAL:
                self.flush_acks(now)

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

    def flush_acks(self, now: float | None = None) -> None:
        if not self.pending_ack:
            return
        if now is None:
            now = time.time()
        seqs = self.pending_ack[:ACK_BATCH_MAX]
        del self.pending_ack[: len(seqs)]
        for seq in seqs:
            self.pending_ack_set.discard(seq)
        head = seqs[0]
        payload = b""
        if len(seqs) > 1:
            payload = struct.pack(f"!{len(seqs) - 1}I", *seqs[1:])
        ack = mkp(TYPE_ACK, seq=head, payload=payload)
        sender = getattr(self.sock, "send_plain", None)
        if sender is not None:
            sender(ack.to_bytes(), self.peer)
        else:
            self.sock.sendto(ack.to_bytes(), self.peer)
        self.last_ack_flush_ts = now

    def maybe_nack(self) -> None:
        self.flush_acks()
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
        missing_batch = []
        for s in range(mn, mx):
            if s in self.received_seq:
                continue
            last = self.nack_ts.get(s, 0.0)
            if now - last < 0.5:
                continue
            self.nack_ts[s] = now
            if not getattr(self, "quiet_recv", False):
                print(f"[USTP-RECV] missing seq={s}, requesting retransmit")
            missing_batch.append(s)
            if len(missing_batch) >= ACK_BATCH_MAX:
                break
        if missing_batch:
            payload = b""
            if len(missing_batch) > 1:
                payload = struct.pack(f"!{len(missing_batch) - 1}I", *missing_batch[1:])
            nack = mkp(TYPE_RETRANSMIT_REQUEST, seq=missing_batch[0], payload=payload)
            sender = getattr(self.sock, "send_plain", None)
            if sender is not None:
                sender(nack.to_bytes(), self.peer)
            else:
                self.sock.sendto(nack.to_bytes(), self.peer)


def parse_packet(raw: bytes) -> Optional[USTPPacket]:
    try:
        return USTPPacket.from_bytes(raw)
    except Exception:
        return None
