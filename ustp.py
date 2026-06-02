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
    def __init__(self, sock: socket.socket, peer: Tuple[str, int], window: int = 512, rto: float = 0.25, loss_percent: int = 0, congestion_control: bool = False):
        self.sock = sock
        self.peer = peer
        self.window = window
        self.rto = rto
        self.loss_percent = max(0, min(100, loss_percent))
        self.congestion_control = congestion_control

        self.next_seq = 1
        self.next_stream_pos = 0
        self.pending: Deque[Tuple[bytes, Optional[int]]] = deque()
        self.sent: Dict[int, SentItem] = {}
        self.retx_queue: Deque[int] = deque()
        self.retx_set: Set[int] = set()

        self.lock = threading.Lock()
        self.running = False
        self.cwnd = 4.0
        self.ssthresh = max(8.0, float(window) / 2.0)
        self.stats_acks = 0
        self.stats_rto = 0
        self.nack_ts: Dict[int, float] = {}

    def start(self) -> None:
        self.running = True
        threading.Thread(target=self._retx_loop, daemon=True).start()
        print("[USTP-SENDER] started")

    def stop(self) -> None:
        self.running = False

    def reset_session(self) -> None:
        with self.lock:
            self.next_seq = 1
            self.next_stream_pos = 0
            self.pending.clear()
            self.sent.clear()
            self.retx_queue.clear()
            self.retx_set.clear()
            self.cwnd = 4.0
            self.ssthresh = max(8.0, float(self.window) / 2.0)
        print("[USTP-SENDER] session reset")

    def queue_payload(self, payload: bytes, stream_pos: Optional[int] = None) -> None:
        if not payload:
            return
        with self.lock:
            self.pending.append((payload, stream_pos))
        self.flush()

    def _send_raw(self, raw: bytes) -> None:
        if self.loss_percent > 0:
            if __import__("random").randint(1, 100) <= self.loss_percent:
                return
        self.sock.sendto(raw, self.peer)

    def flush(self) -> None:
        burst = 0
        while burst < 256:
            with self.lock:
                in_flight = len(self.sent)
                eff_window = self.window
                if self.congestion_control:
                    eff_window = max(1, min(self.window, int(self.cwnd)))
                if in_flight >= eff_window:
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

    def on_control(self, pkt: USTPPacket) -> None:
        if pkt.pkt_type == TYPE_ACK:
            with self.lock:
                if pkt.seq in self.sent:
                    del self.sent[pkt.seq]
                    self.stats_acks += 1
                    if self.congestion_control:
                        if self.cwnd < self.ssthresh:
                            self.cwnd += 1.0
                        else:
                            self.cwnd += 1.0 / max(1.0, self.cwnd)
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
            self.flush()

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
                if self.congestion_control:
                    with self.lock:
                        self.ssthresh = max(2.0, self.cwnd / 2.0)
                        self.cwnd = max(1.0, self.ssthresh)
                with self.lock:
                    self.stats_rto += len(timed_out)
                print(f"[USTP-SENDER] RTO queued {len(timed_out)}")
                self.flush()
            time.sleep(0.03)

    def get_stats(self) -> Dict[str, float]:
        with self.lock:
            return {
                "acks": float(self.stats_acks),
                "rto": float(self.stats_rto),
                "inflight": float(len(self.sent)),
                "cwnd": float(self.cwnd),
            }


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
            chunk = self.buffer_by_pos[self.next_pos]
            self.contiguous_max_pos = self.next_pos + len(chunk) - 1
            self.next_pos += len(chunk)

        return out

    def maybe_nack(self) -> None:
        # gap detection by seq continuity around observed set
        if not self.received_seq:
            return
        # Warm-up guard: avoid early false-positive NACK storms.
        if self.data_count < 12:
            return
        now = time.time()
        # Do not spam NACK when stream is idle/restarting.
        if self.last_data_ts and (now - self.last_data_ts) > 1.0:
            self.received_seq.clear()
            self.nack_ts.clear()
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
            sent += 1
            if sent >= 6:
                break
        if sent:
            print(f"[USTP-RECV] NACK sent={sent}")


def parse_packet(raw: bytes) -> Optional[USTPPacket]:
    try:
        return USTPPacket.from_bytes(raw)
    except Exception:
        return None
