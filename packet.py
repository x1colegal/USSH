import base64
import struct
from dataclasses import dataclass

DATA_MAGIC = b"UPAK"

TYPE_DATA = 1
TYPE_ACK = 2
TYPE_RETRANSMIT_REQUEST = 3
TYPE_HELLO = 4
TYPE_CLOSE = 5

MAX_PAYLOAD = 1200

CONTROL_PREFIXES = {
    TYPE_ACK: b"ACK: ",
    TYPE_RETRANSMIT_REQUEST: b"NACK: ",
    TYPE_HELLO: b"HELLO: ",
    TYPE_CLOSE: b"CLOSE:",
}

# magic(4), type(1), flags(1), seq(4), stream_pos(8), length(2)
DATA_HEADER_FMT = "!4sBBIQH"
DATA_HEADER_SIZE = struct.calcsize(DATA_HEADER_FMT)


@dataclass
class USTPPacket:
    pkt_type: int
    flags: int
    seq: int
    stream_pos: int
    payload: bytes

    def to_bytes(self) -> bytes:
        if self.pkt_type == TYPE_DATA:
            if len(self.payload) > MAX_PAYLOAD:
                raise ValueError(f"payload too large {len(self.payload)} > {MAX_PAYLOAD}")
            header = struct.pack(
                DATA_HEADER_FMT,
                DATA_MAGIC,
                self.pkt_type,
                self.flags,
                self.seq,
                self.stream_pos,
                len(self.payload),
            )
            return header + self.payload

        if self.pkt_type == TYPE_ACK:
            seqs = [str(self.seq).encode("ascii")]
            if self.payload:
                extra = len(self.payload) // 4
                if extra:
                    seqs.extend(str(v).encode("ascii") for v in struct.unpack(f"!{extra}I", self.payload[: extra * 4]))
            return CONTROL_PREFIXES[TYPE_ACK] + b" ".join(seqs) + b"\n"

        if self.pkt_type == TYPE_RETRANSMIT_REQUEST:
            seqs = [str(self.seq).encode("ascii")]
            if self.payload:
                extra = len(self.payload) // 4
                if extra:
                    seqs.extend(str(v).encode("ascii") for v in struct.unpack(f"!{extra}I", self.payload[: extra * 4]))
            return CONTROL_PREFIXES[TYPE_RETRANSMIT_REQUEST] + b" ".join(seqs) + b"\n"

        if self.pkt_type == TYPE_HELLO:
            payload_b64 = base64.b64encode(self.payload)
            return CONTROL_PREFIXES[TYPE_HELLO] + payload_b64 + b"\n"

        if self.pkt_type == TYPE_CLOSE:
            return CONTROL_PREFIXES[TYPE_CLOSE] + b"\n"

        raise ValueError(f"unsupported control packet type {self.pkt_type}")

    @staticmethod
    def from_bytes(raw: bytes) -> "USTPPacket":
        if raw.startswith(DATA_MAGIC):
            if len(raw) < DATA_HEADER_SIZE:
                raise ValueError("data packet too short")
            magic, pkt_type, flags, seq, stream_pos, length = struct.unpack(DATA_HEADER_FMT, raw[:DATA_HEADER_SIZE])
            if magic != DATA_MAGIC:
                raise ValueError("bad data magic")
            payload = raw[DATA_HEADER_SIZE:DATA_HEADER_SIZE + length]
            if len(payload) != length:
                raise ValueError("data payload length mismatch")
            return USTPPacket(pkt_type, flags, seq, stream_pos, payload)

        line = raw.rstrip(b"\r\n")
        if line.startswith(CONTROL_PREFIXES[TYPE_ACK]):
            body = line[len(CONTROL_PREFIXES[TYPE_ACK]):].strip()
            if not body:
                raise ValueError("empty ACK")
            parts = body.split()
            seqs = [int(p.decode("ascii")) for p in parts]
            payload = b""
            if len(seqs) > 1:
                payload = struct.pack(f"!{len(seqs) - 1}I", *seqs[1:])
            return USTPPacket(TYPE_ACK, 0, seqs[0], 0, payload)

        if line.startswith(CONTROL_PREFIXES[TYPE_RETRANSMIT_REQUEST]):
            body = line[len(CONTROL_PREFIXES[TYPE_RETRANSMIT_REQUEST]):].strip()
            if not body:
                raise ValueError("empty NACK")
            seqs = [int(p.decode("ascii")) for p in body.split()]
            payload = b""
            if len(seqs) > 1:
                payload = struct.pack(f"!{len(seqs) - 1}I", *seqs[1:])
            return USTPPacket(TYPE_RETRANSMIT_REQUEST, 0, seqs[0], 0, payload)

        if line.startswith(CONTROL_PREFIXES[TYPE_HELLO]):
            body = line[len(CONTROL_PREFIXES[TYPE_HELLO]):].strip()
            try:
                payload = base64.b64decode(body, validate=True) if body else b""
            except Exception as exc:
                raise ValueError("invalid HELLO payload") from exc
            return USTPPacket(TYPE_HELLO, 0, 0, 0, payload)

        if line == CONTROL_PREFIXES[TYPE_CLOSE]:
            return USTPPacket(TYPE_CLOSE, 0, 0, 0, b"")

        raise ValueError("unknown control packet")


def mkp(pkt_type: int, seq: int = 0, stream_pos: int = 0, payload: bytes = b"", flags: int = 0) -> USTPPacket:
    return USTPPacket(pkt_type=pkt_type, flags=flags, seq=seq, stream_pos=stream_pos, payload=payload)
