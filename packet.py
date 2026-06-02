import struct
from dataclasses import dataclass

MAGIC = b"UST1"

TYPE_DATA = 1
TYPE_ACK = 2
TYPE_RETRANSMIT_REQUEST = 3
TYPE_HELLO = 4
TYPE_CLOSE = 5

MAX_PAYLOAD = 1200

# magic(4), type(1), flags(1), seq(4), stream_pos(8), length(2)
HEADER_FMT = "!4sBBIQH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


@dataclass
class USTPPacket:
    pkt_type: int
    flags: int
    seq: int
    stream_pos: int
    payload: bytes

    def to_bytes(self) -> bytes:
        if len(self.payload) > MAX_PAYLOAD:
            raise ValueError(f"payload too large {len(self.payload)} > {MAX_PAYLOAD}")
        header = struct.pack(
            HEADER_FMT,
            MAGIC,
            self.pkt_type,
            self.flags,
            self.seq,
            self.stream_pos,
            len(self.payload),
        )
        return header + self.payload

    @staticmethod
    def from_bytes(raw: bytes) -> "USTPPacket":
        if len(raw) < HEADER_SIZE:
            raise ValueError("packet too short")
        magic, pkt_type, flags, seq, stream_pos, length = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
        if magic != MAGIC:
            raise ValueError("bad magic")
        payload = raw[HEADER_SIZE:HEADER_SIZE + length]
        if len(payload) != length:
            raise ValueError("payload length mismatch")
        return USTPPacket(pkt_type, flags, seq, stream_pos, payload)


def mkp(pkt_type: int, seq: int = 0, stream_pos: int = 0, payload: bytes = b"", flags: int = 0) -> USTPPacket:
    return USTPPacket(pkt_type=pkt_type, flags=flags, seq=seq, stream_pos=stream_pos, payload=payload)
