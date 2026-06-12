import base64
import struct
from dataclasses import dataclass

CONTROL_MAGIC = b"UST1"
DATA_MAGIC = b"UPAK"

TYPE_DATA = 1
TYPE_ACK = 2
TYPE_RETRANSMIT_REQUEST = 3
TYPE_HELLO = 4
TYPE_CLOSE = 5

MAX_PAYLOAD = 1200

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

        payload_b64 = base64.b64encode(self.payload).decode("ascii")
        return (
            CONTROL_MAGIC
            + b"|"
            + str(self.pkt_type).encode("ascii")
            + b"|"
            + str(self.flags).encode("ascii")
            + b"|"
            + str(self.seq).encode("ascii")
            + b"|"
            + str(self.stream_pos).encode("ascii")
            + b"|"
            + payload_b64.encode("ascii")
            + b"\n"
        )

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

        if not raw.startswith(CONTROL_MAGIC + b"|"):
            raise ValueError("bad control magic")
        line = raw.rstrip(b"\r\n")
        parts = line.split(b"|", 5)
        if len(parts) != 6:
            raise ValueError("invalid control packet")
        _, pkt_type_b, flags_b, seq_b, stream_pos_b, payload_b64 = parts
        try:
            payload = base64.b64decode(payload_b64, validate=True) if payload_b64 else b""
        except Exception as exc:
            raise ValueError("invalid control payload") from exc
        return USTPPacket(
            pkt_type=int(pkt_type_b.decode("ascii")),
            flags=int(flags_b.decode("ascii")),
            seq=int(seq_b.decode("ascii")),
            stream_pos=int(stream_pos_b.decode("ascii")),
            payload=payload,
        )


def mkp(pkt_type: int, seq: int = 0, stream_pos: int = 0, payload: bytes = b"", flags: int = 0) -> USTPPacket:
    return USTPPacket(pkt_type=pkt_type, flags=flags, seq=seq, stream_pos=stream_pos, payload=payload)
