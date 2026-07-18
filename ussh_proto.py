import struct
from dataclasses import dataclass

MAGIC = b"USH1"

TYPE_AUTH = 1
TYPE_READY = 2
TYPE_STDIN = 3
TYPE_STDOUT = 4
TYPE_RESIZE = 5
TYPE_CLOSE = 6
TYPE_PING = 7
TYPE_PONG = 8
TYPE_EXIT = 9
TYPE_AUTH_FAIL = 10

HEADER_FMT = "!4sBBIH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)


@dataclass
class USHPacket:
    pkt_type: int
    flags: int
    seq: int
    payload: bytes

    def to_bytes(self) -> bytes:
        return struct.pack(HEADER_FMT, MAGIC, self.pkt_type, self.flags, self.seq, len(self.payload)) + self.payload

    @staticmethod
    def from_bytes(raw: bytes) -> "USHPacket":
        if len(raw) < HEADER_SIZE:
            raise ValueError("packet too short")
        magic, pkt_type, flags, seq, ln = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
        if magic != MAGIC:
            raise ValueError("bad magic")
        payload = raw[HEADER_SIZE:HEADER_SIZE + ln]
        if len(payload) != ln:
            raise ValueError("payload mismatch")
        return USHPacket(pkt_type=pkt_type, flags=flags, seq=seq, payload=payload)


def mkp(pkt_type: int, payload: bytes = b"", seq: int = 0, flags: int = 0) -> USHPacket:
    return USHPacket(pkt_type=pkt_type, flags=flags, seq=seq, payload=payload)
