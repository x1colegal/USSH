import hashlib
import os
import socket
from typing import Tuple

MAGIC = b"USS1"
CIPHER_AES128GCM = 1
CIPHER_AES256GCM = 2
CIPHER_CHACHA20 = 3


def normalize_cipher_name(name: str) -> str:
    c = (name or "").lower().strip()
    if c in ("aes-128-gcm", "aes128", "aes128gcm"):
        return "aes-128-gcm"
    if c in ("aes", "aesgcm", "aes-gcm", "aes-256-gcm", "aes256", "aes256gcm"):
        return "aes-256-gcm"
    return "chacha20"


def _kdf(psk: str | bytes) -> bytes:
    if isinstance(psk, bytes):
        return hashlib.sha256(psk).digest()
    return hashlib.sha256(psk.encode("utf-8")).digest()


class AEADDatagramSocket:
    def __init__(self, sock: socket.socket, psk: str | bytes | None = None, cipher_name: str = "chacha20"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        self.sock = sock
        base_key = os.urandom(32) if psk is None else _kdf(psk)
        c = normalize_cipher_name(cipher_name)
        self.cipher_name = c
        if c == "aes-128-gcm":
            self.cipher_id = CIPHER_AES128GCM
            self.aead = AESGCM(base_key[:16])
        elif c == "aes-256-gcm":
            self.cipher_id = CIPHER_AES256GCM
            self.aead = AESGCM(base_key)
        else:
            self.cipher_id = CIPHER_CHACHA20
            self.aead = ChaCha20Poly1305(base_key)

        self._aead_by_id = {
            CIPHER_AES128GCM: AESGCM(base_key[:16]),
            CIPHER_AES256GCM: AESGCM(base_key),
            CIPHER_CHACHA20: ChaCha20Poly1305(base_key),
        }
        self._cipher_id_by_name = {
            "aes-128-gcm": CIPHER_AES128GCM,
            "aes-256-gcm": CIPHER_AES256GCM,
            "chacha20": CIPHER_CHACHA20,
        }
        self._peer_cipher: dict[Tuple[str, int], int] = {}
        self._peer_aeads: dict[Tuple[str, int], dict[int, object]] = {}

    def bind(self, addr: Tuple[str, int]):
        self.sock.bind(addr)

    def sendto(self, data: bytes, addr: Tuple[str, int]):
        cid = self._peer_cipher.get(addr, self.cipher_id)
        aead = self._peer_aeads.get(addr, self._aead_by_id)[cid]
        nonce = os.urandom(12)
        ct = aead.encrypt(nonce, data, None)
        pkt = MAGIC + bytes([cid]) + nonce + ct
        return self.sock.sendto(pkt, addr)

    def send_plain(self, data: bytes, addr: Tuple[str, int]):
        return self.sock.sendto(data, addr)

    def set_peer_cipher(self, addr: Tuple[str, int], cipher_name: str) -> str:
        c = normalize_cipher_name(cipher_name)
        self._peer_cipher[addr] = self._cipher_id_by_name[c]
        return c

    def set_peer_psk(self, addr: Tuple[str, int], psk: str | bytes, cipher_name: str | None = None) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        key = _kdf(psk)
        self._peer_aeads[addr] = {
            CIPHER_AES128GCM: AESGCM(key[:16]),
            CIPHER_AES256GCM: AESGCM(key),
            CIPHER_CHACHA20: ChaCha20Poly1305(key),
        }
        if cipher_name is not None:
            return self.set_peer_cipher(addr, cipher_name)
        return normalize_cipher_name(self.cipher_name)

    def clear_peer(self, addr: Tuple[str, int]) -> None:
        self._peer_cipher.pop(addr, None)
        self._peer_aeads.pop(addr, None)

    def recvfrom(self, bufsize: int):
        while True:
            raw, addr = self.sock.recvfrom(max(bufsize, 65535))
            if raw[:4] == b"UST1" and addr not in self._peer_aeads:
                return raw, addr
            if len(raw) < 4 + 1 + 12 + 16:
                continue
            if raw[:4] != MAGIC:
                continue
            cid = raw[4]
            nonce = raw[5:17]
            ct = raw[17:]
            peer_aeads = self._peer_aeads.get(addr)
            aead_sets = [peer_aeads] if peer_aeads is not None else [self._aead_by_id]
            for aead_by_id in aead_sets:
                aead = aead_by_id.get(cid)
                if aead is None:
                    continue
                try:
                    return aead.decrypt(nonce, ct, None), addr
                except Exception:
                    pass

    def setsockopt(self, *args, **kwargs):
        return self.sock.setsockopt(*args, **kwargs)

    def getsockname(self):
        return self.sock.getsockname()
