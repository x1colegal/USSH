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


def _kdf(psk: str) -> bytes:
    return hashlib.sha256(psk.encode("utf-8")).digest()


class AEADDatagramSocket:
    def __init__(self, sock: socket.socket, psk: str, cipher_name: str = "chacha20"):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

        self.sock = sock
        base_key = _kdf(psk)
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

    def bind(self, addr: Tuple[str, int]):
        self.sock.bind(addr)

    def sendto(self, data: bytes, addr: Tuple[str, int]):
        nonce = os.urandom(12)
        ct = self.aead.encrypt(nonce, data, None)
        pkt = MAGIC + bytes([self.cipher_id]) + nonce + ct
        return self.sock.sendto(pkt, addr)

    def recvfrom(self, bufsize: int):
        while True:
            raw, addr = self.sock.recvfrom(max(bufsize, 65535))
            if len(raw) < 4 + 1 + 12 + 16:
                continue
            if raw[:4] != MAGIC:
                continue
            cid = raw[4]
            aead = self._aead_by_id.get(cid)
            if aead is None:
                continue
            nonce = raw[5:17]
            ct = raw[17:]
            try:
                pt = aead.decrypt(nonce, ct, None)
            except Exception:
                continue
            self.cipher_id = cid
            self.aead = aead
            return pt, addr

    def setsockopt(self, *args, **kwargs):
        return self.sock.setsockopt(*args, **kwargs)

    def getsockname(self):
        return self.sock.getsockname()
