"""Tarfile fileobject handler for encrypted files."""
import hashlib
import sys
from typing import IO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
def overwrite(line: str):
    sys.stdout.write(f"\r{line.encode('utf-8', 'replace').decode()}\033[K")


def _generate_iv(key: bytes, salt: bytes) -> bytes:
    """Generate an iv from data."""
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    return temp_iv[:16]

def password_to_key(password: str) -> bytes:
    """Generate a AES Key from password.  Copied form Home Assistant"""
    key: bytes = password.encode("utf-8")
    for _ in range(100):
        # Rehashing this 100 times doen't make sense to me, but its what HA does.
        key = hashlib.sha256(key).digest()
    return key[:16]


UPDATE_MB = 1024 * 1024 * 5  # 5MB

class DecryptedStream:
    """File-like object for decrypting a stream using HA's unique V2 encryption format."""

    def __init__(
        self,
        file: IO[bytes],
        password: str,
        expected_size: int,
        progress_text: str,
        bufsize: int = 10240,
    ) -> None:
        """Initialize encryption handler."""
        self._bufsize: int = bufsize
        self._file = file
        self._expected_size = expected_size
        self._position = 0
        self._progress_text = progress_text
        self._last_update = 0

        # First 16 bytes of the file are used to create the IV
        self._key = password_to_key(password)
        cbc_rand = self._file.read(16)

        # Create Cipher
        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(_generate_iv(self._key, cbc_rand)),
            backend=default_backend(),
        )
        self._decrypt = self._aes.decryptor()

    def read(self, size: int = 0) -> bytes:
        """Read data."""
        if size == 0:
            size = self._bufsize
        data = self._decrypt.update(self._file.read(size))
        self._position += len(data)

        # Only write to conole every few MB, otherwise it's too slow.
        if (last_update := self._position // UPDATE_MB) != self._last_update:
            self._last_update = last_update
            overwrite(f"{self._progress_text} {self._position/self._expected_size:.2%}")
        return data
