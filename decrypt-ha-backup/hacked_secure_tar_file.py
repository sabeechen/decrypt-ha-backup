"""Tarfile fileobject handler for encrypted files."""
import hashlib
import logging
from pathlib import Path
import tarfile
from typing import IO, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)

DEFAULT_BUFSIZE = 10240

class HackedSecureTarFile:
    """Thsi is a hacked up verison of SecureTarFile that works around a bunch of windows specific issues the library has"""

    def __init__(
        self,
        name: Path,
        key: bytes,
        gzip: bool = True,
        bufsize: int = DEFAULT_BUFSIZE,
    ) -> None:
        """Initialize encryption handler."""
        self._file: Optional[IO[bytes]] = None
        self._name: Path = name
        self._bufsize: int = bufsize

        # Tarfile options
        self._tar: Optional[tarfile.TarFile] = None
        self._tar_mode: str = f"r|gz" if gzip else f"r|"

        # Encryption/Description
        self._aes: Optional[Cipher] = None
        self._key = key

        # Function helper
        self._decrypt: Optional[CipherContext] = None
        self._init = True

    def __enter__(self) -> tarfile.TarFile:
        try:
            # Encrypted/Decryped Tarfile
            self._file = open(self._name, "rb")

            # Extract IV for CBC
            cbc_rand = self._file.read(16)

            # Create Cipher
            self._aes = Cipher(
                algorithms.AES(self._key),
                modes.CBC(_generate_iv(self._key, cbc_rand)),
                backend=default_backend(),
            )
            self._decrypt = self._aes.decryptor()
            self._tar = tarfile.open(
                fileobj=self, mode=self._tar_mode, dereference=False, bufsize=self._bufsize
            )
            return self._tar
        except:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Close file."""
        if self._tar:
            self._tar.close()
            self._tar = None
        if self._file:
            self._file.close()
            self._file = None

    def read(self, size: int = 0) -> bytes:
        """Read data."""
        assert self._decrypt is not None
        assert self._file is not None
        data = self._decrypt.update(self._file.read(size))
        return data

    @property
    def path(self) -> Path:
        """Return path object of tarfile."""
        return self._name

    @property
    def size(self) -> float:
        """Return backup size."""
        if not self._name.is_file():
            return 0
        return round(self._name.stat().st_size / 1_048_576, 2)  # calc mbyte


def _generate_iv(key: bytes, salt: bytes) -> bytes:
    """Generate an iv from data."""
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    return temp_iv[:16]



