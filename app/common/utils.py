"""
Common helpers: base64, timestamps, and SHA-256 hex.

Used by:
  - storage/db.py (salted password hashing)
  - protocol and message signing
  - encrypted chat (base64 for ciphertext)
"""

import base64
import hashlib
import time
from typing import Union


def b64_encode(data: bytes) -> str:
    """Return URL-safe base64 string (no newlines)."""
    return base64.b64encode(data).decode("ascii")


def b64_decode(s: str) -> bytes:
    """Decode base64 string back to bytes."""
    return base64.b64decode(s.encode("ascii"))


def now_ms() -> int:
    """Current UNIX time in milliseconds as int."""
    return int(time.time() * 1000)


def sha256_hex(data: Union[bytes, str]) -> str:
    """
    Compute SHA-256 digest as a lowercase hex string.

    Accepts bytes or text (UTF-8).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
