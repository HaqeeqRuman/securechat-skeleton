"""
Classic DH helpers + Trunc16(SHA256(Ks)) derivation.

This module implements "plain" modular Diffie–Hellman using a fixed
2048-bit MODP group and derives the AES-128 key as:

    K = Trunc16(SHA256(big-endian(Ks)))

where Ks is the shared secret integer.

You will use:

- DH_P, DH_G           : public parameters
- generate_private()   : pick random a or b
- compute_public()     : A = g^a mod p, B = g^b mod p
- compute_shared()     : Ks = B^a mod p  (or A^b mod p)
- derive_aes_key()     : K from Ks (16 bytes)
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Final


# 2048-bit MODP group (RFC 3526, group 14) prime p and generator g = 2.
# Using a fixed, well-known group avoids having to negotiate parameters.
DH_P: Final[int] = int(
    (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
    ),
    16,
)
DH_G: Final[int] = 2


def generate_private(p: int = DH_P) -> int:
    """
    Generate a random private exponent in [2, p-2].

    Args:
        p: DH prime modulus.

    Returns:
        A random integer suitable as a DH private key.
    """
    if p <= 3:
        raise ValueError("DH prime too small")

    # secrets.randbelow(n) returns [0, n); shift by 2 to get [2, p-2]
    return secrets.randbelow(p - 3) + 2


def compute_public(g: int, x: int, p: int = DH_P) -> int:
    """
    Compute public value: Y = g^x mod p.

    Args:
        g: Generator.
        x: Private exponent.
        p: Prime modulus.

    Returns:
        Public value (integer).
    """
    return pow(g, x, p)


def compute_shared(peer_public: int, x: int, p: int = DH_P) -> int:
    """
    Compute shared secret Ks = (peer_public)^x mod p.

    Args:
        peer_public: Peer’s DH public value (A or B).
        x: Our private exponent.
        p: Prime modulus.

    Returns:
        Shared secret Ks as integer.

    Raises:
        ValueError: If peer_public is outside the valid range.
    """
    if not (1 < peer_public < p - 1):
        raise ValueError("Invalid peer DH public value")

    return pow(peer_public, x, p)


def _int_to_big_endian(value: int) -> bytes:
    """Convert positive integer to minimal big-endian byte string."""
    if value <= 0:
        raise ValueError("Shared secret must be positive")
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, byteorder="big")


def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret Ks.

    Formula (from assignment):

        K = Trunc16(SHA256(big-endian(Ks)))

    Args:
        shared_secret: Ks as integer.

    Returns:
        16-byte AES key.
    """
    ks_bytes = _int_to_big_endian(shared_secret)
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]
