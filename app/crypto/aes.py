"""
AES-128(ECB)+PKCS#7 helpers (use cryptography lib).

This module exposes small, explicit helpers for your data-plane:

- pkcs7_pad / pkcs7_unpad: operate on raw bytes.
- encrypt_aes_ecb / decrypt_aes_ecb: AES-128 in ECB mode with PKCS#7.

You should do *base64* encoding/decoding at the protocol layer
(app.common.utils) – here we only deal with raw bytes.
"""

from typing import Final

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE_BYTES: Final[int] = 16  # 128-bit blocks


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    """
    Apply PKCS#7 padding.

    Args:
        data: Arbitrary-length byte string.
        block_size: Block size in bytes (16 for AES-128).

    Returns:
        Padded bytes whose length is a multiple of block_size.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")

    padder = padding.PKCS7(block_size * 8).padder()
    padded = padder.update(data) + padder.finalize()
    return padded


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    """
    Remove PKCS#7 padding.

    Args:
        padded: Bytes that were padded with PKCS#7.
        block_size: Block size in bytes.

    Returns:
        Original unpadded bytes.

    Raises:
        ValueError: If padding is invalid (e.g., corrupt ciphertext).
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")

    unpadder = padding.PKCS7(block_size * 8).unpadder()
    try:
        data = unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        # cryptography raises ValueError on bad padding
        raise ValueError("Invalid PKCS#7 padding") from exc
    return data


def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-128 in ECB mode + PKCS#7 padding.

    Args:
        key: 16-byte AES key (from Trunc16(SHA256(Ks))).
        plaintext: Raw message bytes.

    Returns:
        Ciphertext bytes (multiples of 16 bytes).
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    padded = pkcs7_pad(plaintext, BLOCK_SIZE_BYTES)
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct


def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-128 ECB ciphertext and remove PKCS#7 padding.

    Args:
        key: 16-byte AES key.
        ciphertext: Ciphertext bytes produced by encrypt_aes_ecb.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If key size is invalid or padding is incorrect.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()

    padded = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = pkcs7_unpad(padded, BLOCK_SIZE_BYTES)
    return plaintext



"""
Summary of what this file (aes_ecb.py or crypto_utils.py) does:

This module implements the low-level symmetric encryption layer used in SecureChat's 
data plane, exactly as specified in the assignment: **AES-128 in ECB mode with PKCS#7 padding**.

Key design points:
- Uses the official `cryptography` library (hazmat) for maximum clarity and security.
- All functions work exclusively with **raw bytes** — base64 encoding/decoding is deliberately 
  left to the protocol/serialization layer (app.common.utils).
- Provides explicit, easy-to-audit helpers:
    • pkcs7_pad()    → add PKCS#7 padding
    • pkcs7_unpad()  → remove and validate padding (raises clear error on tampering)
    • encrypt_aes_ecb() → pad → AES-128-ECB encrypt
    • decrypt_aes_ecb() → AES-128-ECB decrypt → unpad + validate
- Enforces strict 16-byte key length (derived elsewhere via Trunc16(SHA256(Ks))).
- ECB mode is used because the assignment explicitly requires it for educational purposes 
  (to demonstrate the exact cryptographic primitives requested).

Intended usage in SecureChat:
    key = sha256(session_key)[:16]          # Trunc16(SHA256(Ks))
    ct  = encrypt_aes_ecb(key, message_bytes)
    pt  = decrypt_aes_ecb(key, ct)

This module satisfies the requirement:
"AES-128(ECB)+PKCS#7 helpers" and keeps the encryption code minimal, explicit, 
and perfectly aligned with the protocol specification.
"""
