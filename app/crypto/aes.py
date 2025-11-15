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
