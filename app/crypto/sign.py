"""
RSA PKCS#1 v1.5 SHA-256 sign/verify.

This module provides small helpers for:
  - Loading RSA private keys (PEM).
  - Loading RSA public keys from X.509 certs.
  - Signing bytes with RSA PKCS#1 v1.5 + SHA-256.
  - Verifying signatures.

Usage example:

    from app.crypto import sign
    from app.common.utils import b64_encode, b64_decode

    priv = sign.load_private_key("certs/server_key.pem")
    data = b"hello"
    sig  = sign.sign_bytes(priv, data)

    pub  = sign.load_public_key_from_cert("certs/server_cert.pem")
    ok   = sign.verify_signature(pub, data, sig)
"""

from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def load_private_key(path: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """
    Load an RSA private key (PEM).

    Args:
        path: Path to PEM file (PKCS#1 or PKCS#8).
        password: Optional password (bytes) if encrypted, else None.

    Returns:
        RSAPrivateKey instance.
    """
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return key


def load_public_key_from_cert(path: str) -> rsa.RSAPublicKey:
    """
    Load RSA public key from an X.509 certificate (PEM).

    Args:
        path: Path to certificate PEM.

    Returns:
        RSAPublicKey instance.
    """
    data = Path(path).read_bytes()
    cert = x509.load_pem_x509_certificate(data)
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("Certificate does not contain an RSA public key")
    return pub


def sign_bytes(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign arbitrary bytes using RSA PKCS#1 v1.5 + SHA-256.

    Args:
        private_key: RSAPrivateKey instance.
        data: Message to sign.

    Returns:
        Signature bytes.
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature


def verify_signature(
    public_key: rsa.RSAPublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """
    Verify RSA PKCS#1 v1.5 + SHA-256 signature.

    Args:
        public_key: RSAPublicKey instance.
        data: Message that was signed.
        signature: Signature bytes.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
