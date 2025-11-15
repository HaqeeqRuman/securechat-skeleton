"""
PKI helpers for SecureChat.

Responsibilities:
  - Load X.509 certificates (CA + peer).
  - Verify that a peer certificate:
      1) Has a valid CA signature (using our Root CA).
      2) Is currently within its validity period.
      3) Has a subject name (CN or SAN DNSName) matching the expected hostname.

This module does NOT manage private keys; those are handled by scripts and
the client/server application logic.
"""

from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


def load_certificate(path: str) -> x509.Certificate:
    """Load an X.509 certificate from a PEM file."""
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def load_ca_certificate(path: str) -> x509.Certificate:
    """Load the trusted Root CA certificate from a PEM file."""
    with open(path, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def _get_cn(cert: x509.Certificate) -> Optional[str]:
    """Extract Common Name (CN) from certificate subject, or None if missing."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    return attrs[0].value


def _get_san_dnsname(cert: x509.Certificate) -> Optional[str]:
    """Extract the first DNSName from SAN, if present."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return None

    for name in san.value:
        if isinstance(name, x509.DNSName):
            return name.value
    return None


def verify_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_hostname: str,
) -> bool:
    """
    Validate a peer certificate.

    Checks:
      1. Signature: cert must be signed by ca_cert.
      2. Time: not expired and not before validity.
      3. Hostname: expected_hostname must match SAN DNSName,
         or if SAN missing, match CN.

    Raises:
      ValueError with a BAD_CERT reason if verification fails.

    Returns:
      True if certificate is valid.
    """

    # 1) Verify CA signature on certificate
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        raise ValueError("BAD_CERT: invalid CA signature")

    # 2) Check validity period
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise ValueError("BAD_CERT: certificate expired or not yet valid")

    # 3) Hostname check (prefer SAN DNSName, fallback to CN)
    san_dns = _get_san_dnsname(cert)
    cn = _get_cn(cert)

    hostname_ok = False

    if san_dns is not None:
        hostname_ok = (san_dns == expected_hostname)
    elif cn is not None:
        hostname_ok = (cn == expected_hostname)

    if not hostname_ok:
        raise ValueError(
            f"BAD_CERT: hostname mismatch (expected={expected_hostname}, "
            f"san_dns={san_dns}, cn={cn})"
        )

    return True


