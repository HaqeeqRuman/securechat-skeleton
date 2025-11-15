#!/usr/bin/env python3
"""
Issue server/client certificates signed by the Root CA.

Requirement from skeleton:
    """Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

Usage:
    python scripts/gen_cert.py --cn server.local --out certs/server
    python scripts.gen_cert.py --cn client.local --out certs/client

Outputs:
    <out>_key.pem
    <out>_cert.pem
"""

import argparse
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


CA_KEY_PATH = Path("certs/ca_key.pem")
CA_CERT_PATH = Path("certs/ca_cert.pem")


def load_ca():
    """Load CA key and certificate from the certs directory."""
    if not CA_KEY_PATH.exists() or not CA_CERT_PATH.exists():
        raise SystemExit(
            "[-] CA key/cert not found. Run gen_ca.py first "
            "(expected certs/ca_key.pem and certs/ca_cert.pem)."
        )

    ca_key = serialization.load_pem_private_key(
        CA_KEY_PATH.read_bytes(),
        password=None,
    )
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    return ca_key, ca_cert


def generate_cert(cn: str, out_prefix: str) -> None:
    """
    Generate an end-entity certificate with:
        - CN = cn
        - SAN = DNSName(cn)
        - Signed by Root CA
    """
    ca_key, ca_cert = load_ca()

    out_prefix_path = Path(out_prefix)
    out_prefix_path.parent.mkdir(exist_ok=True)

    key_path = Path(f"{out_prefix}_key.pem")
    cert_path = Path(f"{out_prefix}_cert.pem")

    # 1) Generate entity RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2) Build subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # 3) Subject Alternative Name (SAN=DNSName(CN)) as required
    san = x509.SubjectAlternativeName([
        x509.DNSName(cn),
    ])

    # 4) Build end-entity certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365 * 2))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            san,
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 5) Write private key
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)

    # 6) Write certificate
    cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_path.write_bytes(cert_bytes)

    print(f"[+] Certificate issued for CN={cn}")
    print(f"    SAN          : DNS:{cn}")
    print(f"    Private key  : {key_path}")
    print(f"    Certificate  : {cert_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a server/client certificate signed by the Root CA."
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name (CN) for this certificate (e.g., server.local)",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output prefix, e.g. 'certs/server' (will write <out>_key.pem and <out>_cert.pem)",
    )
    args = parser.parse_args()

    generate_cert(args.cn, args.out)


if __name__ == "__main__":
    main()
