#!/usr/bin/env python3
"""
Generate RSA keypair + certificate signed by the Root CA.
Includes SAN = DNSName(CN) as required by assignment.
"""

import argparse
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID


def load_ca():
    ca_key = serialization.load_pem_private_key(
        Path("certs/ca_key.pem").read_bytes(),
        password=None,
    )
    ca_cert = x509.load_pem_x509_certificate(Path("certs/ca_cert.pem").read_bytes())
    return ca_key, ca_cert


def generate_cert(cn: str, out_prefix: str):
    ca_key, ca_cert = load_ca()

    out_prefix = Path(out_prefix)
    out_prefix.parent.mkdir(exist_ok=True)

    key_path = Path(f"{out_prefix}_key.pem")
    cert_path = Path(f"{out_prefix}_cert.pem")

    # 1. Generate RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Build subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # 3. Build certificate with SAN
    san = x509.SubjectAlternativeName([
        x509.DNSName(cn)
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365 * 2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san, critical=False)   # <-- REQUIRED BY ASSIGNMENT
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 4. Write key
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)

    # 5. Write certificate
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Certificate issued for CN={cn}")
    print(f"    SAN = DNS:{cn}")
    print(f"    Private Key : {key_path}")
    print(f"    Certificate : {cert_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name for certificate")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    args = parser.parse_args()
    generate_cert(args.cn, args.out)


if __name__ == "__main__":
    main()
