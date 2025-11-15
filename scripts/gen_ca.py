#!/usr/bin/env python3
"""
Generate a Root CA (keypair + self-signed certificate).
"""

import argparse
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


def generate_ca(cn: str, out_prefix: str):
    out_prefix = Path(out_prefix)
    out_prefix.parent.mkdir(exist_ok=True)

    key_path = Path(f"{out_prefix}_key.pem")
    cert_path = Path(f"{out_prefix}_cert.pem")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Root CA generated:")
    print(f"    Key : {key_path}")
    print(f"    Cert: {cert_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    generate_ca(args.cn, args.out)


if __name__ == "__main__":
    main()
