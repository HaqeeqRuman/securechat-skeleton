#!/usr/bin/env python3
"""
Offline non-repudiation verification for SecureChat.

Checks:
  1) For each ChatMsg in the transcript:
       - recompute SHA256(seqno || ts || ct)
       - verify RSA signature with client/server certs

  2) For the SessionReceipt line:
       - recompute TranscriptHash over all *previous* lines
         (exact bytes, including '\n')
       - compare to "transcript sha256" in receipt
       - verify RSA signature over that hash using the
         signer’s certificate (client or server)

Any edit to ct/sig/metadata/receipt should break verification.
"""

import json
import hashlib
from pathlib import Path

from cryptography import x509

from app.common.utils import b64_decode
from app.common.protocol import ChatMsg, ReceiptMsg
from app.crypto import sign as rsa_sign


# ---------------------------------------------------------------------
# CONFIG – CHANGE THIS TO ONE OF YOUR REAL TRANSCRIPTS
# ---------------------------------------------------------------------
# Example:
#   "transcripts/session-1763309537-client.log"
TRANSCRIPT_PATH = "transcripts/session-1763313638-server.log"

SERVER_CERT_PATH = "certs/server_cert.pem"
CLIENT_CERT_PATH = "certs/client_cert.pem"


def load_keys():
    server_cert = x509.load_pem_x509_certificate(Path(SERVER_CERT_PATH).read_bytes())
    client_cert = x509.load_pem_x509_certificate(Path(CLIENT_CERT_PATH).read_bytes())

    return server_cert.public_key(), client_cert.public_key()


def main():
    server_pub, client_pub = load_keys()

    transcript_file = Path(TRANSCRIPT_PATH)
    if not transcript_file.exists():
        print(f"[ERROR] Transcript not found: {TRANSCRIPT_PATH}")
        return

    print(f"[INFO] Verifying transcript: {TRANSCRIPT_PATH}")

    # Running SHA-256 over *exact* bytes for TranscriptHash
    hasher = hashlib.sha256()

    receipt_obj = None

    # First pass: verify messages and compute TranscriptHash
    with transcript_file.open("rb") as f:
        for raw_line in f:
            if not raw_line.strip():
                continue

            # Decode JSON only for semantic checks
            try:
                obj = json.loads(raw_line.decode("utf-8"))
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping non-JSON line: {e}")
                continue

            msg_type = obj.get("type")

            # Stop hashing when we hit the first receipt line.
            # (At runtime, TranscriptHash was computed BEFORE appending receipt.)
            if msg_type == "receipt":
                receipt_obj = obj
                # IMPORTANT: do NOT include this line in TranscriptHash
                break

            # Update TranscriptHash with the exact bytes (including '\n')
            hasher.update(raw_line)

            # Only verify ChatMsg signatures here
            if msg_type != "msg":
                continue

            msg = ChatMsg(**obj)
            ct_b64 = msg.ct
            sig_b64 = msg.sig

            verify_bytes = f"{msg.seqno}|{msg.ts}|{ct_b64}".encode("utf-8")
            sig_bytes = b64_decode(sig_b64)

            # Try server key, then client key
            if rsa_sign.verify_signature(server_pub, verify_bytes, sig_bytes):
                who = "server"
                ok = True
            elif rsa_sign.verify_signature(client_pub, verify_bytes, sig_bytes):
                who = "client"
                ok = True
            else:
                who = "unknown"
                ok = False

            print(f"[MSG] seq={msg.seqno} from={who} sig_ok={ok}")

    # Final computed TranscriptHash (over log lines BEFORE receipt)
    recomputed_hash_hex = hasher.hexdigest()
    print(f"\n[HASH] Recomposed TranscriptHash = {recomputed_hash_hex}")

    if receipt_obj is None:
        print("[WARN] No SessionReceipt found in transcript (no 'type':'receipt' line).")
        return

    # -----------------------------------------------------------------
    # 2) Verify Receipt
    # -----------------------------------------------------------------
    receipt = ReceiptMsg(**receipt_obj)

    print("\n[RECEIPT] Fields:")
    print(f"  peer             = {receipt.peer}")
    print(f"  first_seq        = {receipt.first_seq}")
    print(f"  last_seq         = {receipt.last_seq}")
    print(f"  transcript_sha256 (in receipt) = {receipt.transcript_sha256}")
    print(f"  recomputed TranscriptHash       = {recomputed_hash_hex}")

    # Check hash match
    hash_matches = (recomputed_hash_hex == receipt.transcript_sha256)
    print(f"[CHECK] TranscriptHash match: {hash_matches}")

    # Verify signature over the transcript hash
    sig_bytes = b64_decode(receipt.sig)
    hash_bytes = receipt.transcript_sha256.encode("ascii")

    # Try both server and client certs to see who signed it
    if rsa_sign.verify_signature(server_pub, hash_bytes, sig_bytes):
        signer = "server"
        receipt_sig_ok = True
    elif rsa_sign.verify_signature(client_pub, hash_bytes, sig_bytes):
        signer = "client"
        receipt_sig_ok = True
    else:
        signer = "unknown"
        receipt_sig_ok = False

    print(f"[CHECK] Receipt signature valid: {receipt_sig_ok} (signed_by={signer})")

    print("\n=== SUMMARY ===")
    if not hash_matches:
        print("  - TranscriptHash mismatch (editing any log line will cause this).")
    if not receipt_sig_ok:
        print("  - Receipt signature invalid (editing the Receipt or using wrong key causes this).")
    if hash_matches and receipt_sig_ok:
        print("  ✓ Non-repudiation OK: transcript + receipt are consistent and correctly signed.")


if __name__ == "__main__":
    main()
