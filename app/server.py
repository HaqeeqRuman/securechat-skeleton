"""
SecureChat Server

Features:
  - Plain TCP (no TLS).
  - PKI hello/server_hello with X.509 certs + nonces.
  - Certificate verification against local Root CA.
  - DH #1 => AES-128(ECB)+PKCS#7 K_auth for registration/login.
  - MySQL-backed registration/login with salted SHA-256 password hashes.
  - DH #2 => AES-128(ECB)+PKCS#7 K_chat for chat session.
  - RSA PKCS#1 v1.5 + SHA-256 signatures on every ChatMsg.
  - Replay protection using seqno.
  - Append-only transcript + TranscriptHash.
  - Signed SessionReceipt at teardown.

Message flow (high level):
  1) Client connects (TCP).
  2) Client -> Server: HelloMsg (client cert + nonceC).
  3) Server -> Client: ServerHelloMsg (server cert + nonceS).
     - Both sides verify each other's cert using Root CA.
  4) Client -> Server: DHClientMsg   (DH #1)
  5) Server -> Client: DHServerMsg   (DH #1)
     - Derive K_auth = Trunc16(SHA256(big-endian(Ks_auth))).
  6) Client -> Server: RegisterMsg/LoginMsg (AES-encrypted with K_auth)
     - Server decrypts and performs DB-backed auth/registration.
  7) Client -> Server: DHClientMsg   (DH #2)
  8) Server -> Client: DHServerMsg   (DH #2)
     - Derive K_chat = Trunc16(SHA256(big-endian(Ks_chat))).
  9) Encrypted chat (ChatMsg) with K_chat + signatures and replay protection.
 10) Both sides send/verify SessionReceipt (signed transcript hash).
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes

import os
import socket
import threading
import json
from typing import Optional

from cryptography import x509

from app.common.utils import b64_encode, b64_decode, now_ms
from app.common.protocol import (
    HelloMsg,
    ServerHelloMsg,
    RegisterMsg,
    LoginMsg,
    DHClientMsg,
    DHServerMsg,
    ChatMsg,
    ReceiptMsg,
    encode_message,
    decode_message,
)
from app.crypto import dh, aes, sign as rsa_sign, pki
from app.storage.transcript import Transcript
from app.storage import db

HOST = os.getenv("CHAT_HOST", "127.0.0.1")
PORT = int(os.getenv("CHAT_PORT", "9000"))

# Paths (can override via env variables if needed)
CA_CERT_PATH = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
SERVER_KEY_PATH = os.getenv("SERVER_KEY_PATH", "certs/server_key.pem")
SERVER_CERT_PATH = os.getenv("SERVER_CERT_PATH", "certs/server_cert.pem")


def _recv_lines(sock: socket.socket):
    """
    Generator yielding complete JSON lines from the socket.
    Uses '\n' as message delimiter.
    """
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if line.strip():
                yield line.decode("utf-8")


def handle_client(conn: socket.socket, addr):
    print(f"[+] Client connected from {addr}")

    # Load our RSA private key and our certificate (for hello)
    priv_key = rsa_sign.load_private_key(SERVER_KEY_PATH)
    server_cert_pem = open(SERVER_CERT_PATH, "rb").read()
    server_cert_b64 = b64_encode(server_cert_pem)

    # Load CA cert for verifying client cert
    ca_cert = pki.load_ca_certificate(CA_CERT_PATH)

    # Transcript for this session
    transcript = Transcript(role="server")

    # Track peer's seqnos (client) for replay & receipt
    peer_first_seq: Optional[int] = None
    peer_last_seq: Optional[int] = None

    # This will be filled after hello verification
    peer_pub_key = None

    # ---------- 0) PKI hello / server_hello ----------

    try:
        first_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] Client disconnected before hello")
        conn.close()
        transcript.close()
        return

    hello_msg = decode_message(first_line)
    if not isinstance(hello_msg, HelloMsg):
        print("[-] Expected 'hello' message")
        conn.close()
        transcript.close()
        return

    transcript.append_message(hello_msg)

    # Decode and verify client certificate
    try:
        client_cert_pem = b64_decode(hello_msg.client_cert)
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
        # Verify against CA and expected CN=client.local
        pki.verify_certificate(client_cert, ca_cert, expected_hostname="client.local")
        peer_pub_key = client_cert.public_key()
        print("[PKI] Client certificate verified (CN=client.local)")

        # NEW: record peer cert fingerprint in transcript for non-repudiation
        fp = client_cert.fingerprint(hashes.SHA256()).hex()
        transcript.set_peer_cert_fingerprint(fp)
    except Exception as e:
        print(f"[BAD_CERT] Client certificate verification failed: {e}")
        conn.close()
        transcript.close()
        return

    # Build and send ServerHelloMsg
    import os as _os
    nonce_s = _os.urandom(16)
    nonce_s_b64 = b64_encode(nonce_s)

    server_hello = ServerHelloMsg(
        server_cert=server_cert_b64,
        nonce=nonce_s_b64,
    )
    conn.sendall(encode_message(server_hello).encode("utf-8") + b"\n")
    transcript.append_message(server_hello)
    print("[PKI] Sent server hello with server certificate")

    # ---------- 1) DH #1 handshake (server role, K_auth) ----------

    try:
        dh1_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] Client disconnected during DH #1 handshake")
        conn.close()
        transcript.close()
        return

    dh1_client = decode_message(dh1_line)
    if not isinstance(dh1_client, DHClientMsg):
        print("[-] Expected 'dh client' message for DH #1")
        conn.close()
        transcript.close()
        return

    p1 = dh1_client.p
    g1 = dh1_client.g
    A1 = dh1_client.A
    print(f"[DH1] Received dh client: p={p1}, g={g1}, A={A1}")
    transcript.append_message(dh1_client)

    # Our DH #1 private/public
    b1_priv = dh.generate_private(p1)
    B1 = dh.compute_public(g1, b1_priv, p1)

    dh1_server = DHServerMsg(B=B1)
    conn.sendall(encode_message(dh1_server).encode("utf-8") + b"\n")
    transcript.append_message(dh1_server)
    print(f"[DH1] Sent dh server: B={B1}")

    # Compute shared secret + AES key for AUTH
    shared_secret_auth = dh.compute_shared(A1, b1_priv, p1)
    K_auth = dh.derive_aes_key(shared_secret_auth)
    print(f"[DH1] Derived K_auth (len={len(K_auth)})")

    # ---------- 2) Registration / Login (control plane over AES with K_auth) ----------

    try:
        auth_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] Client disconnected before register/login")
        conn.close()
        transcript.close()
        return

    auth_msg = decode_message(auth_line)

    # Handle REGISTER
    if isinstance(auth_msg, RegisterMsg):
        try:
            auth_ct = b64_decode(auth_msg.ct)
            auth_json = aes.decrypt_aes_ecb(K_auth, auth_ct).decode("utf-8")
            creds = json.loads(auth_json)
            email = creds["email"]
            username = creds["username"]
            password = creds["password"]
        except Exception as e:
            print(f"[-] Failed to decrypt/parse register payload: {e}")
            conn.close()
            transcript.close()
            return

        try:
            # Generates salt and hex(SHA256(salt||password)), stores in MySQL.
            db.create_user(email=email, username=username, password=password)
            print(f"[AUTH] Registered new user email={email}, username={username}")
        except ValueError as e:
            print(f"[AUTH_FAIL] Registration error: {e}")
            conn.close()
            transcript.close()
            return

        transcript.append_message(auth_msg)

    # Handle LOGIN
    elif isinstance(auth_msg, LoginMsg):
        try:
            auth_ct = b64_decode(auth_msg.ct)
            auth_json = aes.decrypt_aes_ecb(K_auth, auth_ct).decode("utf-8")
            creds = json.loads(auth_json)
            email = creds["email"]
            password = creds["password"]
        except Exception as e:
            print(f"[-] Failed to decrypt/parse login payload: {e}")
            conn.close()
            transcript.close()
            return

        user = db.verify_login(email=email, password=password)
        if user is None:
            print(f"[AUTH_FAIL] Invalid credentials for email={email}")
            conn.close()
            transcript.close()
            return

        print(f"[AUTH] Login successful for email={email}, username={user.username}")
        transcript.append_message(auth_msg)

    else:
        print(f"[-] Expected register/login message, got: {auth_msg}")
        conn.close()
        transcript.close()
        return

    # ---------- 3) DH #2 handshake (server role, K_chat) ----------

    try:
        dh2_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] Client disconnected during DH #2 handshake")
        conn.close()
        transcript.close()
        return

    dh2_client = decode_message(dh2_line)
    if not isinstance(dh2_client, DHClientMsg):
        print("[-] Expected 'dh client' message for DH #2")
        conn.close()
        transcript.close()
        return

    p2 = dh2_client.p
    g2 = dh2_client.g
    A2 = dh2_client.A
    print(f"[DH2] Received dh client: p={p2}, g={g2}, A={A2}")
    transcript.append_message(dh2_client)

    # Our DH #2 private/public
    b2_priv = dh.generate_private(p2)
    B2 = dh.compute_public(g2, b2_priv, p2)

    dh2_server = DHServerMsg(B=B2)
    conn.sendall(encode_message(dh2_server).encode("utf-8") + b"\n")
    transcript.append_message(dh2_server)
    print(f"[DH2] Sent dh server: B={B2}")

    shared_secret_chat = dh.compute_shared(A2, b2_priv, p2)
    K_chat = dh.derive_aes_key(shared_secret_chat)
    print(f"[DH2] Derived K_chat (len={len(K_chat)})")

    # ---------- 4) Encrypted chat loop (using K_chat) ----------

    stop_event = threading.Event()

    def recv_loop():
        nonlocal peer_first_seq, peer_last_seq
        try:
            for line in _recv_lines(conn):
                incoming = decode_message(line)

                # Handle SessionReceipt from client
                if isinstance(incoming, ReceiptMsg):
                    my_hash = transcript.transcript_hash_hex()
                    if my_hash != incoming.transcript_sha256:
                        print("[RECEIPT_FAIL] transcript hash mismatch")
                    else:
                        sig_bytes = b64_decode(incoming.sig)
                        ok = rsa_sign.verify_signature(
                            peer_pub_key,
                            incoming.transcript_sha256.encode("ascii"),
                            sig_bytes,
                        )
                        if ok:
                            print("[RECEIPT_OK] Client SessionReceipt verified")
                        else:
                            print("[RECEIPT_FAIL] invalid RSA signature on receipt")
                    transcript.append_message(incoming)
                    continue

                # Handle ChatMsg
                if not isinstance(incoming, ChatMsg):
                    print(f"[WARN] Ignoring non-chat message: {incoming}")
                    continue

                # Replay protection
                if peer_last_seq is not None and incoming.seqno <= peer_last_seq:
                    print(
                        f"[REPLAY] Dropping message seqno={incoming.seqno}, "
                        f"last seen={peer_last_seq}"
                    )
                    continue

                # Verify signature: seqno|ts|ct
                ct_b64 = incoming.ct
                to_verify = f"{incoming.seqno}|{incoming.ts}|{ct_b64}".encode("utf-8")
                sig_bytes = b64_decode(incoming.sig)

                if not rsa_sign.verify_signature(peer_pub_key, to_verify, sig_bytes):
                    print("[SIG_FAIL] invalid signature, dropping message")
                    continue

                # Update seq tracking
                if peer_first_seq is None:
                    peer_first_seq = incoming.seqno
                peer_last_seq = incoming.seqno

                # Log after signature passes (includes fingerprint if set)
                transcript.append_chat_message(incoming)

                # Decrypt and display with K_chat
                ct_bytes = b64_decode(ct_b64)
                try:
                    pt_bytes = aes.decrypt_aes_ecb(K_chat, ct_bytes)
                    plaintext = pt_bytes.decode("utf-8", errors="replace")
                except Exception as e:
                    print(f"[ERR] Decryption failed: {e}")
                    continue

                print(f"\n[CLIENT #{incoming.seqno} @ {incoming.ts}] {plaintext}")
        finally:
            print("[*] Receive loop ended")
            stop_event.set()

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    recv_thread.start()

    # Send loop
    seqno = 1
    try:
        while not stop_event.is_set():
            try:
                text = input("server> ")
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Server input interrupted")
                break

            if not text:
                continue
            if text.lower() in {"quit", "exit"}:
                print("[*] Server exiting chat with client")
                break

            ct = aes.encrypt_aes_ecb(K_chat, text.encode("utf-8"))
            ct_b64 = b64_encode(ct)

            ts = now_ms()
            to_sign = f"{seqno}|{ts}|{ct_b64}".encode("utf-8")
            sig_bytes = rsa_sign.sign_bytes(priv_key, to_sign)
            sig_b64 = b64_encode(sig_bytes)

            outgoing = ChatMsg(
                seqno=seqno,
                ts=ts,
                ct=ct_b64,
                sig=sig_b64,
            )
            seqno += 1

            # Log with peer_cert_fp included
            transcript.append_chat_message(outgoing)
            conn.sendall(encode_message(outgoing).encode("utf-8") + b"\n")
    finally:
        # ---------- 5) Send SessionReceipt to client ----------
        print("[*] Preparing SessionReceipt (server)")

        t_hash = transcript.transcript_hash_hex()
        if peer_first_seq is None or peer_last_seq is None:
            first_seq = 0
            last_seq = 0
        else:
            first_seq = peer_first_seq
            last_seq = peer_last_seq

        receipt = ReceiptMsg(
            peer="client",
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=t_hash,
            sig="",
        )

        sig_bytes = rsa_sign.sign_bytes(priv_key, t_hash.encode("ascii"))
        receipt.sig = b64_encode(sig_bytes)

        try:
            conn.sendall(encode_message(receipt).encode("utf-8") + b"\n")
        except Exception:
            print("[-] Failed to send SessionReceipt to client")

        conn.close()
        transcript.close()
        print("[*] Connection closed, transcript finalized")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[LISTEN] SecureChat server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
