#!/usr/bin/env python3
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

Includes test requirements:
  - SIG_FAIL when tampered client signature arrives (if you tamper client).
  - REPLAY detection on reused/lower seqno.
  - SessionReceipt verification.
"""

from __future__ import annotations

import os
import socket
import threading
import json
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes

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

CA_CERT_PATH = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
SERVER_KEY_PATH = os.getenv("SERVER_KEY_PATH", "certs/server_key.pem")
SERVER_CERT_PATH = os.getenv("SERVER_CERT_PATH", "certs/server_cert.pem")


def _recv_lines(sock: socket.socket):
    """Yield complete newline-delimited JSON lines from the socket."""
    buffer = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            line = line.strip()
            if line:
                yield line.decode("utf-8", errors="replace")


def handle_client(conn: socket.socket, addr):
    print(f"[+] Client connected from {addr}")

    priv_key = rsa_sign.load_private_key(SERVER_KEY_PATH)
    server_cert_pem = open(SERVER_CERT_PATH, "rb").read()
    server_cert_b64 = b64_encode(server_cert_pem)

    # Canonical fingerprint from SERVER cert (both sides use this)
    server_cert = x509.load_pem_x509_certificate(server_cert_pem)
    server_fp = server_cert.fingerprint(hashes.SHA256()).hex()

    ca_cert = pki.load_ca_certificate(CA_CERT_PATH)

    transcript = Transcript(role="server")

    peer_first_seq: Optional[int] = None
    peer_last_seq: Optional[int] = None
    peer_pub_key = None

    # ----------------------------------------------------------------------
    # 0) HELLO / SERVER_HELLO
    # ----------------------------------------------------------------------

    try:
        first_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] Client disconnected before hello")
        conn.close()
        transcript.close()
        return

    hello_msg = decode_message(first_line)
    if not isinstance(hello_msg, HelloMsg):
        print("[-] Expected HelloMsg")
        conn.close()
        transcript.close()
        return

    transcript.append_message(hello_msg)

    # Verify client certificate
    try:
        client_cert = x509.load_pem_x509_certificate(b64_decode(hello_msg.client_cert))
        pki.verify_certificate(client_cert, ca_cert, expected_hostname="client.local")
        peer_pub_key = client_cert.public_key()
        print("[PKI] Client certificate verified.")

        # Use SERVER cert fingerprint so client and server logs match
        transcript.set_peer_cert_fingerprint(server_fp)

    except Exception as e:
        print(f"[BAD_CERT] Client certificate verification failed: {e}")
        conn.close()
        transcript.close()
        return

    # Send server hello
    nonce_s = os.urandom(16)
    server_hello = ServerHelloMsg(
        server_cert=server_cert_b64,
        nonce=b64_encode(nonce_s),
    )
    conn.sendall(encode_message(server_hello).encode("utf-8") + b"\n")
    transcript.append_message(server_hello)
    print("[PKI] Sent server hello")

    # ----------------------------------------------------------------------
    # 1) DH #1 (AUTH)
    # ----------------------------------------------------------------------

    try:
        dh1_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] DH1 aborted")
        conn.close()
        transcript.close()
        return

    dh1_client = decode_message(dh1_line)
    if not isinstance(dh1_client, DHClientMsg):
        print("[-] Expected DHClientMsg (DH1)")
        conn.close()
        transcript.close()
        return

    transcript.append_message(dh1_client)

    p1, g1, A1 = dh1_client.p, dh1_client.g, dh1_client.A

    b1 = dh.generate_private(p1)
    B1 = dh.compute_public(g1, b1, p1)

    dh1_server = DHServerMsg(B=B1)
    conn.sendall(encode_message(dh1_server).encode("utf-8") + b"\n")
    transcript.append_message(dh1_server)

    shared_secret_auth = dh.compute_shared(A1, b1, p1)
    K_auth = dh.derive_aes_key(shared_secret_auth)
    print("[DH1] K_auth ready")

    # ----------------------------------------------------------------------
    # 2) REGISTER / LOGIN
    # ----------------------------------------------------------------------

    try:
        auth_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] No auth msg received")
        conn.close()
        transcript.close()
        return

    auth_msg = decode_message(auth_line)

    # REGISTER
    if isinstance(auth_msg, RegisterMsg):
        try:
            pt = aes.decrypt_aes_ecb(K_auth, b64_decode(auth_msg.ct))
            data = json.loads(pt.decode("utf-8"))
            db.create_user(
                email=data["email"],
                username=data["username"],
                password=data["password"],
            )
            print(f"[AUTH] Registered {data['email']}")
        except Exception as e:
            print(f"[AUTH_FAIL] Registration error: {e}")
            conn.close()
            transcript.close()
            return

        transcript.append_message(auth_msg)

    # LOGIN
    elif isinstance(auth_msg, LoginMsg):
        try:
            pt = aes.decrypt_aes_ecb(K_auth, b64_decode(auth_msg.ct))
            data = json.loads(pt.decode("utf-8"))
            user = db.verify_login(email=data["email"], password=data["password"])
            if not user:
                print("[AUTH_FAIL] Invalid credentials")
                conn.close()
                transcript.close()
                return
        except Exception as e:
            print(f"[AUTH_FAIL] Login decrypt error: {e}")
            conn.close()
            transcript.close()
            return

        print(f"[AUTH] Login ok for {data['email']}")
        transcript.append_message(auth_msg)

    else:
        print("[-] Expected RegisterMsg/LoginMsg")
        conn.close()
        transcript.close()
        return

    # ----------------------------------------------------------------------
    # 3) DH #2 (CHAT)
    # ----------------------------------------------------------------------

    try:
        dh2_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] No DH2 from client")
        conn.close()
        transcript.close()
        return

    dh2_client = decode_message(dh2_line)
    if not isinstance(dh2_client, DHClientMsg):
        print("[-] DH2 missing")
        conn.close()
        transcript.close()
        return

    transcript.append_message(dh2_client)

    p2, g2, A2 = dh2_client.p, dh2_client.g, dh2_client.A
    b2 = dh.generate_private(p2)
    B2 = dh.compute_public(g2, b2, p2)

    dh2_server = DHServerMsg(B=B2)
    conn.sendall(encode_message(dh2_server).encode("utf-8") + b"\n")
    transcript.append_message(dh2_server)

    shared_secret_chat = dh.compute_shared(A2, b2, p2)
    K_chat = dh.derive_aes_key(shared_secret_chat)
    print("[DH2] K_chat ready")

    # ----------------------------------------------------------------------
    # 4) CHAT LOOP
    # ----------------------------------------------------------------------

    stop_event = threading.Event()

    def recv_loop():
        nonlocal peer_first_seq, peer_last_seq

        try:
            for line in _recv_lines(conn):
                msg = decode_message(line)

                # ---------------- SessionReceipt ----------------
                if isinstance(msg, ReceiptMsg):
                    th = transcript.transcript_hash_hex()

                    if msg.transcript_sha256 != th:
                        print("[RECEIPT_FAIL] Hash mismatch")
                    else:
                        ok = rsa_sign.verify_signature(
                            peer_pub_key,
                            th.encode("ascii"),
                            b64_decode(msg.sig),
                        )
                        print("[RECEIPT_OK]" if ok else "[RECEIPT_FAIL] Bad signature")

                    # IMPORTANT: do NOT append ReceiptMsg to transcript
                    continue

                # ---------------- ChatMsg ----------------
                if not isinstance(msg, ChatMsg):
                    print("[WARN] Ignoring non-chat msg")
                    continue

                # REPLAY
                if peer_last_seq is not None and msg.seqno <= peer_last_seq:
                    print(f"[REPLAY] seq={msg.seqno} (last {peer_last_seq})")
                    continue

                # Signature verify
                verify_bytes = f"{msg.seqno}|{msg.ts}|{msg.ct}".encode("utf-8")
                try:
                    sig_ok = rsa_sign.verify_signature(
                        peer_pub_key,
                        verify_bytes,
                        b64_decode(msg.sig),
                    )
                except Exception:
                    sig_ok = False

                if not sig_ok:
                    print("[SIG_FAIL] Dropping tampered message")
                    continue

                # Update seq tracking
                if peer_first_seq is None:
                    peer_first_seq = msg.seqno
                peer_last_seq = msg.seqno

                transcript.append_chat_message(msg)

                # Decrypt
                try:
                    pt = aes.decrypt_aes_ecb(K_chat, b64_decode(msg.ct))
                    print(f"\n[CLIENT #{msg.seqno}] {pt.decode('utf-8', errors='replace')}")
                except Exception as e:
                    print(f"[ERR] Decrypt failed: {e}")

        finally:
            stop_event.set()
            print("[*] recv_loop terminated")

    threading.Thread(target=recv_loop, daemon=True).start()

    # -------------------- SEND LOOP --------------------
    seqno = 1

    try:
        while not stop_event.is_set():
            try:
                text = input("server> ")
            except (EOFError, KeyboardInterrupt):
                print("\n[*] Server input interrupted")
                break

            if text.lower() in {"quit", "exit"}:
                break
            if not text:
                continue

            ct = aes.encrypt_aes_ecb(K_chat, text.encode("utf-8"))
            ct_b64 = b64_encode(ct)

            ts = now_ms()
            verify = f"{seqno}|{ts}|{ct_b64}".encode("utf-8")
            sig_b64 = b64_encode(rsa_sign.sign_bytes(priv_key, verify))

            msg = ChatMsg(seqno=seqno, ts=ts, ct=ct_b64, sig=sig_b64)
            transcript.append_chat_message(msg)
            conn.sendall(encode_message(msg).encode("utf-8") + b"\n")

            seqno += 1

    finally:
        # ------------------------------------------------------------------
        # 5) Send SessionReceipt
        # ------------------------------------------------------------------

        th = transcript.transcript_hash_hex()
        first_seq = peer_first_seq or 0
        last_seq = peer_last_seq or 0

        sig_b64 = b64_encode(rsa_sign.sign_bytes(priv_key, th.encode("ascii")))

        rec = ReceiptMsg(
            peer="client",
            first_seq=first_seq,
            last_seq=last_seq,
            transcript_sha256=th,
            sig=sig_b64,
        )

        # Log the receipt into transcript (AFTER computing th)
        try:
            transcript.append_message(rec)
        except Exception as e:
            print(f"[WARN] Failed to append receipt to transcript: {e}")

        try:
            conn.sendall(encode_message(rec).encode("utf-8") + b"\n")
        except Exception:
            pass

        conn.close()
        transcript.close()
        print("[*] Server session closed")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[LISTEN] SecureChat server on {HOST}:{PORT}")

        try:
            while True:
                conn, addr = s.accept()
                handle_client(conn, addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutting down (KeyboardInterrupt)")
        finally:
            try:
                s.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
