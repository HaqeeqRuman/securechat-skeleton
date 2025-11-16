#!/usr/bin/env python3
"""
SecureChat Client (Clean Version — No Tamper / No Replay on send)

Features:
  - Plain TCP (no TLS).
  - PKI hello/server_hello with X.509 certs + nonces.
  - Certificate verification against local Root CA.
  - DH #1 => AES-128(ECB)+PKCS#7 K_auth for registration/login.
  - AES-protected registration/login against server-side MySQL.
  - DH #2 => AES-128(ECB)+PKCS#7 K_chat for chat session.
  - RSA PKCS#1 v1.5 + SHA-256 signatures on every ChatMsg.
  - Replay protection (enforced on the server, optional on client receive).
  - Append-only transcript + TranscriptHash.
  - Signed SessionReceipt at teardown.
"""

from __future__ import annotations

import os
import socket
import threading
from typing import Optional
import json
import getpass

from cryptography import x509
from cryptography.hazmat.primitives import hashes  # for server cert fingerprint

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


HOST = os.getenv("CHAT_HOST", "127.0.0.1")
PORT = int(os.getenv("CHAT_PORT", "9000"))

CA_CERT_PATH = os.getenv("CA_CERT_PATH", "certs/ca_cert.pem")
CLIENT_KEY_PATH = os.getenv("CLIENT_KEY_PATH", "certs/client_key.pem")
CLIENT_CERT_PATH = os.getenv("CLIENT_CERT_PATH", "certs/client_cert.pem")


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
            if line.strip():
                yield line.decode("utf-8", errors="replace")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[CONNECT] Connecting to {HOST}:{PORT} ...")
        s.connect((HOST, PORT))
        print("[+] Connected")

        # Load client private key and certificate
        priv_key = rsa_sign.load_private_key(CLIENT_KEY_PATH)
        client_cert_pem = open(CLIENT_CERT_PATH, "rb").read()
        client_cert_b64 = b64_encode(client_cert_pem)

        # Load CA cert for verifying server cert
        ca_cert = pki.load_ca_certificate(CA_CERT_PATH)

        transcript = Transcript(role="client")

        # Track peer (server) seqnos for replay + receipts
        peer_first_seq: Optional[int] = None
        peer_last_seq: Optional[int] = None

        peer_pub_key = None

        # ---------- 0) PKI hello / server_hello ----------

        nonce_c = os.urandom(16)
        nonce_c_b64 = b64_encode(nonce_c)

        hello = HelloMsg(
            client_cert=client_cert_b64,
            nonce=nonce_c_b64,
        )
        s.sendall(encode_message(hello).encode("utf-8") + b"\n")
        transcript.append_message(hello)
        print("[PKI] Sent hello with client certificate")

        try:
            sh_line = next(_recv_lines(s))
        except StopIteration:
            print("[-] Server closed connection before server hello")
            transcript.close()
            return

        server_hello = decode_message(sh_line)
        if not isinstance(server_hello, ServerHelloMsg):
            print("[-] Expected 'server hello' message")
            transcript.close()
            return

        # Decode and verify server certificate BEFORE appending server_hello
        try:
            server_cert_pem = b64_decode(server_hello.server_cert)
            server_cert = x509.load_pem_x509_certificate(server_cert_pem)
            pki.verify_certificate(server_cert, ca_cert, expected_hostname="server.local")
            peer_pub_key = server_cert.public_key()
            print("[PKI] Server certificate verified (CN=server.local)")

            # Use SERVER cert fingerprint as canonical peer_cert_fp on both sides
            fp = server_cert.fingerprint(hashes.SHA256()).hex()
            transcript.set_peer_cert_fingerprint(fp)

        except Exception as e:
            print(f"[BAD_CERT] Server certificate verification failed: {e}")
            s.close()
            transcript.close()
            return

        # Now append ServerHello AFTER setting fingerprint (order matches server logic)
        transcript.append_message(server_hello)

        # ---------- 1) DH #1 handshake (client role, K_auth) ----------

        a1_priv = dh.generate_private()
        A1 = dh.compute_public(dh.DH_G, a1_priv, dh.DH_P)

        dh1_client = DHClientMsg(
            g=dh.DH_G,
            p=dh.DH_P,
            A=A1,
        )
        s.sendall(encode_message(dh1_client).encode("utf-8") + b"\n")
        transcript.append_message(dh1_client)
        print(f"[DH1] Sent dh client: p={dh.DH_P}, g={dh.DH_G}, A={A1}")

        try:
            dh1_line = next(_recv_lines(s))
        except StopIteration:
            print("[-] Server closed connection during DH #1 handshake")
            transcript.close()
            return

        dh1_server = decode_message(dh1_line)
        if not isinstance(dh1_server, DHServerMsg):
            print("[-] Expected 'dh server' message for DH #1")
            transcript.close()
            return

        transcript.append_message(dh1_server)
        B1 = dh1_server.B
        print(f"[DH1] Received dh server: B={B1}")

        shared_secret_auth = dh.compute_shared(B1, a1_priv, dh.DH_P)
        K_auth = dh.derive_aes_key(shared_secret_auth)
        print(f"[DH1] Derived K_auth (len={len(K_auth)})")

        # ---------- 2) Registration / Login (control plane over AES with K_auth) ----------

        while True:
            mode = input("Auth mode [register/login]: ").strip().lower()
            if mode in {"register", "login"}:
                break
            print("Please type 'register' or 'login'.")

        if mode == "register":
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")

            payload = {
                "email": email,
                "username": username,
                "password": password,
            }
            inner = json.dumps(payload).encode("utf-8")
            ct = aes.encrypt_aes_ecb(K_auth, inner)
            ct_b64 = b64_encode(ct)

            auth_msg = RegisterMsg(ct=ct_b64)
        else:  # login
            email = input("Email: ").strip()
            password = getpass.getpass("Password: ")

            payload = {
                "email": email,
                "password": password,
            }
            inner = json.dumps(payload).encode("utf-8")
            ct = aes.encrypt_aes_ecb(K_auth, inner)
            ct_b64 = b64_encode(ct)

            auth_msg = LoginMsg(ct=ct_b64)

        s.sendall(encode_message(auth_msg).encode("utf-8") + b"\n")
        transcript.append_message(auth_msg)
        print(f"[AUTH] Sent {mode} request (encrypted with K_auth)")

        # ---------- 3) DH #2 handshake (client role, K_chat) ----------

        a2_priv = dh.generate_private()
        A2 = dh.compute_public(dh.DH_G, a2_priv, dh.DH_P)

        dh2_client = DHClientMsg(
            g=dh.DH_G,
            p=dh.DH_P,
            A=A2,
        )
        s.sendall(encode_message(dh2_client).encode("utf-8") + b"\n")
        transcript.append_message(dh2_client)
        print(f"[DH2] Sent dh client: p={dh.DH_P}, g={dh.DH_G}, A={A2}")

        try:
            dh2_line = next(_recv_lines(s))
        except StopIteration:
            print("[-] Server closed connection during DH #2 handshake")
            transcript.close()
            return

        dh2_server = decode_message(dh2_line)
        if not isinstance(dh2_server, DHServerMsg):
            print("[-] Expected 'dh server' message for DH #2")
            transcript.close()
            return

        transcript.append_message(dh2_server)
        B2 = dh2_server.B
        print(f"[DH2] Received dh server: B={B2}")

        shared_secret_chat = dh.compute_shared(B2, a2_priv, dh.DH_P)
        K_chat = dh.derive_aes_key(shared_secret_chat)
        print(f"[DH2] Derived K_chat (len={len(K_chat)})")

        # ---------- 4) Encrypted chat (using K_chat) ----------

        stop_event = threading.Event()

        def recv_loop():
            nonlocal peer_first_seq, peer_last_seq
            try:
                for line in _recv_lines(s):
                    msg = decode_message(line)

                    # Handle SessionReceipt from server
                    if isinstance(msg, ReceiptMsg):
                        my_hash = transcript.transcript_hash_hex()
                        hash_ok = (my_hash == msg.transcript_sha256)
                        sig_ok = rsa_sign.verify_signature(
                            peer_pub_key,
                            msg.transcript_sha256.encode("ascii"),
                            b64_decode(msg.sig),
                        )
                        if hash_ok and sig_ok:
                            print("[RECEIPT_OK] Server SessionReceipt verified")
                        else:
                            print("[RECEIPT_FAIL] transcript hash or signature mismatch")
                        # DO NOT append ReceiptMsg to transcript
                        continue

                    # Handle ChatMsg from server
                    if not isinstance(msg, ChatMsg):
                        print(f"[WARN] Ignoring non-chat message: {msg}")
                        continue

                    # Replay protection (client-side view)
                    if peer_last_seq is not None and msg.seqno <= peer_last_seq:
                        print(f"[REPLAY] seq={msg.seqno} (last {peer_last_seq})")
                        continue

                    ct_b64 = msg.ct
                    to_verify = f"{msg.seqno}|{msg.ts}|{ct_b64}".encode("utf-8")
                    sig_bytes = b64_decode(msg.sig)

                    if not rsa_sign.verify_signature(peer_pub_key, to_verify, sig_bytes):
                        print("[SIG_FAIL] invalid signature, dropping message")
                        continue

                    # Update seq tracking
                    if peer_first_seq is None:
                        peer_first_seq = msg.seqno
                    peer_last_seq = msg.seqno

                    # Log after signature passes
                    transcript.append_chat_message(msg)

                    # Decrypt and display with K_chat
                    ct_bytes = b64_decode(ct_b64)
                    try:
                        pt_bytes = aes.decrypt_aes_ecb(K_chat, ct_bytes)
                        plaintext = pt_bytes.decode("utf-8", errors="replace")
                    except Exception as e:
                        print(f"[ERR] Decryption failed: {e}")
                        continue

                    print(f"\n[SERVER #{msg.seqno} @ {msg.ts}] {plaintext}")
            finally:
                print("[*] Receive loop ended")
                stop_event.set()

        recv_thread = threading.Thread(target=recv_loop, daemon=True)
        recv_thread.start()

        seqno = 1
        try:
            while not stop_event.is_set():
                try:
                    text = input("client> ")
                except (EOFError, KeyboardInterrupt):
                    print("\n[*] Client input interrupted")
                    break

                if not text:
                    continue
                if text.lower() in {"quit", "exit"}:
                    print("[*] Client exiting chat")
                    break

                # Encrypt plaintext with K_chat
                ct = aes.encrypt_aes_ecb(K_chat, text.encode("utf-8"))
                ct_b64 = b64_encode(ct)

                # Build signed message
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

                transcript.append_chat_message(outgoing)
                s.sendall(encode_message(outgoing).encode("utf-8") + b"\n")
        finally:
            # ---------- 5) Send SessionReceipt to server ----------
            print("[*] Preparing SessionReceipt (client)")

            t_hash = transcript.transcript_hash_hex()
            if peer_first_seq is None or peer_last_seq is None:
                first_seq = 0
                last_seq = 0
            else:
                first_seq = peer_first_seq
                last_seq = peer_last_seq

            receipt = ReceiptMsg(
                peer="server",
                first_seq=first_seq,
                last_seq=last_seq,
                transcript_sha256=t_hash,
                sig="",
            )

            sig_bytes = rsa_sign.sign_bytes(priv_key, t_hash.encode("ascii"))
            receipt.sig = b64_encode(sig_bytes)

            # Log the receipt itself in the transcript (AFTER computing t_hash)
            try:
                transcript.append_message(receipt)
            except Exception as e:
                print(f"[WARN] Failed to append receipt to transcript: {e}")

            try:
                s.sendall(encode_message(receipt).encode("utf-8") + b"\n")
            except Exception:
                print("[-] Failed to send SessionReceipt to server")

            s.close()
            transcript.close()
            print("[*] Connection closed, transcript finalized")


if __name__ == "__main__":
    main()
