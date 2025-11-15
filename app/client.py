"""
SecureChat Client

Features:
  - Plain TCP (no TLS).
  - PKI hello/server_hello with X.509 certs + nonces.
  - Certificate verification against local Root CA.
  - DH key exchange => AES-128(ECB)+PKCS#7 session key.
  - AES-protected registration/login against server-side MySQL.
  - RSA PKCS#1 v1.5 + SHA-256 signatures on every ChatMsg.
  - Replay protection using seqno.
  - Append-only transcript + TranscriptHash.
  - Signed SessionReceipt at teardown.

Message flow:
  1) Connect to server.
  2) Client -> Server: HelloMsg (client cert + nonceC).
  3) Server -> Client: ServerHelloMsg (server cert + nonceS).
     - Verify server cert using Root CA.
  4) Client -> Server: DHClientMsg
  5) Server -> Client: DHServerMsg
  6) Client -> Server: RegisterMsg/LoginMsg (AES-encrypted credentials)
     - Server decrypts and performs registration/login.
  7) Encrypted chat (ChatMsg) with signatures and replay protection.
  8) Both sides send/verify SessionReceipt.
"""

from __future__ import annotations

import os
import socket
import threading
from typing import Optional
import json
import getpass

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
                yield line.decode("utf-8")


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

        import os as _os
        nonce_c = _os.urandom(16)
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

        transcript.append_message(server_hello)

        # Decode and verify server certificate
        try:
            server_cert_pem = b64_decode(server_hello.server_cert)
            server_cert = x509.load_pem_x509_certificate(server_cert_pem)
            pki.verify_certificate(server_cert, ca_cert, expected_hostname="server.local")
            peer_pub_key = server_cert.public_key()
            print("[PKI] Server certificate verified (CN=server.local)")
        except Exception as e:
            print(f"[BAD_CERT] Server certificate verification failed: {e}")
            s.close()
            transcript.close()
            return

        # (We could also check our nonce was echoed or use nonce_s for extra checks.)

        # ---------- 1) DH handshake (client role) ----------

        a_priv = dh.generate_private()
        A = dh.compute_public(dh.DH_G, a_priv, dh.DH_P)

        dh_client = DHClientMsg(
            g=dh.DH_G,
            p=dh.DH_P,
            A=A,
        )
        s.sendall(encode_message(dh_client).encode("utf-8") + b"\n")
        transcript.append_message(dh_client)
        print(f"[DH] Sent dh client: p={dh.DH_P}, g={dh.DH_G}, A={A}")

        try:
            dh_line = next(_recv_lines(s))
        except StopIteration:
            print("[-] Server closed connection during DH handshake")
            transcript.close()
            return

        dh_server = decode_message(dh_line)
        if not isinstance(dh_server, DHServerMsg):
            print("[-] Expected 'dh server' message")
            transcript.close()
            return

        transcript.append_message(dh_server)
        B = dh_server.B
        print(f"[DH] Received dh server: B={B}")

        shared_secret = dh.compute_shared(B, a_priv, dh.DH_P)
        K = dh.derive_aes_key(shared_secret)
        print(f"[DH] Derived shared secret and AES key (len={len(K)})")

        # ---------- 2) Registration / Login (control plane over AES) ----------

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
            ct = aes.encrypt_aes_ecb(K, inner)
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
            ct = aes.encrypt_aes_ecb(K, inner)
            ct_b64 = b64_encode(ct)

            auth_msg = LoginMsg(ct=ct_b64)

        s.sendall(encode_message(auth_msg).encode("utf-8") + b"\n")
        transcript.append_message(auth_msg)
        print(f"[AUTH] Sent {mode} request (encrypted)")

        # ---------- 3) Encrypted chat ----------

        stop_event = threading.Event()

        def recv_loop():
            nonlocal peer_first_seq, peer_last_seq
            try:
                for line in _recv_lines(s):
                    msg = decode_message(line)

                    # Handle SessionReceipt from server
                    if isinstance(msg, ReceiptMsg):
                        my_hash = transcript.transcript_hash_hex()
                        if my_hash != msg.transcript_sha256:
                            print("[RECEIPT_FAIL] transcript hash mismatch")
                        else:
                            sig_bytes = b64_decode(msg.sig)
                            ok = rsa_sign.verify_signature(
                                peer_pub_key,
                                msg.transcript_sha256.encode("ascii"),
                                sig_bytes,
                            )
                            if ok:
                                print("[RECEIPT_OK] Server SessionReceipt verified")
                            else:
                                print("[RECEIPT_FAIL] invalid RSA signature on receipt")
                        transcript.append_message(msg)
                        continue

                    # Handle ChatMsg from server
                    if not isinstance(msg, ChatMsg):
                        print(f"[WARN] Ignoring non-chat message: {msg}")
                        continue

                    # Replay protection
                    if peer_last_seq is not None and msg.seqno <= peer_last_seq:
                        print(
                            f"[REPLAY] Dropping message seqno={msg.seqno}, "
                            f"last seen={peer_last_seq}"
                        )
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

                    # Decrypt and display
                    ct_bytes = b64_decode(ct_b64)
                    try:
                        pt_bytes = aes.decrypt_aes_ecb(K, ct_bytes)
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

                ct = aes.encrypt_aes_ecb(K, text.encode("utf-8"))
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

                transcript.append_chat_message(outgoing)
                s.sendall(encode_message(outgoing).encode("utf-8") + b"\n")
        finally:
            # ---------- 4) Send SessionReceipt to server ----------
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

            try:
                s.sendall(encode_message(receipt).encode("utf-8") + b"\n")
            except Exception:
                print("[-] Failed to send SessionReceipt to server")

            s.close()
            transcript.close()
            print("[*] Connection closed, transcript finalized")


if __name__ == "__main__":
    main()
