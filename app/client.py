"""
SecureChat Client (Part 3: Session key + encrypted chat).

This version:
  - Connects to the SecureChat server.
  - Initiates DH key exchange ("dh client").
  - Derives AES-128 key K.
  - Sends and receives encrypted chat messages.

NOTE:
  - No PKI, login, or signatures yet (Part 4).
  - Enough to test encrypted payloads via Wireshark.
"""

from __future__ import annotations

import os
import socket
import threading

from app.common.utils import b64_encode, b64_decode, now_ms
from app.common.protocol import (
    DHClientMsg,
    DHServerMsg,
    ChatMsg,
    encode_message,
    decode_message,
)
from app.crypto import dh, aes


HOST = os.getenv("CHAT_HOST", "127.0.0.1")
PORT = int(os.getenv("CHAT_PORT", "9000"))


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

        # ---------- 1) DH handshake (client role) ----------

        # Our DH private/public
        a_priv = dh.generate_private()
        A = dh.compute_public(dh.DH_G, a_priv, dh.DH_P)

        dh_client = DHClientMsg(
            g=dh.DH_G,
            p=dh.DH_P,
            A=A,
        )
        s.sendall(encode_message(dh_client).encode("utf-8") + b"\n")
        print(f"[DH] Sent dh client: p={dh.DH_P}, g={dh.DH_G}, A={A}")

        # Receive DHServerMsg
        try:
            first_line = next(_recv_lines(s))
        except StopIteration:
            print("[-] Server closed connection during handshake")
            return

        dh_server = decode_message(first_line)
        if not isinstance(dh_server, DHServerMsg):
            print("[-] Expected 'dh server' message")
            return

        B = dh_server.B
        print(f"[DH] Received dh server: B={B}")

        # Compute shared secret + AES key
        shared_secret = dh.compute_shared(B, a_priv, dh.DH_P)
        K = dh.derive_aes_key(shared_secret)
        print(f"[DH] Derived shared secret and AES key (len={len(K)})")

        # ---------- 2) Encrypted chat ----------

        def recv_loop():
            seq_seen = 0
            try:
                for line in _recv_lines(s):
                    msg = decode_message(line)
                    if not isinstance(msg, ChatMsg):
                        print(f"[WARN] Ignoring non-chat message: {msg}")
                        continue

                    if msg.seqno <= seq_seen:
                        print(f"[REPLAY?] Received seqno={msg.seqno} <= last={seq_seen}")
                    seq_seen = max(seq_seen, msg.seqno)

                    ct_bytes = b64_decode(msg.ct)
                    try:
                        pt_bytes = aes.decrypt_aes_ecb(K, ct_bytes)
                        plaintext = pt_bytes.decode("utf-8", errors="replace")
                    except Exception as e:
                        print(f"[ERR] Decryption failed: {e}")
                        continue

                    print(f"\n[SERVER #{msg.seqno} @ {msg.ts}] {plaintext}")
            finally:
                print("[*] Receive loop ended")

        recv_thread = threading.Thread(target=recv_loop, daemon=True)
        recv_thread.start()

        seqno = 1
        try:
            while True:
                text = input("client> ")
                if not text:
                    continue
                if text.lower() in {"quit", "exit"}:
                    print("[*] Client exiting chat")
                    break

                ct = aes.encrypt_aes_ecb(K, text.encode("utf-8"))
                ct_b64 = b64_encode(ct)

                msg = ChatMsg(
                    seqno=seqno,
                    ts=now_ms(),
                    ct=ct_b64,
                    sig="",  # will be real RSA signature in Part 4
                )
                seqno += 1

                s.sendall(encode_message(msg).encode("utf-8") + b"\n")
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Client interrupted, closing")
        finally:
            s.close()


if __name__ == "__main__":
    main()
