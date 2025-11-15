"""
SecureChat Server (Part 3: Session key + encrypted chat).

This version:
  - Accepts one TCP client.
  - Runs DH key exchange (server sends B).
  - Derives AES-128 key K using derive_aes_key(shared_secret).
  - Receives encrypted chat messages and prints the plaintext.
  - Allows the server operator to send encrypted replies.

NOTE:
  - No PKI, login, or signatures wired yet (that’s Part 4).
  - This is sufficient for Wireshark to show encrypted payloads.
"""

from __future__ import annotations

import os
import socket
import threading

from app.common.utils import b64_decode, b64_encode, now_ms
from app.common.protocol import (
    DHServerMsg,
    DHClientMsg,
    ChatMsg,
    encode_message,
    decode_message,
)
from app.crypto import dh, aes


HOST = os.getenv("CHAT_HOST", "127.0.0.1")
PORT = int(os.getenv("CHAT_PORT", "9000"))


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

    # ---------- 1) DH handshake (server role) ----------

    # Receive DHClientMsg
    try:
        first_line = next(_recv_lines(conn))
    except StopIteration:
        print("[-] Client disconnected during handshake")
        conn.close()
        return

    dh_client = decode_message(first_line)
    if not isinstance(dh_client, DHClientMsg):
        print("[-] Expected 'dh client' message")
        conn.close()
        return

    p = dh_client.p
    g = dh_client.g
    A = dh_client.A
    print(f"[DH] Received dh client: p={p}, g={g}, A={A}")

    # Our DH private/public
    b_priv = dh.generate_private(p)
    B = dh.compute_public(g, b_priv, p)

    # Send DHServerMsg
    dh_server = DHServerMsg(B=B)
    conn.sendall(encode_message(dh_server).encode("utf-8") + b"\n")
    print(f"[DH] Sent dh server: B={B}")

    # Compute shared secret + AES key
    shared_secret = dh.compute_shared(A, b_priv, p)
    K = dh.derive_aes_key(shared_secret)
    print(f"[DH] Derived shared secret and AES key (len={len(K)})")

    # ---------- 2) Encrypted chat loop ----------

    # Receiving messages in a separate thread
    def recv_loop():
        seq_seen = 0
        try:
            for line in _recv_lines(conn):
                msg = decode_message(line)
                if not isinstance(msg, ChatMsg):
                    print(f"[WARN] Ignoring non-chat message: {msg}")
                    continue

                # (Replay protection etc. can be enforced in Part 4)
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

                print(f"\n[CLIENT #{msg.seqno} @ {msg.ts}] {plaintext}")
        finally:
            print("[*] Receive loop ended")

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    recv_thread.start()

    # Server send loop (optional replies)
    seqno = 1
    try:
        while True:
            text = input("server> ")
            if not text:
                continue
            if text.lower() in {"quit", "exit"}:
                print("[*] Server exiting chat with client")
                break

            ct = aes.encrypt_aes_ecb(K, text.encode("utf-8"))
            ct_b64 = b64_encode(ct)

            msg = ChatMsg(
                seqno=seqno,
                ts=now_ms(),
                ct=ct_b64,
                sig="",  # Part 4 will add real RSA signatures
            )
            seqno += 1

            conn.sendall(encode_message(msg).encode("utf-8") + b"\n")
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Server interrupted, closing connection")
    finally:
        conn.close()
        print("[*] Connection closed")


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[LISTEN] SecureChat server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr)
            # For simplicity, handle a single client then loop for next.


if __name__ == "__main__":
    main()
