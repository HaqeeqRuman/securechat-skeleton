"""
Append-only transcript + TranscriptHash helpers.

Each SecureChat session should have an append-only transcript file
under `transcripts/`, plus a running SHA-256 "TranscriptHash" over the
exact bytes written.

Typical usage pattern (per session):

    from app.storage.transcript import Transcript
    from app.common.protocol import ChatMsg, encode_message

    t = Transcript(role="server")  # or "client"

    # For every message sent/received:
    t.append_message(msg)

    # At teardown:
    h_hex = t.transcript_hash_hex()
    t.close()

The resulting hex digest (TranscriptHash) is what you place in the
SessionReceipt message and sign with RSA.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Optional

from app.common.protocol import Message, ChatMsg, encode_message

TRANSCRIPTS_DIR = Path("transcripts")


class Transcript:
    """
    Append-only transcript for a single chat session.

    - Writes one JSON line per application message (encode_message(...)).
    - Maintains a running SHA-256 over the *exact* bytes written.
    - Designed so that both client and server can produce identical
      TranscriptHash values when they log messages in the same order.
    """

    def __init__(self, role: str, session_id: Optional[str] = None):
        """
        Args:
            role: "client" or "server" (used in filename for convenience).
            session_id: Optional custom session id; defaults to unix timestamp.
        """
        TRANSCRIPTS_DIR.mkdir(exist_ok=True)

        if session_id is None:
            session_id = str(int(time.time()))

        self.role = role
        self.session_id = session_id

        self.path = TRANSCRIPTS_DIR / f"session-{session_id}-{role}.log"
        # open in append-binary mode
        self._file = self.path.open("ab")

        # running SHA-256 of all written lines (with trailing "\n")
        self._hasher = hashlib.sha256()

    # ------------------------------------------------------------------
    # Append helpers
    # ------------------------------------------------------------------

    def append_raw_line(self, line: bytes) -> None:
        """
        Append a raw line (without trailing newline) to the transcript.
        Adds '\n', writes to file, and updates hash.
        """
        if b"\n" in line:
            # keep lines simple; we want exactly one newline per record
            raise ValueError("line must not contain newline characters")

        record = line + b"\n"
        self._file.write(record)
        self._file.flush()
        self._hasher.update(record)

    def append_message(self, msg: Message) -> None:
        """
        Append a protocol Message (e.g., ChatMsg, HelloMsg, etc.)
        by serializing it with encode_message.
        """
        json_line = encode_message(msg).encode("utf-8")
        self.append_raw_line(json_line)

    def append_chat_message(self, msg: ChatMsg) -> None:
        """Type-safe alias for chat messages."""
        self.append_message(msg)

    # ------------------------------------------------------------------
    # Finalization helpers
    # ------------------------------------------------------------------

    def transcript_hash_hex(self) -> str:
        """
        Return the hex-encoded SHA-256 of all lines written so far.

        This value is what you embed as "transcript sha256" in a
        SessionReceipt and then sign with RSA.
        """
        return self._hasher.hexdigest()

    def close(self) -> None:
        """Close the transcript file."""
        try:
            self._file.close()
        except Exception:
            pass


def compute_transcript_hash_from_file(path: str) -> str:
    """
    Compute SHA-256 hex of an existing transcript file.

    Useful if you ever need to verify transcripts offline.

    Args:
        path: Path to transcript .log file.

    Returns:
        Hex string of SHA-256(file contents).
    """
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()
