"""
MySQL users table + salted hashing (no chat storage).

Responsibilities:

- Connect to MySQL using environment variables.
- Initialize schema:

    CREATE TABLE users (
        email      VARCHAR(255) PRIMARY KEY,
        username   VARCHAR(255) UNIQUE NOT NULL,
        salt       VARBINARY(16) NOT NULL,
        pwd_hash   CHAR(64)      NOT NULL
    );

- Store passwords as:
    salt = 16 random bytes
    pwd_hash = hex(SHA256(salt || password))

- Provide helpers to:
    * create_user(...)
    * get_user_by_email(...)
    * verify_login(...)

All comparisons are constant-time; plaintext passwords are never logged.
"""

from __future__ import annotations

import argparse
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Optional

import pymysql
from dotenv import load_dotenv

from app.common.utils import sha256_hex

# Load .env so `python -m app.storage.db --init` works directly.
load_dotenv()


@dataclass
class User:
    email: str
    username: str
    salt: bytes
    pwd_hash: str  # hex string (length 64)


def _get_db_connection() -> pymysql.connections.Connection:
    """
    Create a new MySQL connection using environment variables.

    Expected .env keys (or system env):

        DB_HOST=localhost
        DB_PORT=3306
        DB_NAME=securechat
        DB_USER=scuser
        DB_PASSWORD=scpass
    """
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "3306"))
    db_name = os.getenv("DB_NAME", "securechat")
    user = os.getenv("DB_USER", "scuser")
    password = os.getenv("DB_PASSWORD", "scpass")

    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        charset="utf8mb4",
        autocommit=True,
    )


def init_schema() -> None:
    """
    Create the `users` table if it does not already exist.

    Called via:
        python -m app.storage.db --init
    """
    ddl = """
    CREATE TABLE IF NOT EXISTS users (
        email      VARCHAR(255) PRIMARY KEY,
        username   VARCHAR(255) UNIQUE NOT NULL,
        salt       VARBINARY(16) NOT NULL,
        pwd_hash   CHAR(64)      NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(ddl)
    finally:
        conn.close()


def _hash_password(salt: bytes, password: str) -> str:
    """
    Compute hex(SHA256(salt || password)) using sha256_hex helper.

    Args:
        salt: 16-byte random salt.
        password: User's plaintext password (not stored).

    Returns:
        64-character hex string.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    data = salt + password.encode("utf-8")
    return sha256_hex(data)


def create_user(email: str, username: str, password: str) -> None:
    """
    Create a new user with salted SHA-256 password hash.

    Raises:
        ValueError: If email or username already exists.
    """
    salt = secrets.token_bytes(16)
    pwd_hash = _hash_password(salt, password)

    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    INSERT INTO users (email, username, salt, pwd_hash)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (email, username, salt, pwd_hash),
                )
            except pymysql.err.IntegrityError as exc:
                # Duplicate email/username
                raise ValueError("User with same email/username already exists") from exc
    finally:
        conn.close()


def get_user_by_email(email: str) -> Optional[User]:
    """
    Fetch a user by email.

    Returns:
        User instance or None if not found.
    """
    conn = _get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, username, salt, pwd_hash FROM users WHERE email = %s",
                (email,),
            )
            row = cur.fetchone()
            if not row:
                return None

            # row = (email, username, salt, pwd_hash)
            return User(
                email=row[0],
                username=row[1],
                salt=row[2],
                pwd_hash=row[3],
            )
    finally:
        conn.close()


def verify_login(email: str, password: str) -> Optional[User]:
    """
    Verify user credentials.

    According to assignment spec, login succeeds only if:
      - Client cert is valid (handled in PKI layer), AND
      - salted hash matches stored pwd_hash.

    This function checks only the salted hash condition.

    Returns:
        User if credentials are valid, else None.
    """
    user = get_user_by_email(email)
    if user is None:
        # Do not reveal if email exists – just return None.
        return None

    candidate_hash = _hash_password(user.salt, password)

    # Constant-time comparison to avoid timing side channels.
    if hmac.compare_digest(candidate_hash, user.pwd_hash):
        return user
    return None


def _main() -> None:
    parser = argparse.ArgumentParser(description="SecureChat DB utilities")
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize MySQL schema (create users table)",
    )
    args = parser.parse_args()

    if args.init:
        print("[INFO] Initializing database schema (users table)...")
        init_schema()
        print("[INFO] Done.")


if __name__ == "__main__":
    _main()
