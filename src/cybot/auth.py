from __future__ import annotations

import hashlib
import hmac
import os
import time


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, derived_hex = stored.split("$", 2)
        if scheme != "scrypt":
            return False
        derived = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32
        )
        return hmac.compare_digest(derived.hex(), derived_hex)
    except (ValueError, TypeError):
        return False


def issue_session(secret: bytes, ttl: int = 12 * 3600) -> str:
    expires = int(time.time()) + ttl
    body = str(expires).encode()
    signature = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return f"{expires}.{signature}"


def session_valid(secret: bytes, value: str | None) -> bool:
    if not value or "." not in value:
        return False
    expires_text, signature = value.split(".", 1)
    try:
        expires = int(expires_text)
    except ValueError:
        return False
    if expires < int(time.time()):
        return False
    expected = hmac.new(secret, expires_text.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
