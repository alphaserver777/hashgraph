"""User authentication and session management for the Web UI (Этап 5).

Passwords are hashed via stdlib `hashlib.scrypt` — no external deps.
Sessions are kept in process memory as a dict[token → SessionRecord].
Sessions are NOT persisted across node restarts; users must re-login.
This is acceptable for the prototype phase.

Roles:
- `viewer` — can read /viz, /dag, /metrics, /peers, /incidents. Cannot
  approve peers, clear DAG, run simulations, edit incidents.
- `admin`  — full access including state-changing endpoints.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional

ROLE_VIEWER = "viewer"
ROLE_ADMIN = "admin"
ROLES = {ROLE_VIEWER, ROLE_ADMIN}

SESSION_TTL_SECONDS = 8 * 3600  # 8 hours
SESSION_COOKIE_NAME = "mdrj_session"

# scrypt parameters: deliberately moderate for prototype CPU cost.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_KEYLEN = 32
_SALT_BYTES = 16


def normalize_role(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in ROLES:
        return text
    return ROLE_VIEWER


def hash_password(password: str) -> str:
    """Hash a password with scrypt + random salt. Result is self-contained."""
    if not password:
        raise ValueError("password must not be empty")
    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_KEYLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(derived).decode()}"


def verify_password(password: str, stored: str) -> bool:
    """Check a candidate password against a stored hash."""
    if not stored or not stored.startswith("scrypt$"):
        return False
    try:
        _algo, n_str, r_str, p_str, salt_b64, derived_b64 = stored.split("$", 5)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(derived_b64)
    except (ValueError, base64.binascii.Error):
        return False
    actual = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=int(n_str),
        r=int(r_str),
        p=int(p_str),
        dklen=len(expected),
    )
    return secrets.compare_digest(actual, expected)


@dataclass(slots=True)
class SessionRecord:
    token: str
    username: str
    role: str
    created_at: float
    expires_at: float


class SessionStore:
    """In-memory session store. Lost on restart."""

    def __init__(self, *, ttl_seconds: int = SESSION_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._sessions: Dict[str, SessionRecord] = {}

    def create(self, username: str, role: str) -> SessionRecord:
        token = secrets.token_urlsafe(32)
        now = time.time()
        record = SessionRecord(
            token=token,
            username=username,
            role=normalize_role(role),
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        self._sessions[token] = record
        return record

    def get(self, token: str) -> Optional[SessionRecord]:
        record = self._sessions.get(token)
        if record is None:
            return None
        if record.expires_at < time.time():
            self._sessions.pop(token, None)
            return None
        return record

    def revoke(self, token: str) -> None:
        self._sessions.pop(token, None)

    def revoke_user(self, username: str) -> int:
        removed = [t for t, rec in self._sessions.items() if rec.username == username]
        for t in removed:
            self._sessions.pop(t, None)
        return len(removed)

    def prune_expired(self) -> int:
        now = time.time()
        removed = [t for t, rec in self._sessions.items() if rec.expires_at < now]
        for t in removed:
            self._sessions.pop(t, None)
        return len(removed)
