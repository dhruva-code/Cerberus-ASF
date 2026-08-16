"""
Password hashing, session tokens, and the FastAPI dependency that gates
protected routes. Sessions are opaque random tokens stored server-side
(not JWTs) — simpler, and revocable by just deleting the row on logout.

Delivered via the Authorization header (bearer token), not a cookie: the
app's CORS config allows a wildcard origin with credentials, which
browsers refuse to honor for cookies, so a header-based token is what
actually works here regardless of that pre-existing CORS looseness.
"""

import secrets

import bcrypt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import db

_bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme)) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user_row = db.get_user_by_session_token(credentials.credentials)
    if user_row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user = dict(user_row)
    user["_session_token"] = credentials.credentials
    return user


def get_user_by_token(token: str):
    """Used by the /ws/telemetry websocket, which can't send an Authorization
    header — token arrives as a query param instead."""
    if not token:
        return None
    user_row = db.get_user_by_session_token(token)
    return dict(user_row) if user_row else None
