"""
Scheme Authority — admin session authentication.

Follows the same JWT cookie pattern as requester-portal/portal_auth.py.
The admin session cookie is named 'sa_admin_session' to avoid collisions.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Request
from jose import JWTError, jwt

import config as cfg

COOKIE_NAME = "sa_admin_session"


def create_admin_token(user_email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=cfg.SA_JWT_EXPIRE_MINUTES)
    payload = {"sub": user_email, "exp": expire}
    return jwt.encode(payload, cfg.SA_JWT_SECRET, algorithm=cfg.SA_JWT_ALGORITHM)


def decode_admin_token(token: str) -> dict:
    return jwt.decode(token, cfg.SA_JWT_SECRET, algorithms=[cfg.SA_JWT_ALGORITHM])


def _extract_token(request: Request) -> str | None:
    """Pull the session token from cookie or Bearer header."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    return token or None


def require_admin_login(request: Request) -> dict:
    """
    FastAPI dependency for HTMX/browser routes — redirects to login page on failure.

    Accepts either:
    - ``sa_admin_session`` cookie  (browser / HTMX flows)
    - ``Authorization: Bearer <token>`` header  (API / script access via POST /auth/token)
    """
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=303, headers={"Location": "/auth/login"})
    try:
        return decode_admin_token(token)
    except JWTError:
        raise HTTPException(status_code=303, headers={"Location": "/auth/login"})


def require_admin_api(request: Request) -> dict:
    """
    FastAPI dependency for JSON API routes (/admin/api/*) — returns 401 on failure
    so the React SPA can handle unauthenticated state rather than following a redirect.
    """
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        return decode_admin_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Session expired")


def verify_operator_credentials(email: str, password: str) -> bool:
    """Check operator email + password against env-var credentials."""
    return email == cfg.OPERATOR_EMAIL and password == cfg.OPERATOR_PASSWORD
