"""Argon2id/TOTP administrator authentication and CSRF protection."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.admin import AdminSession, AdminUser, utc_now
from app.security.crypto import decrypt_secret, encrypt_secret
from app.services.audit import record_audit


PASSWORD_HASHER = PasswordHasher()
TOTP_CONTEXT = b"still-alive/admin-totp/v1"
ADMIN_SESSION_COOKIE = "still_alive_admin_session"
ADMIN_CSRF_COOKIE = "still_alive_admin_csrf"
ADMIN_LOGIN_CSRF_COOKIE = "still_alive_admin_login_csrf"


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def verify_totp(secret: str, code: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except (TypeError, ValueError):
        return False


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def cookie_is_secure(settings: Settings) -> bool:
    return str(settings.public_base_url).startswith("https://")


def issue_cookie(response, *, name: str, value: str, settings: Settings, max_age: int | None = None) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=True,
        secure=cookie_is_secure(settings),
        samesite="strict",
        path="/",
    )


def clear_auth_cookies(response) -> None:
    response.delete_cookie(ADMIN_SESSION_COOKIE, path="/")
    response.delete_cookie(ADMIN_CSRF_COOKIE, path="/")
    response.delete_cookie(ADMIN_LOGIN_CSRF_COOKIE, path="/")


def issue_login_csrf(response, settings: Settings) -> str:
    token = secrets.token_urlsafe(32)
    issue_cookie(response, name=ADMIN_LOGIN_CSRF_COOKIE, value=token, settings=settings, max_age=900)
    return token


def valid_login_csrf(request: Request, submitted_token: str) -> bool:
    cookie_token = request.cookies.get(ADMIN_LOGIN_CSRF_COOKIE, "")
    return bool(cookie_token and submitted_token and hmac.compare_digest(cookie_token, submitted_token))


def create_admin_session(db: Session, admin: AdminUser) -> tuple[str, str]:
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = utc_now()
    db.add(
        AdminSession(
            admin_user_id=admin.id,
            session_token_digest=token_digest(session_token),
            csrf_token_digest=token_digest(csrf_token),
            created_at=now,
            last_seen_at=now,
        )
    )
    return session_token, csrf_token


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def get_current_admin(request: Request, db: Session) -> AdminUser | None:
    raw_token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not raw_token:
        return None
    session = db.scalar(select(AdminSession).where(AdminSession.session_token_digest == token_digest(raw_token)))
    if session is None or session.revoked_at is not None:
        return None

    settings: Settings = request.app.state.settings
    now = datetime.now(timezone.utc)
    if now > _as_utc(session.created_at) + timedelta(hours=settings.admin_session_absolute_hours):
        session.revoked_at = now
        db.commit()
        return None
    if now > _as_utc(session.last_seen_at) + timedelta(minutes=settings.admin_session_idle_minutes):
        session.revoked_at = now
        db.commit()
        return None

    admin = db.get(AdminUser, session.admin_user_id)
    if admin is None or not admin.active:
        return None
    session.last_seen_at = now
    db.commit()
    return admin


def require_admin(request: Request) -> AdminUser:
    with request.app.state.session_factory() as db:
        admin = get_current_admin(request, db)
    if admin is None:
        next_path = request.url.path
        raise HTTPException(status_code=303, headers={"Location": f"/admin/login?next={next_path}"})
    return admin


def validate_admin_csrf(request: Request, db: Session, submitted_token: str | None) -> bool:
    cookie_token = request.cookies.get(ADMIN_CSRF_COOKIE, "")
    session_token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if not cookie_token or not session_token or not submitted_token:
        return False
    if not hmac.compare_digest(cookie_token, submitted_token):
        return False
    session = db.scalar(select(AdminSession).where(AdminSession.session_token_digest == token_digest(session_token)))
    return session is not None and hmac.compare_digest(session.csrf_token_digest, token_digest(cookie_token))


def ensure_bootstrap_admin(engine, settings: Settings) -> bool:
    """Create exactly one initial admin when explicitly configured.

    The plaintext bootstrap values are used only during this transaction; the
    database stores an Argon2id password hash and encrypted TOTP secret.
    """

    if not inspect(engine).has_table("admin_users"):
        return False
    if settings.admin_bootstrap_password is None or settings.admin_bootstrap_totp_secret is None:
        return False

    from sqlalchemy.orm import Session as OrmSession

    with OrmSession(engine) as db:
        if db.scalar(select(AdminUser.id).limit(1)) is not None:
            return False
        totp_secret = settings.admin_bootstrap_totp_secret.get_secret_value().strip().replace(" ", "")
        nonce, ciphertext = encrypt_secret(totp_secret, settings.master_key_bytes, context=TOTP_CONTEXT)
        admin = AdminUser(
            username=settings.admin_bootstrap_username,
            password_hash=hash_password(settings.admin_bootstrap_password.get_secret_value()),
            totp_secret_nonce=nonce,
            totp_secret_ciphertext=ciphertext,
        )
        db.add(admin)
        db.flush()
        record_audit(
            db,
            actor_type="system",
            event_type="admin.bootstrap.created",
            actor_id=admin.id,
            target_type="admin",
            target_id=admin.id,
        )
        db.commit()
        return True


def decrypt_admin_totp(admin: AdminUser, settings: Settings) -> str:
    return decrypt_secret(
        admin.totp_secret_ciphertext,
        admin.totp_secret_nonce,
        settings.master_key_bytes,
        context=TOTP_CONTEXT,
    )
