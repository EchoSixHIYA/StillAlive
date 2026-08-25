"""Administrator login, dashboard shell, logout, and audit view."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.models.admin import AdminSession, AdminUser
from app.models.audit import AuditEvent
from app.models.grant import DownloadGrant
from app.models.integrity import IdentityIntegritySnapshot
from app.models.release import SealedRelease
from app.security.admin_auth import (
    ADMIN_CSRF_COOKIE,
    ADMIN_LOGIN_CSRF_COOKIE,
    ADMIN_SESSION_COOKIE,
    clear_auth_cookies,
    create_admin_session,
    decrypt_admin_totp,
    get_current_admin,
    issue_cookie,
    require_admin,
    validate_admin_csrf,
    valid_login_csrf,
    verify_password,
    verify_totp,
    token_digest,
)
from app.services.audit import record_audit
from app.services.setup import build_setup_checklist


router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _render_login(request: Request, settings, *, error: str | None = None, status_code: int = 200) -> HTMLResponse:
    token = secrets.token_urlsafe(32)
    response = templates.TemplateResponse(
        request=request,
        name="admin/login.html",
        context={"csrf_token": token, "error": error},
        status_code=status_code,
    )
    issue_cookie(response, name=ADMIN_LOGIN_CSRF_COOKIE, value=token, settings=settings, max_age=900)
    return response


def _admin_csrf_token(request: Request) -> str:
    return request.cookies.get(ADMIN_CSRF_COOKIE, "")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return _render_login(request, request.app.state.settings)


@router.post("/login", response_class=HTMLResponse, response_model=None)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(...),
    csrf_token: str = Form(...),
) -> HTMLResponse | RedirectResponse:
    settings = request.app.state.settings
    if not valid_login_csrf(request, csrf_token):
        return _render_login(request, settings, error="登录请求已失效，请刷新后重试。", status_code=403)

    username = username.strip()
    with request.app.state.session_factory() as db:
        admin = db.scalar(select(AdminUser).where(AdminUser.username == username))
        valid = False
        if admin is not None and admin.active:
            valid = verify_password(admin.password_hash, password)
            if valid:
                try:
                    valid = verify_totp(decrypt_admin_totp(admin, settings), totp)
                except Exception:
                    valid = False

        if not valid:
            record_audit(db, actor_type="admin", event_type="admin.login.failed", metadata={"method": "password_totp"})
            db.commit()
            return _render_login(request, settings, error="用户名、密码或动态验证码不正确。", status_code=401)

        session_token, csrf = create_admin_session(db, admin)
        record_audit(db, actor_type="admin", event_type="admin.login.success", actor_id=admin.id, target_type="admin", target_id=admin.id)
        db.commit()

    response = RedirectResponse("/admin", status_code=303)
    issue_cookie(response, name=ADMIN_SESSION_COOKIE, value=session_token, settings=settings, max_age=settings.admin_session_absolute_hours * 3600)
    issue_cookie(response, name=ADMIN_CSRF_COOKIE, value=csrf, settings=settings, max_age=settings.admin_session_absolute_hours * 3600)
    response.delete_cookie(ADMIN_LOGIN_CSRF_COOKIE, path="/")
    return response


@router.get("", response_class=HTMLResponse)
def dashboard(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        latest_events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(5)).all()
        setup = build_setup_checklist(db)
        snapshot = setup["latest_snapshot"]
        latest_release = db.scalar(select(SealedRelease).order_by(SealedRelease.created_at.desc()).limit(1))
    integrity_status = "尚未计算"
    blocking_pairs = warning_pairs = clusters = 0
    if isinstance(snapshot, IdentityIntegritySnapshot):
        integrity_status = {"pass": "通过", "warning": "提醒", "blocking": "阻塞", "stale": "待重算"}.get(snapshot.status, snapshot.status)
        blocking_pairs = snapshot.blocking_pair_count
        warning_pairs = snapshot.warning_pair_count
        clusters = snapshot.cluster_count
    context = {
        "admin": admin,
        "csrf_token": _admin_csrf_token(request),
        "metrics": {
            "active_people": setup["active_people"],
            "active_questions": setup["active_questions"],
            "integrity_status": integrity_status,
            "blocking_pairs": blocking_pairs,
            "warning_pairs": warning_pairs,
            "clusters": clusters,
            "public_delivery": "可用",
            "ready_releases": setup["ready_releases"],
            "latest_release": latest_release.version if latest_release else "暂无",
        },
        "latest_events": latest_events,
        "setup": setup,
    }
    return templates.TemplateResponse(request=request, name="admin/dashboard.html", context=context)


@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        setup = build_setup_checklist(db)
    return templates.TemplateResponse(
        request=request,
        name="admin/setup.html",
        context={"admin": admin, "csrf_token": _admin_csrf_token(request), "setup": setup},
    )


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, event_type: str | None = None, target: str | None = None, release: str | None = None, start: str | None = None, end: str | None = None, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        query = select(AuditEvent)
        if event_type:
            query = query.where(AuditEvent.event_type == event_type.strip()[:128])
        if target:
            query = query.where(AuditEvent.target_id == target.strip()[:128])
        if release:
            query = query.where(AuditEvent.target_type == "release", AuditEvent.target_id == release.strip()[:128])
        for raw_value, descending in ((start, False), (end, True)):
            if not raw_value:
                continue
            try:
                parsed = datetime.fromisoformat(raw_value)
            except ValueError:
                continue
            query = query.where(AuditEvent.created_at >= parsed if not descending else AuditEvent.created_at <= parsed)
        events = db.scalars(query.order_by(AuditEvent.created_at.desc()).limit(100)).all()
    return templates.TemplateResponse(
        request=request,
        name="admin/audit.html",
        context={"admin": admin, "csrf_token": _admin_csrf_token(request), "events": events, "json": json, "filters": {"event_type": event_type or "", "target": target or "", "release": release or "", "start": start or "", "end": end or ""}},
    )


@router.post("/logout")
def logout(request: Request, csrf_token: str = Form(...), admin: AdminUser = Depends(require_admin)) -> RedirectResponse:
    with request.app.state.session_factory() as db:
        if not validate_admin_csrf(request, db, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        raw_token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
        session = db.scalar(select(AdminSession).where(AdminSession.session_token_digest == token_digest(raw_token)))
        if session is not None:
            session.revoked_at = datetime.now(timezone.utc)
        record_audit(db, actor_type="admin", event_type="admin.logout", actor_id=admin.id, target_type="admin", target_id=admin.id)
        db.commit()
    response = RedirectResponse("/admin/login", status_code=303)
    clear_auth_cookies(response)
    return response


@router.get("/{section}", response_class=HTMLResponse)
def placeholder_section(request: Request, section: str, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    sections = {
        "people": "人物管理将在 Phase 2 开放。",
        "questions": "问题管理将在 Phase 2 开放。",
        "identity-integrity": "Identity Integrity 将在 Phase 4 开放。",
        "releases": "Sealed Release 用于离线恢复与长期保存，不控制线上 Public Delivery。",
        "simulator": "Simulator 用于在不改变线上 Session 的情况下预览识别结果。",
    }
    if section not in sections:
        raise HTTPException(status_code=404, detail="Not found")
    return templates.TemplateResponse(
        request=request,
        name="admin/placeholder.html",
        context={"admin": admin, "csrf_token": _admin_csrf_token(request), "section": section, "message": sections[section]},
    )


@router.post("/grants/{grant_id}/revoke")
def revoke_grant(request: Request, grant_id: str, csrf_token: str = Form(...), admin: AdminUser = Depends(require_admin)) -> RedirectResponse:
    with request.app.state.session_factory() as db:
        if not validate_admin_csrf(request, db, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        grant = db.get(DownloadGrant, grant_id)
        if grant is None:
            raise HTTPException(status_code=404, detail="Grant not found")
        grant.revoked_at = datetime.now(timezone.utc)
        record_audit(db, actor_type="admin", event_type="grant.revoked", actor_id=admin.id, target_type="grant", target_id=grant.id)
        db.commit()
    return RedirectResponse("/admin/audit?event_type=grant.revoked", status_code=303)
