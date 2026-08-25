"""Administrator Recovery Key and Sealed Release manager."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from pathlib import Path
import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.models.admin import AdminUser
from app.models.release import RecoveryKeyRecord, SealedRelease
from app.security.admin_auth import decrypt_admin_totp, require_admin, validate_admin_csrf, verify_password, verify_totp
from app.services.audit import record_audit
from app.services.recovery import create_recovery_record, active_recovery_record
from app.services.releases import ReleaseGateError, build_release, evaluate_gates, validate_existing_release


router = APIRouter(prefix="/admin", tags=["admin-releases"])
api_router = APIRouter(prefix="/api/admin", tags=["admin-releases"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


class ReleaseCreateRequest(BaseModel):
    version: str = Field(min_length=1, max_length=128)
    recovery_key: str = Field(min_length=32, max_length=256)
    csrf_token: str | None = None


class ReleaseValidateRequest(BaseModel):
    recovery_key: str = Field(min_length=32, max_length=256)
    csrf_token: str | None = None


class ReleaseRevokeRequest(BaseModel):
    csrf_token: str | None = None


class ReleaseExportRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)
    totp: str = Field(min_length=1, max_length=32)
    csrf_token: str | None = None


def _csrf(request: Request) -> str:
    return request.cookies.get("still_alive_admin_csrf", "")


def _require_csrf(request: Request, token: str | None) -> None:
    with request.app.state.session_factory() as db:
        if not validate_admin_csrf(request, db, token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")


def _release_payload(release: SealedRelease) -> dict[str, object]:
    return {
        "id": release.id,
        "version": release.version,
        "status": release.status,
        "integrity_snapshot_id": release.integrity_snapshot_id,
        "recovery_key_id": release.recovery_key_id,
        "manifest_sha256": release.manifest_sha256,
        "archive_path": release.archive_path,
        "created_at": release.created_at.isoformat(),
        "validated_at": release.validated_at.isoformat() if release.validated_at else None,
        "error": release.error_message,
    }


def _api_csrf(request: Request, token: str | None) -> None:
    _require_csrf(request, token or request.headers.get("x-csrf-token"))


def _job_token(request: Request, release_id: str, admin_id: str) -> str:
    issued = str(int(time.time()))
    payload = f"{release_id}:{admin_id}:{issued}".encode("utf-8")
    signature = hmac.new(request.app.state.settings.admin_auth_secret.get_secret_value().encode("utf-8"), payload, hashlib.sha256).hexdigest()
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{encoded}.{signature}"


def _decode_job_token(request: Request, token: str, release_id: str, admin_id: str) -> None:
    try:
        encoded, signature = token.split(".", 1)
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii"))
        expected = hmac.new(request.app.state.settings.admin_auth_secret.get_secret_value().encode("utf-8"), payload, hashlib.sha256).hexdigest()
        token_release, token_admin, issued = payload.decode("utf-8").split(":", 2)
        valid_time = int(time.time()) - int(issued) <= 3600
    except (ValueError, TypeError, UnicodeDecodeError):
        valid_time = False
        expected = ""
        token_release = token_admin = ""
    if not valid_time or not hmac.compare_digest(signature, expected) or token_release != release_id or token_admin != admin_id:
        raise HTTPException(status_code=404, detail="export job not found")


@api_router.get("/releases")
def api_releases(request: Request, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        releases = db.scalars(select(SealedRelease).order_by(SealedRelease.created_at.desc())).all()
        gates = evaluate_gates(db, request.app.state.db_engine, request.app.state.settings)
        recovery_configured = active_recovery_record(db) is not None
    return {"releases": [_release_payload(release) for release in releases], "gates": [gate.as_dict() for gate in gates], "recovery_key_configured": recovery_configured}


@api_router.post("/releases", status_code=201)
def api_release_create(request: Request, body: ReleaseCreateRequest, admin: AdminUser = Depends(require_admin)) -> JSONResponse:
    _api_csrf(request, body.csrf_token)
    try:
        release = build_release(request.app.state.db_engine, request.app.state.settings, version=body.version, recovery_key=body.recovery_key, actor_id=admin.id)
    except ReleaseGateError as exc:
        return JSONResponse(status_code=409, content={"error": "sealed release gate failed", "gates": [gate.as_dict() for gate in exc.gates]})
    return JSONResponse(status_code=201, content={"release": _release_payload(release)})


@api_router.get("/releases/{release_id}")
def api_release_detail(request: Request, release_id: str, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        if release is None:
            raise HTTPException(status_code=404, detail="Release not found")
        gates = evaluate_gates(db, request.app.state.db_engine, request.app.state.settings)
    return {"release": _release_payload(release), "gates": [gate.as_dict() for gate in gates]}


@api_router.post("/releases/{release_id}/validate")
def api_release_validate(request: Request, release_id: str, body: ReleaseValidateRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _api_csrf(request, body.csrf_token)
    release = validate_existing_release(request.app.state.db_engine, request.app.state.settings, release_id=release_id, recovery_key=body.recovery_key, actor_id=admin.id)
    return {"release": _release_payload(release)}


@api_router.post("/releases/{release_id}/revoke")
def api_release_revoke(request: Request, release_id: str, body: ReleaseRevokeRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _api_csrf(request, body.csrf_token)
    with request.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        if release is None:
            raise HTTPException(status_code=404, detail="Release not found")
        release.status = "revoked"
        record_audit(db, actor_type="admin", event_type="sealed_release.revoked", actor_id=admin.id, target_type="release", target_id=release.id)
        db.commit()
        db.refresh(release)
    return {"release": _release_payload(release)}


@api_router.post("/releases/{release_id}/export", status_code=202)
def api_release_export(request: Request, release_id: str, body: ReleaseExportRequest, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _api_csrf(request, body.csrf_token)
    with request.app.state.session_factory() as db:
        if not verify_password(admin.password_hash, body.password) or not verify_totp(decrypt_admin_totp(admin, request.app.state.settings), body.totp):
            raise HTTPException(status_code=403, detail="recent re-authentication required")
        release = db.get(SealedRelease, release_id)
        if release is None or release.status != "ready" or not release.archive_path:
            raise HTTPException(status_code=409, detail="ready release required")
        archive = Path(release.archive_path).resolve()
        if archive.parent != request.app.state.settings.release_path.resolve() or not archive.is_file():
            raise HTTPException(status_code=404, detail="release archive not found")
        job_id = _job_token(request, release.id, admin.id)
        record_audit(db, actor_type="admin", event_type="sealed_release.exported", actor_id=admin.id, target_type="release", target_id=release.id)
        db.commit()
    return {"job_id": job_id, "status": "completed", "download_url": f"/api/admin/releases/{release_id}/export/{job_id}/download", "manifest_sha256": release.manifest_sha256}


@api_router.get("/releases/{release_id}/export/{job_id}")
def api_release_export_status(request: Request, release_id: str, job_id: str, admin: AdminUser = Depends(require_admin)) -> dict[str, object]:
    _decode_job_token(request, job_id, release_id, admin.id)
    with request.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        if release is None or release.status != "ready":
            raise HTTPException(status_code=404, detail="export job not found")
    return {"job_id": job_id, "status": "completed", "download_url": f"/api/admin/releases/{release_id}/export/{job_id}/download"}


@api_router.get("/releases/{release_id}/export/{job_id}/download")
def api_release_export_download(request: Request, release_id: str, job_id: str, admin: AdminUser = Depends(require_admin)) -> FileResponse:
    _decode_job_token(request, job_id, release_id, admin.id)
    with request.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        if release is None or release.status != "ready" or not release.archive_path:
            raise HTTPException(status_code=404, detail="export job not found")
        archive = Path(release.archive_path).resolve()
        if archive.parent != request.app.state.settings.release_path.resolve() or not archive.is_file():
            raise HTTPException(status_code=404, detail="release archive not found")
    return FileResponse(archive, media_type="application/zip", filename=archive.name)


@router.get("/recovery-key", response_class=HTMLResponse)
def recovery_key_page(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        record = active_recovery_record(db)
    return templates.TemplateResponse(request=request, name="admin/recovery_key.html", context={"admin": admin, "csrf_token": _csrf(request), "record": record, "recovery_key": None})


@router.post("/recovery-key", response_class=HTMLResponse)
def recovery_key_create(
    request: Request,
    recovery_key: str = Form(""),
    confirm_recovery_key: str = Form(""),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> HTMLResponse:
    _require_csrf(request, csrf_token)
    value = "".join(recovery_key.strip().split()) or secrets.token_urlsafe(32)
    if value != "".join(confirm_recovery_key.strip().split()) and recovery_key.strip():
        raise HTTPException(status_code=422, detail="recovery key confirmation does not match")
    with request.app.state.session_factory() as db:
        previous = active_recovery_record(db)
        record = create_recovery_record(db, request.app.state.settings, value)
        record_audit(db, actor_type="admin", event_type="recovery_key.rotated" if previous else "recovery_key.created", actor_id=admin.id, target_type="recovery_key", target_id=record.key_id)
        db.commit()
    return templates.TemplateResponse(request=request, name="admin/recovery_key.html", context={"admin": admin, "csrf_token": _csrf(request), "record": record, "recovery_key": value})


def _release_context(request: Request, admin: AdminUser, *, gates=None, error: str | None = None) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        releases = db.scalars(select(SealedRelease).order_by(SealedRelease.created_at.desc())).all()
        recovery_record = active_recovery_record(db)
        if gates is None:
            gates = evaluate_gates(db, request.app.state.db_engine, request.app.state.settings)
    friendly_gates = [_friendly_gate(gate) for gate in gates]
    return {"admin": admin, "csrf_token": _csrf(request), "releases": releases, "recovery_record": recovery_record, "gates": friendly_gates, "error": error}


def _friendly_gate(gate) -> dict[str, object]:
    labels = {
        "integrity": ("身份完整性 / Identity Integrity", "去处理人物混淆待办", "/admin/identity-integrity"),
        "active_person_challenges": ("每个人物都有专属验证", "去配置缺少验证的人物", "/admin/people"),
        "verification_digests": ("验证答案完整", "去检查专属验证问题", "/admin/people"),
        "asset_roundtrip": ("遗产内容可安全读取", "去检查遗产内容", "/admin/people"),
        "vault": ("加密内容仓库可访问", "检查运行目录", "/admin"),
        "runtime_secrets": ("运行密钥已加载", "检查运行配置", "/admin"),
        "recovery_key": ("Recovery Key 已配置", "去保存 Recovery Key", "/admin/recovery-key"),
        "migration": ("数据库结构已同步", "检查数据库迁移", "/admin"),
        "dependencies": ("离线依赖清单完整", "检查项目依赖文件", "/admin"),
        "offline_runtime": ("离线恢复运行环境可构建", "检查离线运行环境", "/admin/releases"),
    }
    label, action, action_url = labels.get(gate.key, (gate.label, "查看封存配置", "/admin/releases"))
    return {
        "key": gate.key,
        "label": label,
        "passed": gate.passed,
        "detail": "已通过，可以继续。" if gate.passed else f"还不能封存：{action}。",
        "action": action if not gate.passed else "",
        "action_url": action_url,
    }


@router.get("/releases", response_class=HTMLResponse)
def releases_page(request: Request, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    return templates.TemplateResponse(request=request, name="admin/releases.html", context=_release_context(request, admin))


@router.post("/releases", response_class=HTMLResponse, response_model=None)
def release_create(
    request: Request,
    version: str = Form(...),
    recovery_key: str = Form(...),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> HTMLResponse | RedirectResponse:
    _require_csrf(request, csrf_token)
    try:
        release = build_release(request.app.state.db_engine, request.app.state.settings, version=version, recovery_key=recovery_key, actor_id=admin.id)
    except ReleaseGateError as exc:
        context = _release_context(request, admin, gates=exc.gates, error="Gate 未全部通过，线上 Public Delivery 未受影响。")
        return templates.TemplateResponse(request=request, name="admin/releases.html", context=context, status_code=409)
    return RedirectResponse(f"/admin/releases/{release.id}", status_code=303)


@router.get("/releases/{release_id}", response_class=HTMLResponse)
def release_detail(request: Request, release_id: str, admin: AdminUser = Depends(require_admin)) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        if release is None:
            raise HTTPException(status_code=404, detail="Release not found")
    return templates.TemplateResponse(request=request, name="admin/release_detail.html", context={"admin": admin, "csrf_token": _csrf(request), "release": release})


@router.post("/releases/{release_id}/revoke")
def release_revoke(request: Request, release_id: str, csrf_token: str = Form(...), admin: AdminUser = Depends(require_admin)) -> RedirectResponse:
    _require_csrf(request, csrf_token)
    with request.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        if release is None:
            raise HTTPException(status_code=404, detail="Release not found")
        release.status = "revoked"
        record_audit(db, actor_type="admin", event_type="sealed_release.revoked", actor_id=admin.id, target_type="release", target_id=release.id)
        db.commit()
    return RedirectResponse(f"/admin/releases/{release_id}", status_code=303)


@router.post("/releases/{release_id}/export")
def release_export(
    request: Request,
    release_id: str,
    password: str = Form(...),
    totp: str = Form(...),
    csrf_token: str = Form(...),
    admin: AdminUser = Depends(require_admin),
) -> FileResponse:
    _require_csrf(request, csrf_token)
    with request.app.state.session_factory() as db:
        if not verify_password(admin.password_hash, password) or not verify_totp(decrypt_admin_totp(admin, request.app.state.settings), totp):
            raise HTTPException(status_code=403, detail="recent re-authentication required")
        release = db.get(SealedRelease, release_id)
        if release is None or release.status != "ready" or not release.archive_path:
            raise HTTPException(status_code=409, detail="ready release required")
        archive = Path(release.archive_path).resolve()
        if archive.parent != request.app.state.settings.release_path.resolve() or not archive.is_file():
            raise HTTPException(status_code=404, detail="release archive not found")
        record_audit(db, actor_type="admin", event_type="sealed_release.exported", actor_id=admin.id, target_type="release", target_id=release.id)
        db.commit()
    return FileResponse(archive, media_type="application/zip", filename=archive.name)
