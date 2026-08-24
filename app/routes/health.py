"""Liveness and readiness endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text


router = APIRouter(tags=["health"])
EXPECTED_MIGRATION_REVISION = "0010_sealed_release"


def _directory_status(path: Path) -> str:
    return "ok" if path.is_dir() else "error"


def _migration_status(request: Request) -> str:
    engine = request.app.state.db_engine
    try:
        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        return "ok" if revision == EXPECTED_MIGRATION_REVISION else "error"
    except Exception:
        return "error"


@router.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@router.get("/health/ready")
def ready(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    checks = {
        "database": "error",
        "vault": _directory_status(settings.vault_path),
        "release_storage": _directory_status(settings.release_path),
        "secrets": "ok",
        "migrations": "error",
    }
    try:
        with request.app.state.db_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
    checks["migrations"] = _migration_status(request)

    is_ready = all(value == "ok" for value in checks.values())
    status_code = 200 if is_ready else 503
    body = {"status": "ready" if is_ready else "not_ready", "checks": checks}
    return JSONResponse(status_code=status_code, content=body)
