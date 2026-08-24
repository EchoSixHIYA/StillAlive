"""FastAPI application factory and Phase 0 lifecycle."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
import uuid

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from app.config import Settings, configuration_error_message
from app.db.session import create_db_engine, create_session_factory
from app.routes.admin import router as admin_router
from app.routes.admin_authoring import router as admin_authoring_router
from app.routes.admin_api import router as admin_api_router
from app.routes.admin_integrity import router as admin_integrity_router
from app.routes.admin_releases import api_router as admin_releases_api_router
from app.routes.admin_releases import router as admin_releases_router
from app.routes.health import router as health_router
from app.routes.pages import router as pages_router
from app.routes.public_discovery import router as public_discovery_router
from app.security.admin_auth import ensure_bootstrap_admin
from app.security.rate_limit import InMemoryRateLimiter


APP_DIR = Path(__file__).resolve().parent
request_logger = logging.getLogger("still_alive.request")
request_logger.setLevel(logging.INFO)


def create_app() -> FastAPI:
    # Alembic's fileConfig can disable pre-existing loggers in test/process
    # embedding scenarios; request telemetry must remain explicitly enabled.
    request_logger.disabled = False

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            settings = Settings()
        except ValidationError as exc:
            raise RuntimeError(configuration_error_message(exc)) from None

        settings.ensure_runtime_directories()
        app.state.settings = settings
        app.state.db_engine = create_db_engine(settings.database_url)
        app.state.session_factory = create_session_factory(app.state.db_engine)
        app.state.rate_limiter = InMemoryRateLimiter()
        ensure_bootstrap_admin(app.state.db_engine, settings)
        try:
            yield
        finally:
            app.state.db_engine.dispose()

    application = FastAPI(
        title="Still Alive",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    @application.middleware("http")
    async def security_headers(request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        started = time.perf_counter()
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            status_code = 500
            raise
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", request.url.path)
            request_logger.info(
                json.dumps(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "level": "INFO",
                        "event": "request.completed",
                        "request_id": request_id,
                        "method": request.method,
                        "route": route_path,
                        "status_code": status_code,
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    },
                    sort_keys=True,
                )
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; object-src 'none'; style-src 'self'; script-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    application.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")
    application.include_router(admin_integrity_router)
    application.include_router(admin_authoring_router)
    application.include_router(admin_api_router)
    application.include_router(admin_releases_router)
    application.include_router(admin_releases_api_router)
    application.include_router(admin_router)
    application.include_router(health_router)
    application.include_router(public_discovery_router)
    application.include_router(pages_router)
    return application


app = create_app()
