"""Run database migrations and start the Still Alive web application."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

import uvicorn

from app.config import GLOBAL_CONFIG


PROJECT_ROOT = Path(__file__).resolve().parent


def _load_global_config() -> dict[str, object]:
    """Load tracked defaults plus an optional ignored local override module."""

    config = dict(GLOBAL_CONFIG)
    try:
        from start_local import GLOBAL_CONFIG as local_config
    except ModuleNotFoundError:
        return config
    if not isinstance(local_config, dict):
        raise SystemExit("start_local.py GLOBAL_CONFIG must be a dictionary")
    config.update(local_config)
    return config


def resolve_setting(env_name: str, parameter_value: object, global_config: dict[str, object], fallback: object = None) -> object:
    """Resolve one setting with environment > parameter > code global priority."""

    if env_name in os.environ:
        return os.environ[env_name]
    if parameter_value is not None:
        return parameter_value
    return global_config.get(env_name, fallback)


def _parse_port(raw_port: object) -> int:
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as exc:
        raise SystemExit("STILL_ALIVE_PORT/--port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("STILL_ALIVE_PORT/--port must be between 1 and 65535")
    return port


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate and start Still Alive.")
    parser.add_argument(
        "--host",
        default=None,
        help="Bind address (priority: environment > parameter > GLOBAL_CONFIG)",
    )
    parser.add_argument(
        "--port",
        default=None,
        type=int,
        help="Bind port (priority: environment > parameter > GLOBAL_CONFIG)",
    )
    parser.add_argument("--app-env", dest="app_env", default=None)
    parser.add_argument("--release-runtime-mode", dest="release_runtime_mode", default=None)
    parser.add_argument("--database-url", dest="database_url", default=None)
    parser.add_argument("--master-key", dest="master_key", default=None)
    parser.add_argument("--answer-pepper", dest="answer_pepper", default=None)
    parser.add_argument("--session-secret", dest="session_secret", default=None)
    parser.add_argument("--admin-auth-secret", dest="admin_auth_secret", default=None)
    parser.add_argument("--admin-bootstrap-username", dest="admin_bootstrap_username", default=None)
    parser.add_argument("--admin-bootstrap-password", dest="admin_bootstrap_password", default=None)
    parser.add_argument("--admin-bootstrap-totp-secret", dest="admin_bootstrap_totp_secret", default=None)
    parser.add_argument("--public-base-url", dest="public_base_url", default=None)
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable Uvicorn auto-reload for local development.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if sys.prefix == sys.base_prefix:
        raise SystemExit("Please run start.py with the project's virtual environment Python.")

    global_config = _load_global_config()
    parameter_values = {
        "STILL_ALIVE_HOST": args.host,
        "STILL_ALIVE_PORT": args.port,
        "APP_ENV": args.app_env,
        "RELEASE_RUNTIME_MODE": args.release_runtime_mode,
        "DATABASE_URL": args.database_url,
        "MASTER_KEY": args.master_key,
        "ANSWER_PEPPER": args.answer_pepper,
        "SESSION_SECRET": args.session_secret,
        "ADMIN_AUTH_SECRET": args.admin_auth_secret,
        "ADMIN_BOOTSTRAP_USERNAME": args.admin_bootstrap_username,
        "ADMIN_BOOTSTRAP_PASSWORD": args.admin_bootstrap_password,
        "ADMIN_BOOTSTRAP_TOTP_SECRET": args.admin_bootstrap_totp_secret,
        "PUBLIC_BASE_URL": args.public_base_url,
    }
    resolved_values = {
        name: resolve_setting(name, parameter_values[name], global_config)
        for name in parameter_values
    }
    for name, value in resolved_values.items():
        if value is not None:
            os.environ[name] = str(value)

    host = str(resolved_values["STILL_ALIVE_HOST"] or "127.0.0.1")
    port = _parse_port(resolved_values["STILL_ALIVE_PORT"] or 8000)
    os.chdir(PROJECT_ROOT)
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=PROJECT_ROOT,
        env=os.environ.copy(),
        check=True,
    )
    uvicorn.run(
        "app.main:app",
        app_dir=str(PROJECT_ROOT),
        host=host,
        port=port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
