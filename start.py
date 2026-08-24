"""Run database migrations and start the Still Alive web application."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

import uvicorn


PROJECT_ROOT = Path(__file__).resolve().parent


def _env_port() -> int:
    raw_port = os.environ.get("STILL_ALIVE_PORT", "8000")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise SystemExit("STILL_ALIVE_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("STILL_ALIVE_PORT must be between 1 and 65535")
    return port


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate and start Still Alive.")
    parser.add_argument(
        "--host",
        default=os.environ.get("STILL_ALIVE_HOST", "127.0.0.1"),
        help="Bind address (default: STILL_ALIVE_HOST or 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        default=_env_port(),
        type=int,
        help="Bind port (default: STILL_ALIVE_PORT or 8000)",
    )
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
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
