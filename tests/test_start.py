from __future__ import annotations

import sys

import start


def test_main_runs_migration_before_uvicorn(monkeypatch):
    events: list[tuple[str, object]] = []

    def fake_run(command, *, cwd, env, check):
        events.append(("migration", (command, cwd, env, check)))

    def fake_uvicorn_run(application, **kwargs):
        events.append(("uvicorn", (application, kwargs)))

    monkeypatch.setattr(start.subprocess, "run", fake_run)
    monkeypatch.setattr(start.uvicorn, "run", fake_uvicorn_run)

    start.main(["--host", "127.0.0.1", "--port", "8765"])

    assert [event[0] for event in events] == ["migration", "uvicorn"]
    migration_command, migration_cwd, _, migration_check = events[0][1]
    assert migration_command == [sys.executable, "-m", "alembic", "upgrade", "head"]
    assert migration_cwd == start.PROJECT_ROOT
    assert migration_check is True
    application, uvicorn_kwargs = events[1][1]
    assert application == "app.main:app"
    assert uvicorn_kwargs == {
        "app_dir": str(start.PROJECT_ROOT),
        "host": "127.0.0.1",
        "port": 8765,
        "reload": False,
    }
