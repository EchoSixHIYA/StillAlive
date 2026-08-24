"""L-series Sealed Release and Recovery acceptance tests."""

from __future__ import annotations

import json
import re
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import zipfile

import httpx
import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.release import RecoveryKeyRecord, SealedRelease
from app.services.recovery import unwrap_recovery_secret, wrap_recovery_secret
from app.services.releases import evaluate_gates


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
RECOVERY_KEY = "fixture-recovery-key-0123456789-abcdef"


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _terminate_process_tree(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _login(client: TestClient) -> None:
    page = client.get("/admin/login")
    token = LOGIN_CSRF_PATTERN.search(page.text).group(1)
    response = client.post("/admin/login", data={"username": "admin", "password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    token = client.cookies.get("still_alive_admin_csrf")
    assert token
    return token


def test_l_recovery_wrapper_is_purpose_bound_and_does_not_store_key(configured_environment) -> None:
    payload = wrap_recovery_secret(b"fixture-secret", RECOVERY_KEY, purpose="master-key-recovery")
    assert unwrap_recovery_secret(payload, RECOVERY_KEY, purpose="master-key-recovery") == b"fixture-secret"
    try:
        unwrap_recovery_secret(payload, RECOVERY_KEY, purpose="answer-pepper-recovery")
    except ValueError:
        pass
    else:
        raise AssertionError("purpose confusion must fail")
    assert RECOVERY_KEY.encode("utf-8") not in payload


def test_l_gate_failure_does_not_block_public_session(client: TestClient) -> None:
    _login(client)
    page = client.get("/admin/releases")
    assert page.status_code == 200
    assert "FAIL" in page.text
    api_page = client.get("/api/admin/releases")
    assert api_page.status_code == 200
    api_create = client.post("/api/admin/releases", json={"version": "blocked-api", "recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)})
    assert api_create.status_code == 409
    assert any(gate["passed"] is False for gate in api_create.json()["gates"])
    assert client.post("/api/public/sessions", json={}).status_code == 201


def test_d10_blocking_integrity_rejects_release_but_public_remains_available(client: TestClient) -> None:
    _login(client)
    people = []
    for name in ("D10 角色A", "D10 角色B"):
        response = client.post("/admin/people", data={"display_name": name, "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
        assert response.status_code == 303
        people.append(response.headers["location"].rsplit("/", 1)[1])
    for index in range(3):
        response = client.post(
            "/admin/questions",
            data={"text": f"D10 common question {index}?", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": f"d10-{index}", "active": "on", "csrf_token": _csrf(client)},
            follow_redirects=False,
        )
        assert response.status_code == 303
    from app.models.identity import Question

    with client.app.state.session_factory() as db:
        questions = db.scalars(select(Question).order_by(Question.id)).all()
    for person_id in people:
        trait_data = {f"value_{question.id}": "1.0" for question in questions}
        trait_data.update({f"confidence_{question.id}": "1.0" for question in questions})
        trait_data["csrf_token"] = _csrf(client)
        response = client.post(f"/admin/people/{person_id}/traits", data=trait_data, follow_redirects=False)
        assert response.status_code == 303
    recompute = client.post("/admin/identity-integrity/recompute", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert recompute.status_code == 303

    page = client.post("/admin/releases", data={"version": "d10-blocked", "recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)})
    assert page.status_code == 409
    assert "Identity Integrity" in page.text and "FAIL" in page.text

    api = client.post("/api/admin/releases", json={"version": "d10-blocked-api", "recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)})
    assert api.status_code == 409
    integrity_gate = next(gate for gate in api.json()["gates"] if gate["key"] == "integrity")
    assert integrity_gate["passed"] is False
    public = client.post("/api/public/sessions", json={})
    assert public.status_code == 201
    assert public.json()["state"] == "QUESTION"


def test_l_strict_runtime_gate_is_explicit(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(client.app.state.settings, "release_runtime_mode", "strict")
    with client.app.state.session_factory() as db:
        runtime = next(gate for gate in evaluate_gates(db, client.app.state.db_engine, client.app.state.settings) if gate.key == "offline_runtime")
    if shutil.which("docker") is None:
        assert runtime.passed is False
        assert "strict mode" in runtime.detail


def _prepare_release_fixture(client: TestClient) -> None:
    _login(client)
    person_response = client.post("/admin/people", data={"display_name": "测试角色A", "status": "active", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert person_response.status_code == 303
    person_id = person_response.headers["location"].rsplit("/", 1)[1]
    for index in range(3):
        question_response = client.post("/admin/questions", data={"text": f"Fixture question {index}?", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": "1.0", "facet_tag": f"fixture-{index}", "active": "on", "csrf_token": _csrf(client)}, follow_redirects=False)
        assert question_response.status_code == 303
    from app.models.identity import Question

    with client.app.state.session_factory() as db:
        questions = db.scalars(select(Question).order_by(Question.id)).all()
        assert len(questions) == 3
    trait_data = {f"value_{question.id}": "1.0" for question in questions}
    trait_data.update({f"confidence_{question.id}": "1.0" for question in questions})
    trait_data["csrf_token"] = _csrf(client)
    trait_response = client.post(f"/admin/people/{person_id}/traits", data=trait_data, follow_redirects=False)
    assert trait_response.status_code == 303
    challenge_response = client.post(f"/admin/people/{person_id}/challenges", data={"prompt": "Fixture verification?", "answers": "fixture answer", "csrf_token": _csrf(client)}, follow_redirects=False)
    assert challenge_response.status_code == 303
    asset_response = client.post(f"/admin/people/{person_id}/assets", data={"display_name": "fixture.txt", "csrf_token": _csrf(client)}, files={"file": ("fixture.txt", b"release fixture", "text/plain")}, follow_redirects=False)
    assert asset_response.status_code == 303
    recovery_response = client.post("/admin/recovery-key", data={"recovery_key": RECOVERY_KEY, "confirm_recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)})
    assert recovery_response.status_code == 200
    assert RECOVERY_KEY in recovery_response.text
    with client.app.state.session_factory() as db:
        record = db.scalar(select(RecoveryKeyRecord))
        assert record is not None
        assert RECOVERY_KEY not in record.verification_digest
    recompute = client.post("/admin/identity-integrity/recompute", data={"csrf_token": _csrf(client)}, follow_redirects=False)
    assert recompute.status_code == 303


def test_l01_l02_l03_release_export_and_offline_restore(client: TestClient, monkeypatch, tmp_path: Path) -> None:
    if os.environ.get("RUN_OCI") == "1":
        try:
            docker_ready = shutil.which("docker") is not None and subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            docker_ready = False
        if not docker_ready:
            pytest.skip("RUN_OCI=1 requires a reachable Docker CLI")
        monkeypatch.setattr(client.app.state.settings, "release_runtime_mode", "strict")
    _prepare_release_fixture(client)
    created = client.post("/admin/releases", data={"version": "fixture-v1", "recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)}, follow_redirects=False)
    assert created.status_code == 303
    release_id = created.headers["location"].rsplit("/", 1)[1]
    with client.app.state.session_factory() as db:
        release = db.get(SealedRelease, release_id)
        assert release is not None and release.status == "ready"
        assert release.manifest_sha256
        archive = Path(release.archive_path)
    api_detail = client.get(f"/api/admin/releases/{release_id}")
    assert api_detail.status_code == 200
    assert api_detail.json()["release"]["status"] == "ready"
    api_validated = client.post(f"/api/admin/releases/{release_id}/validate", json={"recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)})
    assert api_validated.status_code == 200
    assert archive.is_file()
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        assert f"fixture-v1/README-FIRST.txt" in names
        assert f"fixture-v1/checksums.sha256" in names
        contents = b"".join(bundle.read(name) for name in names if not name.endswith("/"))
        assert RECOVERY_KEY.encode("utf-8") not in contents
    exported = client.post(f"/admin/releases/{release_id}/export", data={"password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": _csrf(client)})
    assert exported.status_code == 200
    assert exported.content.startswith(b"PK")
    api_export = client.post(f"/api/admin/releases/{release_id}/export", json={"password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": _csrf(client)})
    assert api_export.status_code == 202
    job = api_export.json()["job_id"]
    assert client.get(f"/api/admin/releases/{release_id}/export/{job}").json()["status"] == "completed"
    api_download = client.get(f"/api/admin/releases/{release_id}/export/{job}/download")
    assert api_download.status_code == 200 and api_download.content.startswith(b"PK")

    offline = tmp_path / "offline"
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(offline)
    restored_root = offline / "fixture-v1"
    verified = subprocess.run([sys.executable, "scripts/verify_release.py", str(restored_root)], check=True, capture_output=True, text=True)
    assert json.loads(verified.stdout)["status"] == "verified"
    recovery_key_file = tmp_path / "recovery-key.txt"
    recovery_key_file.write_text(RECOVERY_KEY, encoding="utf-8")
    port = _free_port()
    log_path = tmp_path / "restore-offline.log"
    with log_path.open("w+", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, str(restored_root / "scripts/restore_offline.py"), str(restored_root), "--recovery-key-file", str(recovery_key_file), "--host", "127.0.0.1", "--port", str(port)],
            cwd=restored_root / "source",
            env=dict(os.environ),
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.flush()
                    raise RuntimeError(f"offline restore exited early:\n{log_path.read_text(encoding='utf-8')}")
                try:
                    if httpx.get(f"{base_url}/health/ready", timeout=0.5).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            else:
                log.flush()
                raise RuntimeError(f"offline restore did not become ready:\n{log_path.read_text(encoding='utf-8')}")

            with httpx.Client(base_url=base_url) as restored:
                discovery = restored.post("/api/public/sessions").json()
                answer = discovery
                for _ in range(3):
                    if answer["state"] == "GUESS":
                        break
                    answer = restored.post(f"/api/public/sessions/{discovery['session_id']}/answers", json={"question_id": answer["question"]["id"], "answer": "yes"}).json()
                    time.sleep(0.6)
                assert answer["state"] == "GUESS"
                verification = restored.post(f"/api/public/sessions/{discovery['session_id']}/guess", json={"accepted": True}).json()
                assert verification["state"] == "VERIFICATION"
                challenge = restored.get(f"/api/public/sessions/{discovery['session_id']}/challenge").json()["challenge"]
                verified = restored.post(f"/api/public/sessions/{discovery['session_id']}/verify", json={"challenge_id": challenge["id"], "answer": "fixture answer"}).json()
                assert verified["state"] == "VERIFIED"
                assets = restored.get(f"/api/public/sessions/{discovery['session_id']}/assets").json()["assets"]
                grant = restored.post(f"/api/public/sessions/{discovery['session_id']}/assets/{assets[0]['id']}/grant").json()
                downloaded = restored.get(grant["download_url"])
                assert downloaded.status_code == 200
                assert downloaded.content == b"release fixture"
        finally:
            _terminate_process_tree(process)


def test_l_release_model_does_not_store_recovery_key(client: TestClient) -> None:
    _login(client)
    response = client.post("/admin/recovery-key", data={"recovery_key": RECOVERY_KEY, "confirm_recovery_key": RECOVERY_KEY, "csrf_token": _csrf(client)})
    assert response.status_code == 200
    with client.app.state.session_factory() as db:
        record = db.scalar(select(RecoveryKeyRecord))
        assert record is not None
        assert RECOVERY_KEY not in record.verification_digest
