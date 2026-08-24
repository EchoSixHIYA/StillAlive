"""SPEC-080 JSON Admin API acceptance tests."""

from __future__ import annotations

import re

import pyotp
from fastapi.testclient import TestClient


LOGIN_CSRF_PATTERN = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _login(client: TestClient) -> None:
    page = client.get("/admin/login")
    token = LOGIN_CSRF_PATTERN.search(page.text).group(1)
    response = client.post("/admin/login", data={"username": "admin", "password": PASSWORD, "totp": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303


def _csrf(client: TestClient) -> str:
    token = client.cookies.get("still_alive_admin_csrf")
    assert token
    return token


def test_spec080_admin_route_inventory(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    routes = {
        (path, method.upper())
        for path, operations in schema["paths"].items()
        for method in operations
    }
    expected = {
        ("/api/admin/people", "GET"),
        ("/api/admin/people", "POST"),
        ("/api/admin/questions", "POST"),
        ("/api/admin/people/{person_id}/traits", "POST"),
        ("/api/admin/people/{person_id}/challenges", "POST"),
        ("/api/admin/people/{person_id}/assets", "POST"),
        ("/api/admin/simulator", "POST"),
        ("/api/admin/identity-integrity", "GET"),
        ("/api/admin/identity-integrity/recompute", "POST"),
        ("/api/admin/identity-integrity/pairs", "GET"),
        ("/api/admin/identity-integrity/pairs/{pair_id}", "GET"),
        ("/api/admin/identity-integrity/clusters", "GET"),
        ("/api/admin/identity-integrity/clusters/{cluster_id}", "GET"),
        ("/api/admin/identity-integrity/preview-question", "POST"),
        ("/api/admin/releases", "GET"),
        ("/api/admin/releases", "POST"),
        ("/api/admin/releases/{release_id}", "GET"),
        ("/api/admin/releases/{release_id}/validate", "POST"),
        ("/api/admin/releases/{release_id}/revoke", "POST"),
        ("/api/admin/releases/{release_id}/export", "POST"),
        ("/api/admin/releases/{release_id}/export/{job_id}", "GET"),
        ("/api/admin/releases/{release_id}/export/{job_id}/download", "GET"),
    }
    assert expected <= routes
    assert not any(path.startswith("/api/admin/lifecycle/") or path.startswith("/api/admin/heartbeat/") for path, _ in routes)


def test_spec080_admin_authoring_and_integrity_json_api(client: TestClient) -> None:
    assert client.get("/api/admin/people", follow_redirects=False).status_code == 303
    _login(client)
    csrf = _csrf(client)

    person = client.post("/api/admin/people", json={"display_name": "API 测试角色A", "status": "active", "csrf_token": csrf})
    assert person.status_code == 201
    person_id = person.json()["person"]["id"]
    assert client.get("/api/admin/people").json()["people"][0]["id"] == person_id

    question = client.post("/api/admin/questions", json={"text": "API fixture question?", "privacy_level": "L1_RELATION", "answer_scale": "five_point", "weight": 1.0, "facet_tag": "api", "active": True, "csrf_token": csrf})
    assert question.status_code == 201
    question_id = question.json()["question"]["id"]
    traits = client.post(f"/api/admin/people/{person_id}/traits", json={"answers": [{"question_id": question_id, "value": 1.0, "confidence": 1.0, "source_note": "api note"}], "csrf_token": csrf})
    assert traits.status_code == 200 and traits.json()["updated"] == 1
    challenge = client.post(f"/api/admin/people/{person_id}/challenges", json={"prompt": "API verify?", "answers": ["api answer"], "csrf_token": csrf})
    assert challenge.status_code == 201
    asset = client.post(f"/api/admin/people/{person_id}/assets", data={"display_name": "api.txt", "csrf_token": csrf}, files={"file": ("api.txt", b"api payload", "text/plain")})
    assert asset.status_code == 201

    simulator = client.post("/api/admin/simulator", json={"target_person_id": person_id, "profile": "EXACT", "seed": 7, "csrf_token": csrf})
    assert simulator.status_code == 200
    integrity = client.get("/api/admin/identity-integrity")
    assert integrity.status_code == 200
    recompute = client.post("/api/admin/identity-integrity/recompute", headers={"X-CSRF-Token": csrf})
    assert recompute.status_code == 200
    assert client.get("/api/admin/identity-integrity/pairs").status_code == 200
    assert client.get("/api/admin/identity-integrity/clusters").status_code == 200
    preview = client.post("/api/admin/identity-integrity/preview-question", json={"pair_id": "missing", "question_id": question_id, "csrf_token": csrf})
    assert preview.status_code == 200 and preview.json()["preview"]["valid"] is False
