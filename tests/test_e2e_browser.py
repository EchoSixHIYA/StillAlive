"""SPEC-100 browser acceptance for the complete authoring-to-download flow."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

import httpx
import pyotp
import pytest
from playwright.sync_api import Page, expect


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "CorrectHorseBatteryStaple!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
CHALLENGE_ANSWER = "浏览器验收答案"


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@pytest.fixture
def e2e_server(tmp_path: Path):
    if os.environ.get("RUN_E2E") != "1":
        pytest.skip("set RUN_E2E=1 to run Playwright acceptance tests")

    port = _free_port()
    database = tmp_path / "app.db"
    env = os.environ.copy()
    env.update(
        {
            "APP_ENV": "test",
            "RELEASE_RUNTIME_MODE": "source_fallback",
            "DATABASE_URL": f"sqlite:///{database}",
            "MASTER_KEY": base64.b64encode(b"m" * 32).decode("ascii"),
            "ANSWER_PEPPER": "a" * 48,
            "SESSION_SECRET": "s" * 48,
            "ADMIN_AUTH_SECRET": "d" * 48,
            "ADMIN_BOOTSTRAP_USERNAME": "admin",
            "ADMIN_BOOTSTRAP_PASSWORD": PASSWORD,
            "ADMIN_BOOTSTRAP_TOTP_SECRET": TOTP_SECRET,
            "INTEGRITY_INCREMENTAL_SIMULATIONS_PER_PERSON": "5",
            "INTEGRITY_SEAL_SIMULATIONS_PER_PERSON": "10",
            "RATE_LIMIT_ENABLED": "false",
            "PUBLIC_BASE_URL": f"http://127.0.0.1:{port}",
            "VAULT_PATH": str(tmp_path / "vault"),
            "RELEASE_PATH": str(tmp_path / "releases"),
        }
    )
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
    log_path = tmp_path / "uvicorn.log"
    with log_path.open("w+", encoding="utf-8") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.flush()
                    raise RuntimeError(f"uvicorn exited early:\n{log_path.read_text(encoding='utf-8')}")
                try:
                    if httpx.get(f"{base_url}/health/ready", timeout=0.5).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            else:
                log.flush()
                raise RuntimeError(f"uvicorn did not become ready:\n{log_path.read_text(encoding='utf-8')}")
            yield base_url
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _login(page: Page, base_url: str) -> None:
    page.goto(f"{base_url}/admin/login")
    page.locator('input[name="username"]').fill("admin")
    page.locator('input[name="password"]').fill(PASSWORD)
    page.locator('input[name="totp"]').fill(pyotp.TOTP(TOTP_SECRET).now())
    page.get_by_role("button", name="登录").click()
    expect(page).to_have_url(f"{base_url}/admin")


def _create_person(page: Page, base_url: str, name: str) -> str:
    page.goto(f"{base_url}/admin/people/new")
    page.locator('input[name="display_name"]').fill(name)
    page.get_by_role("button", name="保存人物").click()
    expect(page).to_have_url(re.compile(rf"{re.escape(base_url)}/admin/people/[^/]+$"))
    return page.url.rsplit("/", 1)[1]


def _create_question(page: Page, base_url: str, text: str) -> None:
    page.goto(f"{base_url}/admin/questions/new")
    page.locator('textarea[name="text"]').fill(text)
    page.locator('select[name="privacy_level"]').select_option("L1_RELATION")
    page.locator('input[name="facet_tag"]').fill("fixture")
    page.get_by_role("button", name="保存问题").click()
    expect(page).to_have_url(f"{base_url}/admin/questions")
    expect(page.locator("body")).to_contain_text(text)


def _fill_same_traits(page: Page, base_url: str, person_id: str, value: str = "1") -> None:
    page.goto(f"{base_url}/admin/people/{person_id}")
    traits = page.locator(f'form[action="/admin/people/{person_id}/traits"]')
    expect(traits).to_be_visible()
    for field in traits.locator('input[name^="value_"]').all():
        field.fill(value)
    for field in traits.locator('input[name^="confidence_"]').all():
        field.fill("1")
    traits.get_by_role("button", name="保存识别答案").click()
    expect(page).to_have_url(f"{base_url}/admin/people/{person_id}")


@pytest.mark.e2e
def test_spec100_browser_authoring_to_download(page: Page, e2e_server: str) -> None:
    """Exercise the required browser-only admin and public delivery path."""

    base_url = e2e_server
    _login(page, base_url)
    person_a = _create_person(page, base_url, "浏览器验收角色A")
    person_b = _create_person(page, base_url, "浏览器验收角色B")
    for index in range(3):
        _create_question(page, base_url, f"浏览器共同经历问题{index + 1}？")
    _fill_same_traits(page, base_url, person_a)
    _fill_same_traits(page, base_url, person_b)

    page.goto(f"{base_url}/admin/identity-integrity")
    expect(page.locator("body")).to_contain_text("BLOCKING")
    page.get_by_role("link", name="开始解决").click()
    expect(page).to_have_url(f"{base_url}/admin/identity-integrity/wizard")
    pair_ids = re.findall(r"[0-9a-f-]{36}", page.locator(".page-intro .muted").inner_text())
    assert len(pair_ids) == 2
    person_a_is_metric_a = pair_ids[0] == person_a
    discriminator_a_value, discriminator_b_value = ("1", "-1") if person_a_is_metric_a else ("-1", "1")
    discriminator_answer = "yes"
    wizard_question = page.locator('form[action="/admin/identity-integrity/wizard/question"]')
    wizard_question.locator('textarea[name="text"]').fill("浏览器验收区分问题？")
    wizard_question.locator('select[name="privacy_level"]').select_option("L1_RELATION")
    wizard_question.locator('input[name="facet_tag"]').fill("work")
    wizard_question.locator('input[name="a_value"]').fill(discriminator_a_value)
    wizard_question.locator('input[name="b_value"]').fill(discriminator_b_value)
    wizard_question.get_by_role("button", name="预览并保存新问题").click()
    expect(page).to_have_url(f"{base_url}/admin/identity-integrity/wizard")
    expect(page.locator("body")).not_to_contain_text("仍需继续")

    page.goto(f"{base_url}/admin/people/{person_a}")
    challenge = page.locator(f'form[action="/admin/people/{person_a}/challenges"]')
    challenge.locator('textarea[name="prompt"]').fill("浏览器验收验证问题？")
    challenge.locator('textarea[name="answers"]').fill(CHALLENGE_ANSWER)
    challenge.get_by_role("button", name="保存 Verification Challenge").click()
    expect(page).to_have_url(re.compile(rf"{re.escape(base_url)}/admin/people/{re.escape(person_a)}(?:#.*)?$"))
    expect(page.locator("body")).to_contain_text("浏览器验收验证问题？")

    asset = page.locator(f'form[action="/admin/people/{person_a}/assets"]')
    asset.locator('input[type="file"]').set_input_files({"name": "browser-fixture.txt", "mimeType": "text/plain", "buffer": b"browser fixture payload"})
    asset.locator('input[name="display_name"]').fill("browser-fixture.txt")
    asset.get_by_role("button", name="上传加密 Asset").click()
    expect(page).to_have_url(re.compile(rf"{re.escape(base_url)}/admin/people/{re.escape(person_a)}(?:#.*)?$"))
    expect(page.locator("body")).to_contain_text("browser-fixture.txt")

    page.goto(base_url)
    page.get_by_role("button", name="开始识别").click()
    expect(page).to_have_url(re.compile(rf"{re.escape(base_url)}/play/[^/]+$"))
    for _ in range(12):
        title = page.locator("#play-title")
        title_text = title.inner_text()
        if "回答一个问题" in title_text:
            question_text = page.locator(".question-text").inner_text()
            button_value = discriminator_answer if "区分问题" in question_text else "yes"
            page.locator(f'form[data-question-id] button[value="{button_value}"]').click()
            expect(page.locator(".question-text")).not_to_have_text(question_text)
            continue
        if "我有一个猜测" in title_text:
            expect(page.locator(".question-text")).to_contain_text("浏览器验收角色A")
            page.get_by_role("button", name="是我", exact=True).click()
            expect(title).to_have_text("进入身份验证")
            break
        raise AssertionError(f"unexpected discovery state: {title_text}")
    else:
        raise AssertionError("discovery did not reach a single guess")

    page.locator('input[name="answer"]').fill(CHALLENGE_ANSWER)
    page.get_by_role("button", name="提交验证").click()
    expect(page.locator("body")).to_contain_text("身份验证通过")
    with page.expect_download() as download_info:
        page.locator(f'form[action*="/play/"][action*="/assets/"] button').click()
    download = download_info.value
    downloaded = Path(download.path()).read_bytes()
    assert downloaded == b"browser fixture payload"
