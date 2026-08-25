"""Anonymous Public Discovery API and server-rendered UI."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.models.discovery import DiscoverySession
from app.services.discovery import answer_session, create_session, decide_guess, session_payload
from app.services.grants import asset_list, consume_grant, content_disposition, create_grant
from app.services.verification import verification_payload, verify_session


router = APIRouter(tags=["public-discovery"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


class AnswerRequest(BaseModel):
    question_id: str = Field(min_length=1, max_length=64)
    answer: str = Field(min_length=1, max_length=32)


class GuessRequest(BaseModel):
    accepted: bool


class VerifyRequest(BaseModel):
    challenge_id: str | None = Field(default=None, max_length=64)
    answer: str = Field(min_length=1, max_length=500)


def _client_metadata(request: Request) -> tuple[str | None, str | None]:
    return (request.client.host if request.client else None, request.headers.get("user-agent"))


def _public_guard(request: Request, *, key: str, limit: int, window_seconds: float) -> None:
    origin = request.headers.get("origin")
    expected = str(request.app.state.settings.public_base_url).rstrip("/")
    if origin:
        try:
            origin_parts = urlsplit(origin.rstrip("/"))
            expected_parts = urlsplit(expected)
            origin_port = origin_parts.port or (443 if origin_parts.scheme == "https" else 80)
            expected_port = expected_parts.port or (443 if expected_parts.scheme == "https" else 80)
            same_origin = (
                origin_parts.scheme.lower(),
                (origin_parts.hostname or "").lower(),
                origin_port,
            ) == (
                expected_parts.scheme.lower(),
                (expected_parts.hostname or "").lower(),
                expected_port,
            )
        except ValueError:
            same_origin = False
        if not same_origin:
            raise HTTPException(status_code=403, detail="cross-site request rejected")
    if request.app.state.settings.rate_limit_enabled:
        request.app.state.rate_limiter.check(key, limit=limit, window_seconds=window_seconds)


def _get_session(request: Request, session_id: str) -> DiscoverySession:
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return session


def _create_public_session(request: Request) -> str:
    client_ip, user_agent = _client_metadata(request)
    with request.app.state.session_factory() as db:
        session = create_session(db, request.app.state.settings, client_ip=client_ip, user_agent=user_agent)
        db.commit()
        return session.id


@router.post("/api/public/sessions", status_code=201)
def api_create_session(request: Request) -> dict[str, object]:
    client_ip, _ = _client_metadata(request)
    _public_guard(request, key=f"create:{client_ip or 'unknown'}", limit=20, window_seconds=60)
    session_id = _create_public_session(request)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        assert session is not None
        return session_payload(db, session, request.app.state.settings)


@router.post("/api/public/sessions/{session_id}/answers")
def api_answer(request: Request, session_id: str, body: AnswerRequest) -> dict[str, object]:
    _public_guard(request, key=f"answer:{session_id}", limit=2, window_seconds=1)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return answer_session(db, session, request.app.state.settings, question_id=body.question_id, answer=body.answer)


@router.post("/api/public/sessions/{session_id}/guess")
def api_guess(request: Request, session_id: str, body: GuessRequest) -> dict[str, object]:
    _public_guard(request, key=f"answer:{session_id}", limit=2, window_seconds=1)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return decide_guess(db, session, request.app.state.settings, accepted=body.accepted)


@router.get("/api/public/sessions/{session_id}/challenge")
def api_challenge(request: Request, session_id: str) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return verification_payload(db, session, request.app.state.settings)


@router.post("/api/public/sessions/{session_id}/verify")
def api_verify(request: Request, session_id: str, body: VerifyRequest) -> dict[str, object]:
    _public_guard(request, key=f"verify:{session_id}", limit=5, window_seconds=60)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return verify_session(db, session, request.app.state.settings, challenge_id=body.challenge_id, answer=body.answer)


@router.get("/api/public/sessions/{session_id}/assets")
def api_assets(request: Request, session_id: str) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return asset_list(db, session, request.app.state.settings)


@router.post("/api/public/sessions/{session_id}/assets/{asset_id}/grant")
def api_grant(request: Request, session_id: str, asset_id: str) -> dict[str, object]:
    _public_guard(request, key=f"grant:{session_id}", limit=10, window_seconds=60)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        token, grant = create_grant(db, session, request.app.state.settings, asset_id=asset_id)
        db.commit()
        return {"download_url": f"/download/{token}", "expires_at": grant.expires_at.isoformat()}


@router.get("/api/public/sessions/{session_id}")
def api_get_session(request: Request, session_id: str) -> dict[str, object]:
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        return session_payload(db, session, request.app.state.settings)


@router.post("/start")
def start_discovery(request: Request) -> RedirectResponse:
    client_ip, _ = _client_metadata(request)
    _public_guard(request, key=f"create:{client_ip or 'unknown'}", limit=20, window_seconds=60)
    return RedirectResponse(f"/play/{_create_public_session(request)}", status_code=303)


@router.get("/play/{session_id}", response_class=HTMLResponse)
def play_page(request: Request, session_id: str) -> HTMLResponse:
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        payload = session_payload(db, session, request.app.state.settings)
    return templates.TemplateResponse(
        request=request,
        name="play.html",
        context={"session_id": session_id, "payload": payload, "state": payload["state"]},
    )


@router.post("/play/{session_id}/answer")
def play_answer(request: Request, session_id: str, question_id: str = Form(...), answer: str = Form(...)) -> RedirectResponse:
    _public_guard(request, key=f"answer:{session_id}", limit=2, window_seconds=1)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        answer_session(db, session, request.app.state.settings, question_id=question_id, answer=answer)
    return RedirectResponse(f"/play/{session_id}", status_code=303)


@router.post("/play/{session_id}/guess")
def play_guess(request: Request, session_id: str, accepted: bool = Form(...)) -> RedirectResponse:
    _public_guard(request, key=f"answer:{session_id}", limit=2, window_seconds=1)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        decide_guess(db, session, request.app.state.settings, accepted=accepted)
    return RedirectResponse(f"/play/{session_id}", status_code=303)


@router.post("/play/{session_id}/verify")
def play_verify(request: Request, session_id: str, challenge_id: str = Form(...), answer: str = Form(...)) -> Response:
    _public_guard(request, key=f"verify:{session_id}", limit=5, window_seconds=60)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        try:
            result = verify_session(db, session, request.app.state.settings, challenge_id=challenge_id, answer=answer)
        except HTTPException as exc:
            if exc.status_code != 429:
                raise
            result = verification_payload(db, session, request.app.state.settings, message="请先等待冷却时间结束，再提交下一次答案。")
        if result.get("state") == "VERIFICATION" and result.get("message"):
            return templates.TemplateResponse(
                request=request,
                name="play.html",
                context={"session_id": session_id, "payload": result, "state": result["state"]},
            )
    return RedirectResponse(f"/play/{session_id}", status_code=303)


@router.post("/play/{session_id}/assets/{asset_id}/grant")
def play_grant(request: Request, session_id: str, asset_id: str) -> RedirectResponse:
    _public_guard(request, key=f"grant:{session_id}", limit=10, window_seconds=60)
    with request.app.state.session_factory() as db:
        session = db.get(DiscoverySession, session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        token, _ = create_grant(db, session, request.app.state.settings, asset_id=asset_id)
        db.commit()
    return RedirectResponse(f"/download/{token}", status_code=303)


@router.get("/download/{token}")
def download(token: str, request: Request) -> Response:
    with request.app.state.session_factory() as db:
        asset, _person, plaintext, display_name = consume_grant(db, request.app.state.settings, token)
    return Response(content=plaintext, media_type=asset.mime_type, headers={"Content-Disposition": content_disposition(display_name), "Content-Length": str(len(plaintext))})
