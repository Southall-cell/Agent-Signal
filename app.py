"""Versioned FastAPI routes for the local agent trust scoring API."""
import os
import json
import hashlib
import hmac
from typing import Optional

from fastapi import APIRouter, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import FileResponse, JSONResponse

import agent_registry
from models import (
    AgentKeyRotationRequest,
    AgentKeyRotationResponse,
    AgentRegistrationRequest,
    AgentRegistrationResponse,
    ChallengeRequest,
    ChallengeResponse,
    HealthResponse,
    ScoreRequest,
    ScoreResponse,
    TrustReportResponse,
    VerifyIdentityRequest,
    VerifyIdentityResponse,
)
from rate_limit import PerKeyRateLimiter
from scoring import build_trust_report, score_agent
from security import (
    PUBLIC_KEYS,
    make_challenge,
    utc_text,
    verify_and_consume_challenge,
)

app = FastAPI(title="Score API", version="1.0.0")
router = APIRouter()
MAX_REQUEST_BODY_BYTES = 64 * 1024
WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(
        os.path.join(WEB_DIR, "index.html"),
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/assets/{asset_name}", include_in_schema=False)
def dashboard_asset(asset_name: str):
    if asset_name not in {"dashboard.css", "dashboard.js"}:
        raise HTTPException(status_code=404, detail="Asset not found.")
    return FileResponse(os.path.join(WEB_DIR, "assets", asset_name), headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


def _error_code(status_code: int) -> str:
    return {
        400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
        405: "method_not_allowed", 409: "conflict", 410: "expired", 413: "request_too_large",
        422: "invalid_request", 429: "rate_limited", 503: "temporarily_unavailable",
    }.get(status_code, "http_error")


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    message = exc.detail if isinstance(exc.detail, str) else "The request could not be completed."
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": _error_code(exc.status_code), "message": message, "details": []}, "detail": message},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    details = [
        {"field": ".".join(str(part) for part in error["loc"]), "message": error["msg"], "code": error["type"]}
        for error in exc.errors()
    ]
    message = "Request validation failed. See error.details for field-level guidance."
    return JSONResponse(status_code=422, content={
        "error": {"code": "invalid_request", "message": message, "details": details},
        "detail": message,
    })


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception):
    message = "An unexpected server error occurred."
    return JSONResponse(status_code=500, content={
        "error": {"code": "internal_error", "message": message, "details": []},
        "detail": message,
    })
RATE_LIMITER = PerKeyRateLimiter(
    max_requests=int(os.environ.get("API_RATE_LIMIT_MAX_REQUESTS", "60")),
    window_seconds=int(os.environ.get("API_RATE_LIMIT_WINDOW_SECONDS", "60")),
)
REGISTRATION_TOKEN = os.environ.get("REGISTRATION_TOKEN")
MIN_REGISTRATION_TOKEN_LENGTH = 32


def require_agent_key(agent_id: str, api_key: Optional[str]) -> str:
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="A valid API key for this agent is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    fingerprint = agent_registry.REGISTRY.key_fingerprint(agent_id, api_key)
    if fingerprint is None:
        raise HTTPException(
            status_code=401,
            detail="A valid API key for this agent is required.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    # Use the stable principal so rotating credentials cannot reset its budget.
    retry_after = RATE_LIMITER.check(agent_id)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for this API key. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    return fingerprint


class RequestBodyLimitMiddleware:
    """Cap request bodies even when Content-Length is absent or dishonest."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks = []
        total = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                message = f"Request body must not exceed {self.max_bytes} bytes."
                body = json.dumps({
                    "error": {"code": "request_too_large", "message": message, "details": []},
                    "detail": "Request body too large.",
                }).encode("utf-8")
                await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
            chunks.append(chunk)
            more_body = message.get("more_body", False)
        body = b"".join(chunks)
        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)


@router.get("/health", response_model=HealthResponse)
@router.get("/status", response_model=HealthResponse)
def health() -> HealthResponse:
    if not agent_registry.REGISTRY.health_check():
        raise HTTPException(status_code=503, detail="Agent registry is not ready.")
    return HealthResponse(status="ok", api_version="v1")


def require_registration_token(token: Optional[str]) -> None:
    if not REGISTRATION_TOKEN or len(REGISTRATION_TOKEN) < MIN_REGISTRATION_TOKEN_LENGTH:
        raise HTTPException(status_code=503, detail="Agent registration is disabled until a strong REGISTRATION_TOKEN is configured.")
    candidate = token if isinstance(token, str) else ""
    if not hmac.compare_digest(REGISTRATION_TOKEN, candidate):
        raise HTTPException(status_code=401, detail="A valid registration token is required.")
    retry_after = RATE_LIMITER.check("registration:" + hashlib.sha256(REGISTRATION_TOKEN.encode("utf-8")).hexdigest())
    if retry_after:
        raise HTTPException(status_code=429, detail="Registration rate limit exceeded. Try again later.", headers={"Retry-After": str(retry_after)})


@router.post("/agents/register", response_model=AgentRegistrationResponse, status_code=201)
def register_agent(
    request: AgentRegistrationRequest,
    x_registration_token: Optional[str] = Header(default=None, alias="X-Registration-Token"),
) -> AgentRegistrationResponse:
    require_registration_token(x_registration_token)
    try:
        api_key = agent_registry.REGISTRY.register(request.agent_id)
    except agent_registry.AgentAlreadyRegistered:
        raise HTTPException(status_code=409, detail="Agent is already registered.")
    return AgentRegistrationResponse(agent_id=request.agent_id, api_key=api_key)


@router.post("/agents/rotate-key", response_model=AgentKeyRotationResponse)
def rotate_agent_key(
    request: AgentKeyRotationRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> AgentKeyRotationResponse:
    require_agent_key(request.agent_id, x_api_key)
    try:
        new_key = agent_registry.REGISTRY.rotate(request.agent_id, x_api_key or "")
    except agent_registry.InvalidAgentKey:
        raise HTTPException(status_code=401, detail="The current API key is no longer valid.")
    return AgentKeyRotationResponse(agent_id=request.agent_id, api_key=new_key)


@router.post("/identity/challenge", response_model=ChallengeResponse)
def create_identity_challenge(
    request: ChallengeRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> ChallengeResponse:
    if request.agent_id not in PUBLIC_KEYS:
        raise HTTPException(status_code=404, detail="No public key is registered for this agent.")
    require_agent_key(request.agent_id, x_api_key)
    try:
        challenge_id, record = make_challenge(request.agent_id)
    except OverflowError:
        raise HTTPException(status_code=503, detail="Identity challenge capacity is temporarily full.")
    return ChallengeResponse(
        agent_id=request.agent_id,
        challenge_id=challenge_id,
        challenge=record.challenge,
        expires_at=utc_text(record.expires_at),
    )


@router.post("/identity/verify", response_model=VerifyIdentityResponse)
def verify_identity(
    request: VerifyIdentityRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> VerifyIdentityResponse:
    require_agent_key(request.agent_id, x_api_key)
    result, verified_at = verify_and_consume_challenge(request.challenge_id, request.agent_id, request.signature)
    if result == "wrong_agent":
        raise HTTPException(status_code=400, detail="Challenge belongs to a different agent.")
    if result == "missing":
        raise HTTPException(status_code=404, detail="Challenge was not found or has already been consumed.")
    if result == "consumed":
        raise HTTPException(status_code=409, detail="Challenge has already been used.")
    if result == "expired":
        raise HTTPException(status_code=410, detail="Challenge has expired.")
    if result == "invalid_signature":
        raise HTTPException(status_code=401, detail="Challenge signature is invalid.")

    return VerifyIdentityResponse(
        agent_id=request.agent_id,
        verified=True,
        reason="Ed25519 challenge signature verified.",
        checked_at=utc_text(verified_at),
    )


@router.get("/score", response_model=ScoreResponse)
def get_score(
    agent_id: str = Query(default="demo", min_length=1, max_length=128),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> ScoreResponse:
    require_agent_key(agent_id, x_api_key)
    return score_agent(ScoreRequest(agent_id=agent_id, incident_count=0))


@router.post("/score", response_model=ScoreResponse)
def post_score(
    request: ScoreRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> ScoreResponse:
    require_agent_key(request.agent_id, x_api_key)
    return score_agent(request)


@router.post("/score/report", response_model=TrustReportResponse)
def post_score_report(
    request: ScoreRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> TrustReportResponse:
    require_agent_key(request.agent_id, x_api_key)
    return build_trust_report(request)


app.include_router(router, prefix="/v1")
# Preserve pre-versioned paths while clients move to /v1.
app.include_router(router)
