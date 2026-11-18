"""FTT Data — FastAPI app.

Browsers encrypt everything (static/crypto.js). This server stores and serves opaque ciphertext,
enforces limits, TTLs and rate limits, and never sees keys, codes, filenames or plaintext.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.background import BackgroundTask
from starlette.datastructures import MutableHeaders

from config import BASE_DIR, CHUNK_OVERHEAD, Settings, load_rules
from ratelimit import RateLimiter
from storage import ID_PATTERN, DropStore, StoreError

MAX_JSON_BODY = 16 * 1024
NO_STORE = {"Cache-Control": "no-store"}

# All scripts and styles are self-hosted: third-party JS on an E2EE page could read the keys.
CSP = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: blob:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    )
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

DropId = Annotated[str, Path(pattern=ID_PATTERN)]
ChunkIndex = Annotated[int, Path(ge=0, le=100_000)]
OptionalHeader = Annotated[str | None, Header()]


class SecurityHeadersMiddleware:
    """Adds hardening headers to every response (pure ASGI, so request streaming is untouched)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers.setdefault(name, value)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class CreateDrop(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(pattern=ID_PATTERN)
    ttl: int
    burn: bool = False
    auth_hash: str = Field(pattern=r"^[0-9a-f]{64}$")  # SHA-256 of the receiver's proof-of-key token
    chunks: int = Field(ge=1)
    size: int = Field(ge=1)  # total ciphertext bytes the sender will upload
    manifest: str = Field(min_length=1, max_length=8192)  # base64 encrypted name/type/size


def validate_create(body: CreateDrop, s: Settings) -> None:
    if not s.ttl_min <= body.ttl <= s.ttl_max:
        raise HTTPException(422, f"Expiry must be between {s.ttl_min} and {s.ttl_max} seconds.")
    if body.chunks > s.max_chunks or body.size > s.max_drop_bytes:
        raise HTTPException(413, "This drop is larger than the server allows.")
    if not body.chunks * CHUNK_OVERHEAD <= body.size <= body.chunks * s.max_chunk_bytes:
        raise HTTPException(422, "Declared size does not match the chunk count.")
    try:
        manifest = base64.b64decode(body.manifest, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "Manifest must be base64.") from None
    if not CHUNK_OVERHEAD < len(manifest) <= s.max_manifest_bytes:
        raise HTTPException(422, "Manifest has an invalid size.")


async def read_body(request: Request, limit: int) -> bytes:
    """Read a request body, refusing it (413) as soon as it exceeds `limit` bytes."""
    declared = content_length(request)
    if declared is not None and declared > limit:
        raise HTTPException(413, "Request body too large.")
    body = bytearray()
    async for piece in request.stream():
        body += piece
        if len(body) > limit:
            raise HTTPException(413, "Request body too large.")
    return bytes(body)


def content_length(request: Request) -> int | None:
    value = request.headers.get("content-length")
    return int(value) if value and value.isdigit() else None


def create_app(settings: Settings | None = None, redis=None) -> FastAPI:
    settings = settings or Settings.from_env()
    redis = redis if redis is not None else aioredis.from_url(settings.redis_url, decode_responses=True)
    store = DropStore(redis, settings)
    limiter = RateLimiter(redis, settings)
    index_html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    public_config = {
        "chunk_size": settings.chunk_size,
        "max_text_bytes": settings.max_text_bytes,
        "max_file_bytes": settings.max_file_bytes,
        "max_chunks": settings.max_chunks,
        "ttl": {
            "presets": list(settings.ttl_presets),
            "default": settings.ttl_default,
            "min": settings.ttl_min,
            "max": settings.ttl_max,
        },
        "rules": load_rules(settings.rules_path),
    }

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        store.root.mkdir(parents=True, exist_ok=True)
        await store.sweep()  # Redis keeps nothing across restarts, so old chunk files are orphans
        sweeper = asyncio.create_task(store.run_sweeper())
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper

    app = FastAPI(title="FTT Data", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.limiter = limiter
    app.state.settings = settings
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(StoreError)
    async def store_error(_request: Request, exc: StoreError) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status, headers=NO_STORE)

    # ---------------------------------------------------------------- pages

    @app.get("/", include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse(index_html, headers=NO_STORE)

    @app.get("/r/{drop_id}", include_in_schema=False)
    async def receive_page(drop_id: str) -> HTMLResponse:
        # The decryption key sits in the URL #fragment, which browsers never send to us.
        return HTMLResponse(index_html, headers=NO_STORE)

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True}

    @app.get("/api/config")
    async def get_config() -> dict:
        return public_config

    # ---------------------------------------------------------------- upload

    @app.post("/api/drops", status_code=201, dependencies=[Depends(limiter.limit("create"))])
    async def create_drop(request: Request) -> JSONResponse:
        try:
            body = CreateDrop.model_validate_json(await read_body(request, MAX_JSON_BODY))
        except ValidationError as exc:
            err = exc.errors()[0]
            raise HTTPException(422, f"{'.'.join(map(str, err['loc'])) or 'body'}: {err['msg']}") from None
        validate_create(body, settings)
        result = await store.create(
            body.id,
            ttl=body.ttl,
            burn=body.burn,
            auth_hash=body.auth_hash,
            chunks=body.chunks,
            size=body.size,
            manifest=body.manifest,
        )
        return JSONResponse(result, status_code=201, headers=NO_STORE)

    @app.put("/api/drops/{drop_id}/chunks/{index}", status_code=204, dependencies=[Depends(limiter.limit("chunk"))])
    async def upload_chunk(
        request: Request, drop_id: DropId, index: ChunkIndex, x_upload_token: OptionalHeader = None
    ) -> Response:
        await store.put_chunk(drop_id, index, x_upload_token, request.stream(), content_length(request))
        return Response(status_code=204)

    @app.post("/api/drops/{drop_id}/complete", dependencies=[Depends(limiter.limit("chunk"))])
    async def complete_drop(drop_id: DropId, x_upload_token: OptionalHeader = None) -> JSONResponse:
        return JSONResponse(await store.complete(drop_id, x_upload_token), headers=NO_STORE)

    # ---------------------------------------------------------------- download

    @app.post("/api/drops/{drop_id}/open", dependencies=[Depends(limiter.limit("open"))])
    async def open_drop(
        drop_id: DropId, x_auth_token: OptionalHeader = None, x_claim: OptionalHeader = None
    ) -> JSONResponse:
        return JSONResponse(await store.open(drop_id, x_auth_token, claim=x_claim == "1"), headers=NO_STORE)

    @app.get("/api/drops/{drop_id}/chunks/{index}", dependencies=[Depends(limiter.limit("chunk"))])
    async def download_chunk(
        drop_id: DropId,
        index: ChunkIndex,
        x_auth_token: OptionalHeader = None,
        x_claim_token: OptionalHeader = None,
    ) -> FileResponse:
        path, burn = await store.chunk_for_read(drop_id, index, x_auth_token, x_claim_token)
        return FileResponse(
            path,
            media_type="application/octet-stream",
            headers={**NO_STORE, "Content-Disposition": "attachment"},
            background=BackgroundTask(store.mark_served, drop_id, index) if burn else None,
        )

    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
    return app


app = create_app()
