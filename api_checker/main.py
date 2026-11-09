import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import Response

from api_checker import __version__
from api_checker.api import router
from api_checker.database import Database
from api_checker.scanner.rules import RULE_COUNT
from api_checker.worker import ScanWorker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_DIR = PACKAGE_DIR / "static"
SAMPLE_SPEC = PACKAGE_DIR / "examples" / "sample-openapi.yaml"
def _allowed_hosts() -> list[str]:
    configured = os.getenv("API_CHECKER_ALLOWED_HOSTS")
    if configured:
        return [host.strip() for host in configured.split(",") if host.strip()]
    return ["localhost", "127.0.0.1", "::1"]


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    database = Database()
    database.initialize()
    worker = ScanWorker(database)
    application.state.database = database
    application.state.worker = worker
    worker.start()
    try:
        yield
    finally:
        await worker.stop()


app = FastAPI(
    title="OpenAPI Security Lint",
    summary="Local security linting for OpenAPI and Swagger specifications.",
    version=__version__,
    lifespan=lifespan,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts())


@app.middleware("http")
async def add_security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    return response


app.include_router(router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str | int]:
    return {"status": "ok", "mode": "offline-spec-analysis", "checks": RULE_COUNT}


@app.get("/api/v1/sample-spec", include_in_schema=False)
async def sample_spec() -> FileResponse:
    return FileResponse(SAMPLE_SPEC, media_type="text/yaml", filename="sample-openapi.yaml")
