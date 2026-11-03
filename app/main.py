import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.database import Database
from app.scanner.rules import RULE_COUNT
from app.worker import ScanWorker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
SAMPLE_SPEC = Path(__file__).resolve().parent.parent / "examples" / "sample-openapi.yaml"


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
    title="API Vulnerability Checker",
    summary="Local, specification-based API security checks.",
    version="0.1.0",
    lifespan=lifespan,
)
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
