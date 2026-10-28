import asyncio
import json
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.database import Database, QueueFullError
from app.worker import ScanWorker

MAX_SPEC_BYTES = 2 * 1024 * 1024
# JSON may expand the uploaded text when clients escape Unicode or control characters.
# Six times the spec limit covers JSON's maximum per-character escaping plus metadata.
MAX_REQUEST_BYTES = MAX_SPEC_BYTES * 6 + 16_000
router = APIRouter(prefix="/api/v1")


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="", max_length=120)
    target_url: str = Field(min_length=1, max_length=2048)
    filename: str = Field(min_length=1, max_length=255)
    spec_text: str = Field(min_length=1)

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        normalized = value.strip()
        if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in normalized):
            raise ValueError("The API base URL cannot contain spaces or control characters.")
        try:
            parsed = urlsplit(normalized)
            _ = parsed.port  # Validate the port even though this app does not connect to the URL.
        except ValueError as exc:
            raise ValueError("Enter a valid API base URL.") from exc
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise ValueError("Enter a complete http:// or https:// API base URL.")
        if parsed.username or parsed.password:
            raise ValueError("Do not put credentials in the target URL.")
        if parsed.query or parsed.fragment:
            raise ValueError("Use a base URL without query parameters or a fragment.")
        return normalized.rstrip("/")

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        name = value.replace("\\", "/").split("/")[-1].strip()
        if not name.lower().endswith((".json", ".yaml", ".yml")):
            raise ValueError("Choose an OpenAPI JSON or YAML file.")
        return name[:255]


@router.post("/scans", status_code=202)
async def create_scan(request: Request) -> dict:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
        if declared_length < 0:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")
        if declared_length > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Request is too large. Specifications are limited to 2 MB.")

    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="Request is too large. Specifications are limited to 2 MB.")
        raw.extend(chunk)
    try:
        payload = ScanCreate.model_validate(json.loads(raw))
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as exc:
        detail = (
            [{"loc": item["loc"], "msg": item["msg"]} for item in exc.errors()]
            if isinstance(exc, ValidationError)
            else "Request body must be valid UTF-8 JSON."
        )
        raise HTTPException(status_code=422, detail=detail) from exc
    try:
        spec_size = len(payload.spec_text.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise HTTPException(status_code=422, detail="The specification must contain valid Unicode text.") from exc
    if spec_size > MAX_SPEC_BYTES:
        raise HTTPException(status_code=413, detail="Specifications are limited to 2 MB.")

    database: Database = request.app.state.database
    worker: ScanWorker = request.app.state.worker
    try:
        scan = await asyncio.to_thread(
            database.create_scan,
            payload.name.strip() or payload.filename,
            payload.target_url,
            payload.filename,
            payload.spec_text,
        )
    except QueueFullError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    worker.notify()
    return scan


@router.get("/scans")
async def list_scans(request: Request, limit: int = 50) -> dict:
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100.")
    scans = await asyncio.to_thread(request.app.state.database.list_scans, limit)
    return {"items": scans}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request) -> dict:
    scan = await asyncio.to_thread(request.app.state.database.get_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan
