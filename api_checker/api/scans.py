import asyncio
import json
from typing import Any, cast
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from starlette.responses import JSONResponse

from api_checker.database import Database, QueueFullError, ScanInProgressError
from api_checker.exporters import to_github_annotations, to_html, to_junit, to_markdown, to_sarif
from api_checker.scanner.parser import MAX_SPEC_BYTES
from api_checker.worker import ScanWorker

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
async def create_scan(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json.")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
        if declared_length < 0:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")
        if declared_length > MAX_REQUEST_BYTES:
            raise HTTPException(
                status_code=413, detail="Request is too large. Specifications are limited to 16 MB."
            )

    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_REQUEST_BYTES:
            raise HTTPException(
                status_code=413, detail="Request is too large. Specifications are limited to 16 MB."
            )
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
        raise HTTPException(
            status_code=422, detail="The specification must contain valid Unicode text."
        ) from exc
    if spec_size > MAX_SPEC_BYTES:
        raise HTTPException(status_code=413, detail="Specifications are limited to 16 MB.")

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
async def list_scans(request: Request, limit: int = 50) -> dict[str, Any]:
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100.")
    scans = await asyncio.to_thread(request.app.state.database.list_scans, limit)
    return {"items": scans}


@router.get("/scans/diff")
async def diff_scans(request: Request, old_id: str, new_id: str) -> dict[str, Any]:
    if old_id == new_id:
        raise HTTPException(status_code=422, detail="Choose two different scans.")
    database: Database = request.app.state.database
    old_scan, new_scan = await asyncio.gather(
        asyncio.to_thread(database.get_scan, old_id),
        asyncio.to_thread(database.get_scan, new_id),
    )
    if old_scan is None or new_scan is None:
        raise HTTPException(status_code=404, detail="One or both scans were not found.")
    if old_scan.get("status") != "completed" or new_scan.get("status") != "completed":
        raise HTTPException(status_code=409, detail="Both scans must be completed.")
    old_findings = {item["fingerprint"]: item for item in old_scan.get("findings", [])}
    new_findings = {item["fingerprint"]: item for item in new_scan.get("findings", [])}
    added = [item for key, item in new_findings.items() if key not in old_findings]
    removed = [item for key, item in old_findings.items() if key not in new_findings]
    return {
        "old_scan": {"id": old_id, "name": old_scan.get("name")},
        "new_scan": {"id": new_id, "name": new_scan.get("name")},
        "added_findings": sorted(added, key=lambda item: (item.get("rule_id", ""), item.get("title", ""))),
        "removed_findings": sorted(removed, key=lambda item: (item.get("rule_id", ""), item.get("title", ""))),
        "summary": {"added": len(added), "removed": len(removed)},
    }


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request) -> dict[str, Any]:
    scan = await asyncio.to_thread(request.app.state.database.get_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return cast(dict[str, Any], scan)


@router.get("/scans/{scan_id}/export")
async def export_scan(scan_id: str, request: Request, format: str = "json") -> Response:
    normalized = format.lower()
    if normalized not in {"json", "sarif", "md", "html", "junit", "github"}:
        raise HTTPException(status_code=422, detail="format must be json, sarif, md, html, junit, or github.")
    scan = await asyncio.to_thread(request.app.state.database.get_scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if normalized == "json":
        return JSONResponse(
            content=scan,
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'},
        )
    if normalized == "sarif":
        return JSONResponse(
            content=to_sarif(scan),
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.sarif"'},
        )
    if normalized == "html":
        return Response(
            content=to_html(scan),
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.html"'},
        )
    if normalized == "junit":
        return Response(
            content=to_junit([scan]),
            media_type="application/xml; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.xml"'},
        )
    if normalized == "github":
        return Response(
            content=to_github_annotations([scan]),
            media_type="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-annotations.txt"'},
        )
    return Response(
        content=to_markdown(scan),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.md"'},
    )


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, request: Request) -> Response:
    await request.app.state.worker.cancel_scan(scan_id)
    deleted = await asyncio.to_thread(request.app.state.database.delete_scan, scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return Response(status_code=204)


@router.delete("/scans", status_code=204)
async def delete_scans(request: Request) -> Response:
    try:
        await asyncio.to_thread(request.app.state.database.delete_scans)
    except ScanInProgressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=204)
