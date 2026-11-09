import asyncio
import json
import logging
import os
import subprocess
import sys
import threading
from typing import Any

from api_checker.database import Database

logger = logging.getLogger(__name__)
SCAN_TIMEOUT_SECONDS = max(1, int(os.getenv("API_CHECKER_SCAN_TIMEOUT", "70")))


class ScanTimeoutError(TimeoutError):
    """A scan exceeded its hard wall-clock limit."""


class ScanWorker:
    """A single-process, SQLite-backed queue suitable for local development."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._current_scan_id: str | None = None
        self._current_process: subprocess.Popen[bytes] | None = None
        self._cancel_process = threading.Event()
        self._current_job_task: asyncio.Task[tuple[list[dict[str, Any]], dict[str, int]]] | None = None
        self._cancelled_scan_id: str | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="openapi-scan-worker")

    async def stop(self) -> None:
        if self._task is not None:
            self._cancel_process.set()
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def notify(self) -> None:
        self._wake.set()

    async def cancel_scan(self, scan_id: str) -> None:
        """Stop the active scan process, if this scan currently owns the worker."""
        if self._current_scan_id != scan_id:
            return
        self._cancelled_scan_id = scan_id
        self._cancel_process.set()
        process = self._current_process
        if process is not None and process.poll() is None:
            process.kill()
        job_task = self._current_job_task
        if job_task is not None and not job_task.done():
            job_task.cancel()
            try:
                await job_task
            except asyncio.CancelledError:
                pass

    async def _analyze_in_process(
        self, scan_id: str, source: str, filename: str | None
    ) -> tuple[list[dict[str, Any]], dict[str, int]]:
        request = json.dumps({"source": source, "filename": filename}).encode("utf-8")
        process_task = asyncio.create_task(asyncio.to_thread(self._run_analysis_process, request))
        try:
            stdout, stderr, returncode = await asyncio.shield(process_task)
        except asyncio.CancelledError:
            self._cancel_process.set()
            process = self._current_process
            if process is not None and process.poll() is None:
                process.kill()
            try:
                await process_task
            except Exception:
                pass
            raise
        if returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"Analysis process exited unexpectedly ({returncode}). {detail}")
        result = json.loads(stdout)
        if result.get("error"):
            raise ValueError(result["error"])
        return result["findings"], result["summary"]

    def _run_analysis_process(self, request: bytes) -> tuple[bytes, bytes, int]:
        """Run analysis outside the event loop for Windows loop compatibility."""
        process = subprocess.Popen(
            [sys.executable, "-m", "api_checker.scan_process"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._current_process = process
        try:
            if self._cancel_process.is_set():
                process.kill()
            try:
                stdout, stderr = process.communicate(request, timeout=SCAN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                stdout, stderr = process.communicate()
                raise ScanTimeoutError(
                    f"Scan exceeded the {SCAN_TIMEOUT_SECONDS}-second time limit."
                ) from exc
            return stdout, stderr, process.returncode if process.returncode is not None else -1
        finally:
            if self._current_process is process:
                self._current_process = None

    async def _run(self) -> None:
        while True:
            job = await asyncio.to_thread(self.database.claim_next_scan)
            if job is None:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=1.0)
                except TimeoutError:
                    pass
                continue

            self._cancel_process.clear()
            self._current_scan_id = job["id"]
            self._current_job_task = asyncio.create_task(
                self._analyze_in_process(
                    job["id"], job["source_spec"] or "", job.get("spec_filename")
                )
            )
            try:
                findings, summary = await self._current_job_task
                await asyncio.to_thread(self.database.complete_scan, job["id"], findings, summary)
            except asyncio.CancelledError:
                if self._cancelled_scan_id != job["id"]:
                    raise
            except Exception as exc:  # Store a concise error; full details stay in server logs.
                logger.error("Scan %s failed (%s)", job["id"], type(exc).__name__)
                await asyncio.to_thread(self.database.fail_scan, job["id"], str(exc))
            finally:
                self._current_scan_id = None
                self._current_job_task = None
                self._current_process = None
                self._cancel_process.clear()
                self._cancelled_scan_id = None
