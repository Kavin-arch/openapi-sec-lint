import asyncio
import json
import logging
import os
import sys
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
        self._current_process: asyncio.subprocess.Process | None = None
        self._current_job_task: asyncio.Task[tuple[list[dict[str, Any]], dict[str, int]]] | None = None
        self._cancelled_scan_id: str | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="openapi-scan-worker")

    async def stop(self) -> None:
        if self._task is not None:
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
        process = self._current_process
        if process is not None and process.returncode is None:
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
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "api_checker.scan_process",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._current_process = process
        request = json.dumps({"source": source, "filename": filename}).encode("utf-8")
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(request), timeout=SCAN_TIMEOUT_SECONDS
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise ScanTimeoutError(
                f"Scan exceeded the {SCAN_TIMEOUT_SECONDS}-second time limit."
            ) from exc
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        finally:
            self._current_process = None
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"Analysis process exited unexpectedly ({process.returncode}). {detail}")
        result = json.loads(stdout)
        if result.get("error"):
            raise ValueError(result["error"])
        return result["findings"], result["summary"]

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
                self._cancelled_scan_id = None
