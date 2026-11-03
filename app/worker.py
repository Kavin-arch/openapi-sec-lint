import asyncio
import logging

from app.database import Database
from app.scanner.engine import analyze

logger = logging.getLogger(__name__)


class ScanWorker:
    """A single-process, SQLite-backed queue suitable for local development."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

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

            try:
                findings, summary = await asyncio.to_thread(
                    analyze, job["source_spec"] or "", job.get("spec_filename")
                )
                await asyncio.to_thread(self.database.complete_scan, job["id"], findings, summary)
            except Exception as exc:  # Store a concise error; full details stay in server logs.
                logger.error("Scan %s failed (%s)", job["id"], type(exc).__name__)
                await asyncio.to_thread(self.database.fail_scan, job["id"], str(exc))
