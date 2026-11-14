"""Resource guard for isolated analysis subprocesses."""

from __future__ import annotations

import os
import threading
import time

import psutil

MAX_SCAN_MEMORY_BYTES = 1024 * 1024 * 1024


def start_memory_guard(limit_bytes: int = MAX_SCAN_MEMORY_BYTES) -> threading.Thread:
    """Terminate this disposable process if its resident memory exceeds the cap."""
    process = psutil.Process(os.getpid())

    def monitor() -> None:
        while True:
            try:
                if process.memory_info().rss > limit_bytes:
                    os._exit(137)  # noqa: S404 - this process is the isolated scan child.
            except psutil.NoSuchProcess:
                return
            time.sleep(0.1)

    thread = threading.Thread(target=monitor, name="scan-memory-guard", daemon=True)
    thread.start()
    return thread
