from __future__ import annotations

import asyncio
import subprocess
import sys
import threading

import pytest

from api_checker.database import Database
from api_checker.scanner import engine, limits
from api_checker.scanner.models import Finding
from api_checker.scanner.parser import MAX_DOCUMENT_NODES, MAX_YAML_ALIASES, SpecError, parse_spec
from api_checker.worker import ScanTimeoutError, ScanWorker


def test_yaml_alias_bomb_is_rejected_at_alias_limit():
    source = "openapi: 3.0.3\ninfo: {title: aliases, version: '1'}\npaths: {}\nbase: &base value\nitems:\n" + "".join("  - *base\n" for _ in range(MAX_YAML_ALIASES + 1))
    with pytest.raises(SpecError, match="aliases"):
        parse_spec(source, "aliases.yaml")


def test_524k_finding_shape_is_stopped_by_document_complexity_limit():
    count = 524_288
    properties = ",".join(f'"token{i}":{{}}' for i in range(count))
    source = ('{"openapi":"3.0.3","info":{"title":"large","version":"1"},"paths":{},'
              '"components":{"schemas":{"Response":{"type":"object","properties":{' + properties + '}}}}}')
    assert len(source.encode()) < 16 * 1024 * 1024
    with pytest.raises(SpecError, match=f"{MAX_DOCUMENT_NODES:,}-node"):
        parse_spec(source, "large.json")


def test_engine_caps_findings_and_reports_the_truncated_count(monkeypatch):
    many = [Finding("TEST-001", "test", "low", "low", "summary", "impact", "fix").to_dict()
            for _ in range(engine.MAX_FINDINGS + 5)]
    monkeypatch.setattr(engine, "run_rules", lambda *_args: [Finding(**finding) for finding in many])
    source = '{"openapi":"3.0.3","info":{"title":"cap","version":"1"},"paths":{}}'
    findings, summary = engine.analyze(source, "cap.json")
    assert len(findings) == engine.MAX_FINDINGS
    assert summary["truncated_findings"] == 1


def test_worker_timeout_kills_analysis_child(monkeypatch, tmp_path):
    worker = ScanWorker(Database(str(tmp_path / "worker.sqlite3")))
    real_popen = subprocess.Popen
    spawned = []

    def slow_process(*_args, **kwargs):
        proc = real_popen([sys.executable, "-c", "import time; time.sleep(5)"], **kwargs)
        spawned.append(proc)
        return proc

    monkeypatch.setattr("api_checker.worker.subprocess.Popen", slow_process)
    monkeypatch.setattr("api_checker.worker.SCAN_TIMEOUT_SECONDS", 0.02)
    with pytest.raises(ScanTimeoutError):
        worker._run_analysis_process(b"{}")
    assert spawned and spawned[0].poll() is not None


def test_worker_cancel_kills_the_owned_child(tmp_path):
    class Process:
        killed = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

    async def scenario():
        worker = ScanWorker(Database(str(tmp_path / "cancel.sqlite3")))
        process = Process()
        worker._current_scan_id = "active"
        worker._current_process = process
        await worker.cancel_scan("active")
        assert process.killed
        assert worker._cancelled_scan_id == "active"

    asyncio.run(scenario())


def test_memory_guard_exits_child_over_configured_cap(monkeypatch):
    called = threading.Event()

    class Memory:
        rss = 11

    class Process:
        def memory_info(self):
            return Memory()

    monkeypatch.setattr(limits.psutil, "Process", lambda _pid: Process())
    monkeypatch.setattr(limits.os, "_exit", lambda code: (called.set(), (_ for _ in ()).throw(limits.psutil.NoSuchProcess(1))))
    monitor = limits.start_memory_guard(10)
    assert called.wait(1)
    monitor.join(1)
    assert not monitor.is_alive()
