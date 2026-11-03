import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

import app.database as database_module
from app.database import Database, ScanInProgressError


def test_database_fingerprint_order_and_delete_lifecycle(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "scanner.sqlite3"))
    db.initialize()
    monkeypatch.setattr(database_module, "utc_now", lambda: "2026-01-01T00:00:00.000000+00:00")
    first = db.create_scan("a", "https://api.example", "a.yaml", "spec A")
    second = db.create_scan("b", "https://api.example", "b.yaml", "spec B")
    assert len(first["spec_sha256"]) == 64
    assert first["spec_sha256"] != second["spec_sha256"]
    assert [item["id"] for item in db.list_scans()] == sorted([first["id"], second["id"]], reverse=True)
    assert db.claim_next_scan()["id"] == min(first["id"], second["id"])
    with pytest.raises(ScanInProgressError):
        db.delete_scan(min(first["id"], second["id"]))
    db.initialize()  # startup recovers a scan left in running state
    assert db.get_scan(min(first["id"], second["id"]))["status"] == "queued"


def test_database_schema_version_and_upgrade_from_legacy_scans_table(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("""CREATE TABLE scans (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, target_url TEXT NOT NULL, spec_filename TEXT NOT NULL,
        source_spec TEXT, status TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT,
        completed_at TEXT, error TEXT, summary_json TEXT NOT NULL DEFAULT '{}'
    )""")
    connection.execute("PRAGMA user_version = 0")
    connection.commit()
    connection.close()

    db = Database(str(path))
    db.initialize()
    with db.connect() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        assert "spec_sha256" in columns


def test_database_concurrent_scan_creation(tmp_path):
    db = Database(str(tmp_path / "parallel.sqlite3"))
    db.initialize()
    with ThreadPoolExecutor(max_workers=4) as executor:
        scans = list(
            executor.map(
                lambda index: db.create_scan(str(index), "https://api.example", f"{index}.yaml", "{}"),
                range(4),
            )
        )
    assert len({scan["id"] for scan in scans}) == 4
    assert len(db.list_scans()) == 4


def test_clear_history_rejects_active_scans(tmp_path):
    db = Database(str(tmp_path / "active.sqlite3"))
    db.initialize()
    db.create_scan("active", "https://api.example", "a.yaml", "{}")
    with pytest.raises(ScanInProgressError):
        db.delete_scans()
