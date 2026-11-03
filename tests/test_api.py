import asyncio
import json

from httpx import ASGITransport, AsyncClient

from app.main import app


def _scan_payload(name="api test"):
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "API test", "version": "1"},
        "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    return {
        "name": name,
        "target_url": "https://api.example",
        "filename": "api.yaml",
        "spec_text": json.dumps(spec),
    }


async def _wait_for_completion(client, scan_id):
    for _ in range(100):
        response = await client.get(f"/api/v1/scans/{scan_id}")
        assert response.status_code == 200
        scan = response.json()
        if scan["status"] in {"completed", "failed"}:
            return scan
        await asyncio.sleep(0.01)
    raise AssertionError("scan did not complete in time")


def test_api_scan_exports_and_delete(monkeypatch, tmp_path):
    monkeypatch.setenv("API_VULN_DB", str(tmp_path / "api.sqlite3"))

    async def scenario():
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                sample = await client.get("/api/v1/sample-spec")
                assert sample.status_code == 200
                assert "openapi" in sample.text
                created = await client.post("/api/v1/scans", json=_scan_payload())
                assert created.status_code == 202
                scan = await _wait_for_completion(client, created.json()["id"])
                assert scan["status"] == "completed"
                assert len(scan["spec_sha256"]) == 64

                assert (await client.get(f"/api/v1/scans/{scan['id']}/export?format=json")).status_code == 200
                sarif = await client.get(f"/api/v1/scans/{scan['id']}/export?format=sarif")
                assert sarif.status_code == 200
                assert sarif.json()["version"] == "2.1.0"
                markdown = await client.get(f"/api/v1/scans/{scan['id']}/export?format=md")
                assert "API security review" in markdown.text

                assert (await client.get(f"/api/v1/scans/{scan['id']}/export?format=xml")).status_code == 422
                assert (await client.delete(f"/api/v1/scans/{scan['id']}")).status_code == 204
                assert (await client.get(f"/api/v1/scans/{scan['id']}")).status_code == 404

    asyncio.run(scenario())


def test_api_delete_all_scans(monkeypatch, tmp_path):
    monkeypatch.setenv("API_VULN_DB", str(tmp_path / "clear.sqlite3"))

    async def scenario():
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                first = (await client.post("/api/v1/scans", json=_scan_payload("one"))).json()
                second = (await client.post("/api/v1/scans", json=_scan_payload("two"))).json()
                await _wait_for_completion(client, first["id"])
                await _wait_for_completion(client, second["id"])
                assert (await client.delete("/api/v1/scans")).status_code == 204
                assert (await client.get("/api/v1/scans")).json()["items"] == []

    asyncio.run(scenario())
