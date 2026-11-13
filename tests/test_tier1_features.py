from __future__ import annotations

import json

import pytest

from api_checker.cli import main
from api_checker.scanner.engine import analyze
from api_checker.scanner.parser import SpecError, parse_spec
from api_checker.scanner.security_diff import build_security_diff


def _spec(security: list[dict[str, list[str]]] | None = None) -> dict[str, object]:
    document: dict[str, object] = {
        "openapi": "3.0.3",
        "info": {"title": "Example", "version": "1"},
        "paths": {
            "/items": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"access_token": {"type": "string"}},
                                    }
                                }
                            },
                        }
                    }
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"file": {"type": "string", "format": "binary"}},
                                }
                            }
                        }
                    },
                    "responses": {"204": {"description": "ok"}},
                },
            }
        },
    }
    if security is not None:
        document["security"] = security
    return document


def test_relative_file_references_are_bundled_and_scanned(tmp_path):
    root = tmp_path / "specs"
    root.mkdir()
    (root / "schemas.yaml").write_text(
        "Sensitive:\n  type: object\n  properties:\n    password: {type: string}\n", encoding="utf-8"
    )
    spec = _spec()
    spec["paths"]["/items"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "$ref": "./schemas.yaml#/Sensitive"
    }
    spec_path = root / "api.yaml"
    source = json.dumps(spec)
    spec_path.write_text(source, encoding="utf-8")
    parsed = parse_spec(source, "api.yaml", source_path=spec_path, reference_root=root)
    assert "schemas.yaml" in parsed["x-security-lint-ref-documents"]
    findings, _ = analyze(source, "api.yaml", source_path=spec_path, reference_root=root)
    assert "DATA-001" in {finding["rule_id"] for finding in findings}


def test_external_reference_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "specs"
    root.mkdir()
    (tmp_path / "outside.yaml").write_text("{}\n", encoding="utf-8")
    spec = _spec()
    spec["paths"]["/items"]["get"]["responses"]["200"]["$ref"] = "../outside.yaml"
    path = root / "api.yaml"
    with pytest.raises(SpecError, match="escapes"):
        parse_spec(json.dumps(spec), "api.yaml", source_path=path, reference_root=root)


def test_attack_surface_cli_reports_static_categories(tmp_path, capsys):
    path = tmp_path / "api.json"
    document = _spec()
    document["paths"]["/items"]["post"]["requestBody"]["content"]["multipart/form-data"]["schema"]["properties"]["callback_url"] = {
        "type": "string",
        "format": "uri",
        "pattern": "^https://trusted.example/",
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    assert main(["surface", str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["unauthenticated_endpoints"]
    assert report["write_operations"]
    assert report["file_upload_endpoints"]
    assert report["url_accepting_endpoints"]


def test_security_diff_reports_new_unauthenticated_operations(tmp_path, capsys):
    old_path, new_path = tmp_path / "old.json", tmp_path / "new.json"
    old = _spec([{"bearerAuth": []}])
    new = _spec([{"bearerAuth": []}])
    new["paths"]["/new"] = {
        "post": {"security": [], "responses": {"200": {"description": "ok"}}}
    }
    old_path.write_text(json.dumps(old), encoding="utf-8")
    new_path.write_text(json.dumps(new), encoding="utf-8")
    assert main(["diff", str(old_path), str(new_path)]) == 0
    diff = json.loads(capsys.readouterr().out)
    assert diff["new_unauthenticated_endpoints"] == ["POST /new"]


def test_security_diff_reports_removed_auth_and_weakened_scopes():
    old = _spec([{"oauth": ["read", "write"]}])
    new = _spec([{"oauth": ["read"]}])
    new["paths"]["/items"]["get"]["security"] = []
    result = build_security_diff([], [], old, new)
    assert any(item["type"] == "authentication_removed" for item in result["security_weakening"])
    assert any(item["type"] == "oauth_scopes_weakened" for item in result["security_weakening"])


def test_suppression_requires_reason_and_ignores_expired_entries():
    document = _spec()
    document["paths"]["/items"]["post"]["x-security-ignore"] = [
        {"rule_id": "AUTH-001", "reason": "Old exception", "expires": "2000-01-01"}
    ]
    findings, _ = analyze(json.dumps(document), "api.json")
    assert "AUTH-001" in {finding["rule_id"] for finding in findings}

    document["paths"]["/items"]["post"]["x-security-ignore"] = [{"rule_id": "AUTH-001"}]
    with pytest.raises(SpecError, match="reason"):
        parse_spec(json.dumps(document), "api.json")


def test_test_plan_export_is_shell_text_and_covers_finding_operations(tmp_path, capsys):
    path = tmp_path / "api.json"
    path.write_text(json.dumps(_spec()), encoding="utf-8")
    assert main(["scan", str(path), "--format", "curl"]) == 0
    output = capsys.readouterr().out
    assert "curl --silent" in output
    assert "--globoff" in output
    assert "Exporting this file sends no requests" in output
