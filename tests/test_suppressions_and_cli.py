import json

from api_checker.cli import main
from api_checker.scanner.engine import analyze


def test_operation_and_property_suppressions():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Suppressions", "version": "1"},
        "paths": {
            "/hooks": {
                "post": {
                    "x-security-ignore": [{"rule_id": "AUTH-001", "reason": "Reviewed by the API owner."}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "callback_url": {
                                            "type": "string",
                                            "x-security-ignore": [
                                                {"rule_id": "SSRF-001", "reason": "Validated by the gateway."}
                                            ],
                                        },
                                    },
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    findings, _ = analyze(json.dumps(spec), "spec.json")
    ids = {finding["rule_id"] for finding in findings}
    assert "AUTH-001" not in ids
    assert "SSRF-001" not in ids


def test_property_suppression_removes_only_the_matching_location():
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Suppression detail", "version": "1"},
        "paths": {
            "/hooks": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "callback_url": {
                                            "type": "string",
                                            "x-security-ignore": [
                                                {"rule_id": "SSRF-001", "reason": "Validated by the gateway."}
                                            ],
                                        },
                                        "webhook_url": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                }
            }
        },
    }
    findings, _ = analyze(json.dumps(spec), "spec.json")
    finding = next(item for item in findings if item["rule_id"] == "SSRF-001")
    assert finding["evidence"]["fields"] == ["webhook_url"]


def test_cli_writes_markdown_and_applies_fail_on(tmp_path, capsys):
    path = tmp_path / "spec.json"
    path.write_text(
        json.dumps(
            {
                "openapi": "3.0.3",
                "info": {"title": "CLI", "version": "1"},
                "paths": {"/x": {"get": {}}},
            }
        ),
        encoding="utf-8",
    )
    status = main(["scan", str(path), "--format", "md", "--fail-on", "medium"])
    output = capsys.readouterr().out
    assert status == 1
    assert "API security review" in output
