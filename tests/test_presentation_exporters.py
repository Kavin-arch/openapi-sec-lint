from __future__ import annotations

from xml.etree import ElementTree as ET

from api_checker.exporters import to_github_annotations, to_html, to_junit


def _finding(severity: str, *, line: int = 7) -> dict[str, object]:
    return {
        "rule_id": "AUTH-001",
        "severity": severity,
        "title": '<script>alert("x")</script>',
        "summary": "Review this endpoint",
        "impact": "Unexpected access",
        "remediation": "Document authorization",
        "affected_operations": ["GET /items"],
        "evidence": {
            "json_pointers": ["/paths/~1items/get"],
            "locations": [{"start_line": line}],
        },
    }


def test_html_export_escapes_untrusted_scan_content_and_handles_empty_reports():
    report = to_html(
        {
            "name": '<img src=x onerror="alert(1)">',
            "spec_filename": "api<.yaml",
            "summary": {"findings": 1, "operations": 1},
            "findings": [_finding("high"), "malformed finding"],
        }
    )
    assert "<script>" not in report
    assert "&lt;script&gt;" in report
    assert "&lt;img" in report
    assert "GET /items" in report
    assert "No findings were recorded." in to_html({"findings": []})
    assert "No findings were recorded." in to_html([{"findings": []}])


def test_junit_export_maps_severities_and_escapes_xml():
    report = to_junit(
        [
            {
                "spec_filename": "api<&.yaml",
                "findings": [
                    _finding("critical"),
                    _finding("high"),
                    _finding("medium"),
                    _finding("low"),
                    "malformed finding",
                ],
            }
        ]
    )
    root = ET.fromstring(report)
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.attrib["failures"] == "2"
    assert suite.attrib["skipped"] == "1"
    assert suite.attrib["tests"] == "5"
    assert len(suite.findall("testcase/failure")) == 2
    assert len(suite.findall("testcase/skipped")) == 1


def test_github_annotations_escape_properties_and_choose_severity_command():
    report = to_github_annotations(
        [
            {
                "spec_filename": "api,one.yaml",
                "findings": [
                    _finding("high"),
                    _finding("medium", line=0),
                    _finding("low"),
                    "malformed finding",
                ],
            }
        ]
    )
    lines = report.splitlines()
    assert len(lines) == 3
    assert lines[0].startswith("::error file=api%2Cone.yaml,line=7,title=AUTH-001 · high::")
    assert lines[1].startswith("::warning file=api%2Cone.yaml,title=AUTH-001 · medium::")
    assert lines[2].startswith("::notice file=api%2Cone.yaml,line=7,title=AUTH-001 · low::")
    assert to_github_annotations([]) == ""
