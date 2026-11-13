"""JSON, Markdown, and SARIF report serialization."""

from __future__ import annotations

import re
import shlex
from typing import Any

from api_checker import __version__


def to_sarif(scan: dict[str, Any]) -> dict[str, Any]:
    findings = scan.get("findings", [])
    rules: dict[str, dict[str, Any]] = {}
    results = []
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    for finding in findings:
        rule_id = str(finding.get("rule_id", "UNKNOWN"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.get("title", rule_id)},
                "fullDescription": {"text": finding.get("summary", finding.get("title", rule_id))},
                "helpUri": f"https://github.com/Kavin-arch/api-vulnerability-checker/blob/main/docs/rules/{rule_id}.md",
                "defaultConfiguration": {
                    "level": levels.get(str(finding.get("severity", "low")), "note")
                },
            },
        )
        locations = []
        evidence_locations = finding.get("evidence", {}).get("locations", [])
        if isinstance(evidence_locations, list):
            for item in evidence_locations:
                if not isinstance(item, dict):
                    continue
                pointer = item.get("pointer")
                location: dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": scan.get("spec_filename", "openapi.yaml")}
                    },
                    "properties": {"operation": item.get("operation")},
                }
                if isinstance(pointer, str):
                    location["logicalLocations"] = [{"kind": "member", "name": pointer}]
                    location["properties"]["jsonPointer"] = pointer
                start_line = item.get("start_line")
                if isinstance(start_line, int) and start_line > 0:
                    location["physicalLocation"]["region"] = {"startLine": start_line}
                locations.append(location)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": levels.get(str(finding.get("severity", "low")), "note"),
            "message": {"text": str(finding.get("summary", finding.get("title", "Finding")))},
            "properties": {
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "impact": finding.get("impact"),
                "remediation": finding.get("remediation"),
                "evidence": finding.get("evidence", {}),
                "affectedOperations": finding.get("affected_operations", []),
            },
        }
        fingerprint = finding.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            result["partialFingerprints"] = {"apiChecker/v1": fingerprint}
        if locations:
            result["locations"] = locations
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OpenAPI Security Lint",
                        "semanticVersion": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "scanId": scan.get("id"),
                    "specSha256": scan.get("spec_sha256"),
                    "summary": scan.get("summary", {}),
                },
            }
        ],
    }


def to_markdown(scan: dict[str, Any]) -> str:
    summary = scan.get("summary", {})
    lines = [
        f"# API security review: {scan.get('name', 'Scan')}",
        "",
        f"- **Status:** {scan.get('status', 'unknown')}",
        f"- **Specification:** {scan.get('spec_filename', 'unknown')}",
        f"- **SHA-256:** `{scan.get('spec_sha256', 'unknown')}`",
        f"- **Operations:** {summary.get('operations', 0)}",
        f"- **Findings:** {summary.get('findings', 0)}",
        "",
    ]
    findings = scan.get("findings", [])
    if not findings:
        lines.append("No findings were recorded.")
        return "\n".join(lines) + "\n"
    for finding in findings:
        lines.extend(
            [
                f"## [{str(finding.get('severity', 'info')).upper()}] {finding.get('title', finding.get('rule_id', 'Finding'))}",
                "",
                f"**Rule:** `{finding.get('rule_id', 'UNKNOWN')}` · **Confidence:** {finding.get('confidence', 'unknown')}",
                "",
                str(finding.get("summary", "")),
                "",
                f"**Potential impact:** {finding.get('impact', '')}",
                "",
                f"**Suggested review:** {finding.get('remediation', '')}",
                "",
            ]
        )
        operations = finding.get("affected_operations", [])
        if operations:
            lines.append("Affected operations:")
            lines.extend(f"- `{operation}`" for operation in operations)
            lines.append("")
        pointers = finding.get("evidence", {}).get("json_pointers", [])
        if pointers:
            lines.append("Specification locations:")
            lines.extend(f"- `{pointer}`" for pointer in pointers)
            lines.append("")
    return "\n".join(lines) + "\n"


def to_curl_test_plan(scan: dict[str, Any]) -> str:
    """Render manual dynamic-test candidates as a shell script; never execute them."""
    base_url = str(scan.get("target_url", "")).rstrip("/")
    findings = scan.get("findings", [])
    candidates: dict[tuple[str, str, str], str] = {}
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            rule_id = str(finding.get("rule_id", "UNKNOWN"))
            for operation in finding.get("affected_operations", []):
                if not isinstance(operation, str) or " " not in operation:
                    continue
                method, path = operation.split(" ", 1)
                if not path.startswith("/"):
                    continue
                candidates[(rule_id, method.upper(), path)] = str(finding.get("title", rule_id))

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Manual dynamic-test candidates generated from contract findings.",
        "# Exporting this file sends no requests. Review each candidate and substitute path placeholders.",
        f"# Specification: {scan.get('spec_filename', 'unknown')}",
        "",
    ]
    if base_url:
        lines.append(f"BASE_URL=${{BASE_URL:-{shlex.quote(base_url)}}}")
    else:
        lines.append(': "${BASE_URL:?Set BASE_URL to the API origin before running these tests}"')
    lines.extend(["", "# Add authentication headers or tokens only in your local test environment.", ""])
    if not candidates:
        lines.append("# No endpoint-specific dynamic-test candidates were found.")
        return "\n".join(lines) + "\n"

    for index, ((rule_id, method, path), title) in enumerate(sorted(candidates.items()), start=1):
        safe_title = re.sub(r"[\r\n]+", " ", title)
        lines.extend(
            [
                f"# Case {index}: {rule_id} - {safe_title}",
                f"# Review authorization and expected status/body for {method} {path}.",
                "curl --silent --show-error --include --globoff --max-time 15 \\",
                f"  --request {shlex.quote(method)} \\",
                f"  --url \"${{BASE_URL%/}}\"{shlex.quote(path)}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def to_attack_surface_markdown(surface: dict[str, Any]) -> str:
    lines = [f"# Attack surface: {surface.get('title', 'API')}", "", f"Operations: {surface.get('operations', 0)}", ""]
    sections = (
        ("Unauthenticated endpoints", "unauthenticated_endpoints"),
        ("Write operations", "write_operations"),
        ("File upload endpoints", "file_upload_endpoints"),
        ("URL accepting endpoints", "url_accepting_endpoints"),
        ("Admin looking endpoints", "admin_looking_endpoints"),
    )
    for title, key in sections:
        lines.extend([f"## {title}", ""])
        entries = surface.get(key, [])
        lines.extend(
            [f"- `{item.get('operation', item)}`" for item in entries]
            if entries
            else ["- None identified"]
        )
        lines.append("")
    return "\n".join(lines)


def to_security_diff_markdown(diff: dict[str, Any]) -> str:
    summary = diff.get("summary", {})
    lines = [
        f"# Security diff: {diff.get('old_spec', 'old spec')} → {diff.get('new_spec', 'new spec')}",
        "",
        f"- New findings: {summary.get('added', 0)}",
        f"- Removed findings: {summary.get('removed', 0)}",
        f"- Security weakenings: {summary.get('security_weakening', 0)}",
        f"- New unauthenticated endpoints: {summary.get('new_unauthenticated_endpoints', 0)}",
        "",
        "## Security weakening",
        "",
    ]
    weakenings = diff.get("security_weakening", [])
    lines.extend(
        [f"- `{item.get('operation')}`: {item.get('type')}{' (' + ', '.join(item.get('removed_scopes', [])) + ')' if item.get('removed_scopes') else ''}" for item in weakenings]
        if weakenings
        else ["- None identified"]
    )
    lines.extend(["", "## Added findings", ""])
    findings = diff.get("added_findings", [])
    lines.extend(
        [f"- `{finding.get('rule_id')}` {finding.get('title')} — {', '.join(finding.get('affected_operations', []))}" for finding in findings]
        if findings
        else ["- None"]
    )
    lines.extend(["", "## New unauthenticated endpoints", ""])
    endpoints = diff.get("new_unauthenticated_endpoints", [])
    lines.extend([f"- `{operation}`" for operation in endpoints] if endpoints else ["- None"])
    return "\n".join(lines) + "\n"
