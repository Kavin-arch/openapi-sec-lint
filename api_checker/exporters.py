"""JSON, Markdown, and SARIF report serialization."""

from __future__ import annotations

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
