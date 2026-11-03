from typing import Any

from app.scanner.common import collect_suppressions
from app.scanner.parser import parse_spec
from app.scanner.rules import RULE_COUNT, operations, run_rules


def _apply_suppressions(findings: list[dict[str, Any]], spec: dict[str, Any]) -> list[dict[str, Any]]:
    suppressions = collect_suppressions(spec)
    if not suppressions:
        return findings

    visible: list[dict[str, Any]] = []
    for finding in findings:
        locations = finding.get("evidence", {}).get("locations", [])
        if not isinstance(locations, list) or not locations:
            visible.append(finding)
            continue
        kept = []
        kept_indexes: list[int] = []
        for index, item in enumerate(locations):
            if not isinstance(item, dict):
                kept.append(item)
                kept_indexes.append(index)
                continue
            operation = item.get("operation")
            pointer = item.get("pointer", "#")
            suppressed = False
            for record in suppressions:
                if finding["rule_id"] not in record["rule_ids"] or operation != record["operation"]:
                    continue
                suppression_pointer = record["pointer"]
                if record.get("scope") == "operation":
                    suppressed = True
                else:
                    suppressed = pointer == suppression_pointer or pointer.startswith(
                        suppression_pointer + "/"
                    )
                if suppressed:
                    break
            if not suppressed:
                kept.append(item)
                kept_indexes.append(index)
        if not kept:
            continue
        evidence = finding["evidence"]
        for key, value in list(evidence.items()):
            if key != "locations" and isinstance(value, list) and len(value) == len(locations):
                evidence[key] = [value[index] for index in kept_indexes]
        evidence["locations"] = kept
        evidence["json_pointers"] = [
            item["pointer"]
            for item in kept
            if isinstance(item, dict) and isinstance(item.get("pointer"), str)
        ]
        operation_names = sorted(
            {
                item["operation"]
                for item in kept
                if isinstance(item, dict)
                and isinstance(item.get("operation"), str)
                and item["operation"] != "API server"
            }
        )
        if operation_names:
            finding["affected_operations"] = operation_names[:100]
        visible.append(finding)
    return visible


def analyze(source: str, filename: str | None = None) -> tuple[list[dict[str, Any]], dict[str, int]]:
    spec = parse_spec(source, filename)
    findings = _apply_suppressions([finding.to_dict() for finding in run_rules(spec)], spec)
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding["severity"]] += 1
    counts["operations"] = sum(1 for _ in operations(spec))
    counts["findings"] = len(findings)
    counts["checks"] = RULE_COUNT
    return findings, counts
