import hashlib
from typing import Any

from api_checker.scanner.common import begin_traversal_budget, collect_suppressions, end_traversal_budget
from api_checker.scanner.parser import parse_spec, source_line_map
from api_checker.scanner.rules import RULE_COUNT, RULE_IDS, operations, run_rules


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
            pointer = item.get("pointer", "#")
            operations = item.get("affected_operations")
            if not isinstance(operations, list):
                operations = [item.get("operation")]
            kept_operations = []
            for operation in operations:
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
                if not suppressed and isinstance(operation, str):
                    kept_operations.append(operation)
            if kept_operations:
                kept_item = dict(item)
                kept_item["affected_operations"] = sorted(set(kept_operations))
                kept_item["operation"] = kept_item["affected_operations"][0]
                kept.append(kept_item)
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
                operation
                for item in kept
                if isinstance(item, dict)
                for operation in item.get("affected_operations", [item.get("operation")])
                if isinstance(operation, str) and operation != "API server"
            }
        )
        if operation_names:
            finding["affected_operations"] = operation_names
        visible.append(finding)
    return visible


def _fingerprint(rule_id: str, location: dict[str, Any] | None, evidence: dict[str, Any]) -> str:
    pointer = location.get("pointer", "") if location else ""
    discriminator = ""
    for key in ("issue_types", "issues"):
        value = evidence.get(key)
        if isinstance(value, list) and value:
            discriminator = str(value[0])
            break
    identity = f"{rule_id}\0{pointer}\0{discriminator}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _one_finding_per_location(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    by_fingerprint: dict[str, dict[str, Any]] = {}
    for finding in findings:
        evidence = finding.get("evidence", {})
        locations = evidence.get("locations", []) if isinstance(evidence, dict) else []
        if not isinstance(locations, list) or not locations:
            finding["fingerprint"] = _fingerprint(finding["rule_id"], None, evidence)
            expanded.append(finding)
            continue
        for index, item in enumerate(locations):
            current = dict(finding)
            current_evidence: dict[str, Any] = {}
            for key, value in evidence.items():
                if key in {"total_matches", "truncated"}:
                    continue
                elif isinstance(value, list) and len(value) == len(locations):
                    current_evidence[key] = [value[index]]
                else:
                    current_evidence[key] = value
            current["evidence"] = current_evidence
            current["affected_operations"] = (
                sorted(set(item["affected_operations"]))
                if isinstance(item, dict) and isinstance(item.get("affected_operations"), list)
                else [item["operation"]]
                if isinstance(item, dict) and isinstance(item.get("operation"), str)
                else []
            )
            fingerprint = _fingerprint(
                current["rule_id"], item if isinstance(item, dict) else None, current_evidence
            )
            previous = by_fingerprint.get(fingerprint)
            if previous is not None:
                previous["affected_operations"] = sorted(
                    set(previous["affected_operations"]) | set(current["affected_operations"])
                )
                continue
            current["fingerprint"] = fingerprint
            by_fingerprint[fingerprint] = current
            expanded.append(current)
    return expanded


def analyze(
    source: str, filename: str | None = None, disabled_rules: set[str] | None = None
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    budget_token = begin_traversal_budget()
    try:
        spec = parse_spec(source, filename)
        lines = source_line_map(source)
        raw_findings = [finding.to_dict() for finding in run_rules(spec, disabled_rules)]
        findings = _one_finding_per_location(_apply_suppressions(raw_findings, spec))
        for finding in findings:
            locations = finding.get("evidence", {}).get("locations", [])
            for item in locations:
                if isinstance(item, dict) and isinstance(item.get("pointer"), str):
                    line = lines.get(item["pointer"])
                    if line is not None:
                        item["start_line"] = line
    finally:
        end_traversal_budget(budget_token)
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding["severity"]] += 1
    counts["operations"] = sum(1 for _ in operations(spec))
    counts["findings"] = len(findings)
    counts["checks"] = RULE_COUNT - len(set(RULE_IDS) & (disabled_rules or set()))
    return findings, counts
