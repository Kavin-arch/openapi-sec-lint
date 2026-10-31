from typing import Any

from app.scanner.parser import parse_spec
from app.scanner.rules import RULE_COUNT, operations, run_rules


def analyze(source: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    spec = parse_spec(source)
    findings = [finding.to_dict() for finding in run_rules(spec)]
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding["severity"]] += 1
    counts["operations"] = sum(1 for _ in operations(spec))
    counts["findings"] = len(findings)
    counts["checks"] = RULE_COUNT
    return findings, counts
