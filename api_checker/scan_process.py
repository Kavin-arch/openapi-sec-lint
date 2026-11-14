"""Isolated scan entry point used by the hard-timeout worker."""

from __future__ import annotations

import json
import sys
from typing import Any

from api_checker.scanner.attack_surface import build_attack_surface
from api_checker.scanner.common import begin_traversal_budget, end_traversal_budget
from api_checker.scanner.engine import analyze
from api_checker.scanner.limits import start_memory_guard
from api_checker.scanner.parser import parse_spec
from api_checker.scanner.security_diff import build_security_diff


def _analyze_side(side: dict[str, Any], disabled: set[str]) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    findings, summary = analyze(
        side["source"],
        side.get("filename"),
        disabled,
        source_path=side.get("source_path"),
        reference_root=side.get("reference_root"),
    )
    spec = parse_spec(
        side["source"],
        side.get("filename"),
        source_path=side.get("source_path"),
        reference_root=side.get("reference_root"),
    )
    return findings, summary, spec


def main() -> int:
    start_memory_guard()
    try:
        request: dict[str, Any] = json.load(sys.stdin)
        disabled = set(request.get("disabled_rules", []))
        action = request.get("action", "scan")
        if action == "scan":
            findings, summary = analyze(
                request["source"], request.get("filename"), disabled,
                source_path=request.get("source_path"), reference_root=request.get("reference_root"),
            )
            result: dict[str, Any] = {"findings": findings, "summary": summary}
        elif action == "surface":
            findings, summary, spec = _analyze_side(request, disabled)
            budget_token = begin_traversal_budget()
            try:
                surface = build_attack_surface(spec, findings)
            finally:
                end_traversal_budget(budget_token)
            result = {"surface": surface, "findings": findings, "summary": summary}
        elif action == "diff":
            old_findings, _, old_spec = _analyze_side(request["old"], disabled)
            new_findings, _, new_spec = _analyze_side(request["new"], disabled)
            result = {"diff": build_security_diff(old_findings, new_findings, old_spec, new_spec)}
        else:
            raise ValueError("Unknown scan action.")
        json.dump(result, sys.stdout, ensure_ascii=False)
        return 0
    except Exception as exc:
        json.dump({"error": str(exc)[:500]}, sys.stdout, ensure_ascii=False)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
