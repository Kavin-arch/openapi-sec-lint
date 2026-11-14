"""Create a deterministic, stratified CSV for manual finding review."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def _scans(report: Any) -> list[dict[str, Any]]:
    if isinstance(report, dict) and isinstance(report.get("scans"), list):
        return [item for item in report["scans"] if isinstance(item, dict)]
    if isinstance(report, list):
        return [item for item in report if isinstance(item, dict)]
    return [report] if isinstance(report, dict) else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    grouped: dict[str, list[dict[str, str]]] = {}
    for scan in _scans(json.loads(args.report.read_text(encoding="utf-8"))):
        for finding in scan.get("findings", []):
            if not isinstance(finding, dict):
                continue
            locations = finding.get("evidence", {}).get("locations", [])
            pointer = locations[0].get("pointer", "") if locations and isinstance(locations[0], dict) else ""
            key = str(finding.get("rule_id", "UNKNOWN"))
            row = {
                "rule_id": key,
                "fingerprint": str(finding.get("fingerprint", "")),
                "spec_filename": str(scan.get("spec_filename", scan.get("name", ""))),
                "title": str(finding.get("title", "")),
                "location": str(pointer),
                "operations": ";".join(str(item) for item in finding.get("affected_operations", [])),
                "label": "",
                "notes": "",
            }
            grouped.setdefault(key, []).append(row)
    for rule, rows in grouped.items():
        grouped[rule] = sorted(rows, key=lambda row: (row["spec_filename"], row["fingerprint"], row["location"]))
    selected: list[dict[str, str]] = []
    rule_order = sorted(grouped)
    cursor = 0
    while len(selected) < args.count and rule_order:
        rule = rule_order[cursor % len(rule_order)]
        if grouped[rule]:
            selected.append(grouped[rule].pop(0))
        if not grouped[rule]:
            rule_order.remove(rule)
            cursor = 0
        else:
            cursor += 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["rule_id", "fingerprint", "spec_filename", "title", "location", "operations", "label", "notes"])
        writer.writeheader()
        writer.writerows(selected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
