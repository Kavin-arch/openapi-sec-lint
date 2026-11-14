"""Verify offline rule-signal coverage for the intentionally vulnerable specs."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def main(report_path: str) -> int:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "corpus" / "vulnerable-manifest.json").read_text(encoding="utf-8"))
    report: Any = json.loads(Path(report_path).read_text(encoding="utf-8"))
    scans = report if isinstance(report, list) else [report]
    actual = {Path(item["spec_filename"]).name: item for item in scans}
    errors = []
    for expected in manifest["specs"]:
        path = root / "corpus" / "vulnerable" / expected["file"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected["sha256"]:
            errors.append(f"{expected['file']}: input hash does not match the pinned manifest")
        scan = actual.get(expected["file"])
        if scan is None:
            errors.append(f"{expected['file']}: no scan result")
            continue
        observed = {finding.get("rule_id") for finding in scan.get("findings", [])}
        missing = set(expected["expected_rules"]) - observed
        unexpected = observed - set(expected["expected_rules"])
        if missing or unexpected:
            errors.append(f"{expected['file']}: missing rules {sorted(missing)}; unexpected rules {sorted(unexpected)}")
        challenges = expected.get("mapped_challenges", [])
        detected = sum(challenge["rule"] in observed for challenge in challenges)
        print(f"{expected['file']}: {detected}/{len(challenges)} mapped challenge categories have a matching static rule signal across {scan['summary']['operations']} operations")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/verify_vulnerable_corpus.py REPORT.json")
    raise SystemExit(main(sys.argv[1]))
