"""Check that the bundled corpus still matches its published finding totals."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def main(report_path: str) -> int:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "corpus" / "manifest.json").read_text(encoding="utf-8"))
    report: Any = json.loads(Path(report_path).read_text(encoding="utf-8"))
    scans = report if isinstance(report, list) else [report]
    actual = {Path(item["spec_filename"]).name: item["summary"] for item in scans}
    errors = []
    for expected in manifest["specs"]:
        observed = actual.get(expected["file"])
        if observed != expected["summary"]:
            errors.append(f"{expected['file']}: expected {expected['summary']}, got {observed}")
    if set(actual) != {item["file"] for item in manifest["specs"]}:
        errors.append(f"unexpected corpus files in report: {sorted(set(actual) - {item['file'] for item in manifest['specs']})}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    for name, summary in sorted(actual.items()):
        print(f"{name}: {summary['findings']} findings across {summary['operations']} operations")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/verify_corpus.py REPORT.json")
    raise SystemExit(main(sys.argv[1]))
