"""Summarize completed true/false/uncertain labels from a review CSV."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("annotations", type=Path)
    args = parser.parse_args()
    totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    with args.annotations.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            label = row.get("label", "").strip().lower()
            if label not in {"true", "false", "uncertain"}:
                continue
            totals[row.get("rule_id", "UNKNOWN")][label] += 1
    print("rule_id,true,false,uncertain,precision")
    for rule in sorted(totals):
        counts = totals[rule]
        denominator = counts["true"] + counts["false"]
        precision = f"{counts['true'] / denominator:.3f}" if denominator else "n/a"
        print(f"{rule},{counts['true']},{counts['false']},{counts['uncertain']},{precision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
