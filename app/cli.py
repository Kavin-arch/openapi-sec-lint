"""Command-line entry point for local OpenAPI analysis."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from app.exporters import to_markdown, to_sarif
from app.scanner.engine import analyze

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api-checker", description="Review an OpenAPI or Swagger specification locally."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="analyze a JSON or YAML API specification")
    scan.add_argument("spec", type=Path, help="path to an OpenAPI or Swagger file")
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit with code 1 when a finding at this severity or higher is present",
    )
    scan.add_argument(
        "--format", choices=("json", "sarif", "md"), default="json", help="report output format"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        source = args.spec.read_text(encoding="utf-8-sig")
        findings, summary = analyze(source, args.spec.name)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"api-checker: {exc}", file=sys.stderr)
        return 2

    try:
        spec_uri = args.spec.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        spec_uri = args.spec.name
    scan = {
        "id": None,
        "name": args.spec.stem,
        "target_url": "",
        "spec_filename": spec_uri,
        "spec_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "status": "completed",
        "summary": summary,
        "findings": findings,
    }
    if args.format == "sarif":
        output = json.dumps(to_sarif(scan), indent=2, ensure_ascii=False)
    elif args.format == "md":
        output = to_markdown(scan)
    else:
        output = json.dumps(scan, indent=2, ensure_ascii=False)
    print(output)

    if args.fail_on:
        threshold = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(finding["severity"]) <= threshold for finding in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
