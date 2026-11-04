"""Isolated scan entry point used by the hard-timeout worker."""

from __future__ import annotations

import json
import sys
from typing import Any

from api_checker.scanner.engine import analyze


def main() -> int:
    try:
        request: dict[str, Any] = json.load(sys.stdin)
        findings, summary = analyze(
            request["source"], request.get("filename"), set(request.get("disabled_rules", []))
        )
        json.dump({"findings": findings, "summary": summary}, sys.stdout, ensure_ascii=False)
        return 0
    except Exception as exc:
        json.dump({"error": str(exc)[:500]}, sys.stdout, ensure_ascii=False)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
