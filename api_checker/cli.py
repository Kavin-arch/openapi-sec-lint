"""Command-line entry point for local OpenAPI analysis."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess  # nosec B404
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from api_checker import __version__
from api_checker.exporters import (
    to_attack_surface_markdown,
    to_curl_test_plan,
    to_github_annotations,
    to_html,
    to_junit,
    to_markdown,
    to_sarif,
    to_security_diff_markdown,
)
from api_checker.scanner.parser import MAX_SPEC_BYTES
from api_checker.scanner.rules import RULE_IDS

SEVERITIES = ("critical", "high", "medium", "low", "info")
SPEC_SUFFIXES = {".json", ".yaml", ".yml"}
SCAN_TIMEOUT_SECONDS = max(1, int(os.getenv("API_CHECKER_SCAN_TIMEOUT", "70")))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openapi-sec-lint", description="Lint OpenAPI and Swagger specifications locally."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="analyze one or more JSON or YAML specifications")
    scan.add_argument("spec", nargs="+", help="file, directory, or - for standard input")
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit 1 when a finding at this severity or higher is present",
    )
    scan.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        help="hide findings below this severity in reports (for example, medium)",
    )
    scan.add_argument("--format", choices=("json", "sarif", "md", "curl", "html", "github", "junit"), help="report format")
    scan.add_argument("--output", type=Path, help="write the report to a file instead of stdout")
    scan.add_argument(
        "--disable", action="append", default=[], metavar="RULE-ID", help="disable a rule (repeatable)"
    )
    scan.add_argument("--config", type=Path, help="read default options from a TOML or JSON file")
    scan.add_argument("--baseline", type=Path, help="show only findings absent from this baseline")
    scan.add_argument("--write-baseline", type=Path, help="write current finding fingerprints to a baseline")
    surface = subparsers.add_parser("surface", help="summarize the API's static attack surface")
    surface.add_argument("spec", help="JSON or YAML specification file")
    surface.add_argument("--format", choices=("json", "md"), default="json")
    surface.add_argument("--output", type=Path)
    diff = subparsers.add_parser("diff", help="compare security posture between two specifications")
    diff.add_argument("old_spec", help="older JSON or YAML specification")
    diff.add_argument("new_spec", help="newer JSON or YAML specification")
    diff.add_argument("--format", choices=("json", "md"), default="json")
    diff.add_argument("--output", type=Path)
    diff.add_argument("--disable", action="append", default=[], metavar="RULE-ID")
    return parser


def _discover_config(start: Path | None = None) -> Path | None:
    """Find the nearest project config by walking from CWD toward the root."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".openapi-sec-lint.toml"
        if candidate.is_file():
            return candidate
    return None


def _config_options(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        value = json.loads(content)
    else:
        value = tomllib.loads(content)
    if not isinstance(value, dict):
        raise ValueError("The config file must contain an object/table.")
    tool_options = value.get("tool")
    if tool_options is None:
        return value
    if not isinstance(tool_options, dict):
        raise ValueError("Config 'tool' must be an object/table.")
    options = tool_options.get("openapi-sec-lint", value)
    if not isinstance(options, dict):
        raise ValueError("Config 'tool.openapi-sec-lint' must be an object/table.")
    return options


def _input_paths(values: list[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        if value == "-":
            continue
        path = Path(value)
        if path.is_dir():
            paths.extend(
                sorted(
                    item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in SPEC_SUFFIXES
                )
            )
        else:
            paths.append(path)
    return paths


def _path_is_ignored(path: str, patterns: list[str]) -> bool:
    value = Path(path)
    try:
        candidate = value.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        candidate = value.as_posix()
    return any(fnmatch.fnmatchcase(candidate, pattern) or fnmatch.fnmatchcase(value.name, pattern) for pattern in patterns)


def _baseline_fingerprints(path: Path | None) -> tuple[set[str], dict[str, set[str]]]:
    if path is None:
        return set(), {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict) and value.get("version") == 2:
        artifacts = value.get("artifacts", {})
        if not isinstance(artifacts, dict) or any(
            not isinstance(uri, str)
            or not isinstance(items, list)
            or not all(isinstance(item, str) for item in items)
            for uri, items in artifacts.items()
        ):
            raise ValueError("The baseline artifacts must map input paths to fingerprint lists.")
        return set(), {uri: set(items) for uri, items in artifacts.items()}
    fingerprints = value.get("fingerprints", []) if isinstance(value, dict) else value
    if not isinstance(fingerprints, list) or not all(isinstance(item, str) for item in fingerprints):
        raise ValueError("The baseline must contain a list of finding fingerprints.")
    return set(fingerprints), {}


def _recount(findings: list[dict[str, Any]], summary: dict[str, int]) -> dict[str, int]:
    updated = dict(summary)
    for severity in SEVERITIES:
        updated[severity] = sum(finding["severity"] == severity for finding in findings)
    updated["findings"] = len(findings)
    return updated


def _scan_one(
    value: str,
    disabled: set[str],
) -> dict[str, Any]:
    source_path: str | None = None
    reference_root: str | None = None
    if value == "-":
        source = sys.stdin.read()
        filename = "stdin.yaml"
        uri = "stdin.yaml"
        name = "stdin"
    else:
        path = Path(value)
        source_path = str(path.resolve())
        reference_root = str(path.resolve().parent)
        source = path.read_text(encoding="utf-8-sig")
        if len(source.encode("utf-8")) > MAX_SPEC_BYTES:
            raise ValueError("Specifications are limited to 16 MB.")
        filename = path.name
        name = path.stem
        try:
            uri = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            uri = path.resolve().as_posix()
    request = json.dumps(
        {
            "source": source,
            "filename": filename,
            "disabled_rules": sorted(disabled),
            "source_path": source_path,
            "reference_root": reference_root,
        }
    )
    try:
        # The specification is supplied over stdin and is never part of the command.
        completed = subprocess.run(  # nosec B603
            [sys.executable, "-m", "api_checker.scan_process"],
            input=request,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"Scan exceeded the {SCAN_TIMEOUT_SECONDS}-second time limit.") from exc
    if completed.returncode != 0:
        raise ValueError(f"Analysis process exited unexpectedly ({completed.returncode}).")
    result = json.loads(completed.stdout)
    if result.get("error"):
        raise ValueError(result["error"])
    findings, summary = result["findings"], result["summary"]
    return {
        "id": None,
        "name": name,
        "target_url": "",
        "spec_filename": uri,
        "spec_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "status": "completed",
        "summary": summary,
        "findings": findings,
    }


def _file_request(value: str) -> dict[str, Any]:
    path = Path(value).resolve()
    source = path.read_text(encoding="utf-8-sig")
    if len(source.encode("utf-8")) > MAX_SPEC_BYTES:
        raise ValueError("Specifications are limited to 16 MB.")
    return {
        "source": source,
        "filename": path.name,
        "source_path": str(path),
        "reference_root": str(path.parent),
    }


def _run_action(request: dict[str, Any]) -> dict[str, Any]:
    try:
        completed = subprocess.run(  # nosec B603
            [sys.executable, "-m", "api_checker.scan_process"],
            input=json.dumps(request),
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"Scan exceeded the {SCAN_TIMEOUT_SECONDS}-second time limit.") from exc
    if completed.returncode != 0:
        raise ValueError(f"Analysis process exited unexpectedly ({completed.returncode}).")
    result = json.loads(completed.stdout)
    if result.get("error"):
        raise ValueError(result["error"])
    return cast(dict[str, Any], result)


def _run_surface(path: str, output_format: str) -> str:
    request = _file_request(path)
    result = _run_action({**request, "action": "surface"})
    return (
        json.dumps(result["surface"], indent=2, ensure_ascii=False)
        if output_format == "json"
        else to_attack_surface_markdown(result["surface"])
    )


def _run_diff(old_path: str, new_path: str, output_format: str, disabled: set[str]) -> str:
    result = _run_action(
        {
            "action": "diff",
            "disabled_rules": sorted(disabled),
            "old": _file_request(old_path),
            "new": _file_request(new_path),
        }
    )
    return (
        json.dumps(result["diff"], indent=2, ensure_ascii=False)
        if output_format == "json"
        else to_security_diff_markdown(result["diff"])
    )


def _serialize(scans: list[dict[str, Any]], output_format: str) -> str:
    if output_format == "html":
        return to_html(scans)
    if output_format == "junit":
        return to_junit(scans)
    if output_format == "github":
        return to_github_annotations(scans)
    if output_format == "curl":
        return "\n".join(to_curl_test_plan(scan) for scan in scans)
    if output_format == "sarif":
        report = to_sarif(scans[0])
        for scan in scans[1:]:
            report["runs"].extend(to_sarif(scan)["runs"])
        return json.dumps(report, indent=2, ensure_ascii=False)
    if output_format == "md":
        return "\n".join(to_markdown(scan) for scan in scans)
    payload: Any = scans[0] if len(scans) == 1 else scans
    return json.dumps(payload, indent=2, ensure_ascii=False)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "surface":
            rendered = _run_surface(args.spec, args.format)
            if args.output:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            else:
                sys.stdout.write(rendered + "\n")
            return 0
        if args.command == "diff":
            disabled = {rule.strip() for value in args.disable for rule in value.split(",") if rule.strip()}
            rendered = _run_diff(args.old_spec, args.new_spec, args.format, disabled)
            if args.output:
                args.output.write_text(rendered + "\n", encoding="utf-8")
            else:
                sys.stdout.write(rendered + "\n")
            return 0
        config = _config_options(args.config or _discover_config())
        config_disabled = config.get("disable", config.get("disabled_rules", []))
        if not isinstance(config_disabled, list) or not all(isinstance(item, str) for item in config_disabled):
            raise ValueError("Config 'disable' must be a list of rule IDs.")
        disabled = set(config_disabled)
        disabled.update(rule.strip() for value in args.disable for rule in value.split(",") if rule.strip())
        output_format = args.format or config.get("format", "json")
        if output_format not in {"json", "sarif", "md", "curl", "html", "github", "junit"}:
            raise ValueError("Config format must be json, sarif, md, curl, html, github, or junit.")
        path_ignores = config.get("path_ignores", [])
        if not isinstance(path_ignores, list) or not all(isinstance(item, str) for item in path_ignores):
            raise ValueError("Config 'path_ignores' must be a list of glob patterns.")
        rule_severity = config.get("rule_severity", {})
        if not isinstance(rule_severity, dict) or any(
            rule not in RULE_IDS or severity not in SEVERITIES for rule, severity in rule_severity.items()
        ):
            raise ValueError("Config 'rule_severity' must map known rule IDs to supported severities.")
        fail_on = args.fail_on or config.get("fail_on")
        if fail_on is not None and fail_on not in SEVERITIES:
            raise ValueError("Config fail_on must be a supported severity.")
        min_severity = args.min_severity or config.get("min_severity")
        if min_severity is not None and min_severity not in SEVERITIES:
            raise ValueError("Config min_severity must be a supported severity.")

        input_paths = _input_paths(args.spec)
        stdin_count = args.spec.count("-")
        if stdin_count > 1 or (stdin_count and len(args.spec) != 1):
            raise ValueError("Standard input can be used as the only input, once.")
        input_values = ["-"] if stdin_count else [str(path) for path in input_paths if not _path_is_ignored(str(path), path_ignores)]
        if not input_values:
            raise ValueError("No JSON or YAML specifications remain after applying path_ignores.")

        scans = [_scan_one(value, disabled) for value in input_values]
        if rule_severity:
            for scan in scans:
                for finding in scan["findings"]:
                    if finding["rule_id"] in rule_severity:
                        finding["severity"] = rule_severity[finding["rule_id"]]
                scan["summary"] = _recount(scan["findings"], scan["summary"])
        if min_severity:
            threshold = SEVERITIES.index(min_severity)
            for scan in scans:
                scan["findings"] = [
                    finding
                    for finding in scan["findings"]
                    if SEVERITIES.index(finding["severity"]) <= threshold
                ]
                scan["summary"] = _recount(scan["findings"], scan["summary"])
        artifact_fingerprints = {
            scan["spec_filename"]: sorted(finding["fingerprint"] for finding in scan["findings"])
            for scan in scans
        }
        if args.write_baseline:
            args.write_baseline.write_text(
                json.dumps({"version": 2, "artifacts": artifact_fingerprints}, indent=2) + "\n",
                encoding="utf-8",
            )
        baseline, artifact_baseline = _baseline_fingerprints(args.baseline)
        if baseline or artifact_baseline:
            for scan in scans:
                known = baseline | artifact_baseline.get(scan["spec_filename"], set())
                scan["findings"] = [
                    finding for finding in scan["findings"] if finding["fingerprint"] not in known
                ]
                scan["summary"] = _recount(scan["findings"], scan["summary"])

        rendered = _serialize(scans, output_format)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            try:
                sys.stdout.write(rendered + "\n")
            except BrokenPipeError:
                return 0

        if fail_on:
            threshold = SEVERITIES.index(fail_on)
            if any(
                SEVERITIES.index(finding["severity"]) <= threshold
                for scan in scans
                for finding in scan["findings"]
            ):
                return 1
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        print(f"openapi-sec-lint: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
