"""Security-focused comparison of findings and effective operation security."""

from __future__ import annotations

from typing import Any

from api_checker.scanner.common import _operation_entries_with_pointers, _operation_name


def _anonymous(requirements: Any) -> bool:
    return (
        not isinstance(requirements, list)
        or not requirements
        or any(not isinstance(item, dict) or not item for item in requirements)
    )


def _operation_security(spec: dict[str, Any]) -> dict[str, list[dict[str, list[str]]]]:
    global_security = spec.get("security")
    snapshot: dict[str, list[dict[str, list[str]]]] = {}
    for method, path, _, operation, _ in _operation_entries_with_pointers(spec):
        raw = operation["security"] if "security" in operation else global_security
        normalized: list[dict[str, list[str]]] = []
        if isinstance(raw, list):
            for item in raw:
                if isinstance(item, dict):
                    normalized.append(
                        {
                            str(scheme): sorted({str(scope) for scope in scopes})
                            if isinstance(scopes, list)
                            else []
                            for scheme, scopes in item.items()
                        }
                    )
        snapshot[_operation_name(method, path)] = normalized
    return snapshot


def _scope_weakenings(
    operation: str,
    old: list[dict[str, list[str]]],
    new: list[dict[str, list[str]]],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for new_alternative in new:
        for scheme, new_scopes in new_alternative.items():
            prior = [
                old_alternative[scheme]
                for old_alternative in old
                if scheme in old_alternative
            ]
            if not prior:
                continue
            old_scopes = min(prior, key=len)
            if set(new_scopes) < set(old_scopes):
                changes.append(
                    {
                        "type": "oauth_scopes_weakened",
                        "operation": operation,
                        "scheme": scheme,
                        "removed_scopes": sorted(set(old_scopes) - set(new_scopes)),
                    }
                )
    return changes


def build_security_diff(
    old_findings: list[dict[str, Any]],
    new_findings: list[dict[str, Any]],
    old_spec: dict[str, Any],
    new_spec: dict[str, Any],
) -> dict[str, Any]:
    old_by_fingerprint = {finding.get("fingerprint"): finding for finding in old_findings}
    new_by_fingerprint = {finding.get("fingerprint"): finding for finding in new_findings}
    added = [new_by_fingerprint[key] for key in new_by_fingerprint.keys() - old_by_fingerprint.keys()]
    removed = [old_by_fingerprint[key] for key in old_by_fingerprint.keys() - new_by_fingerprint.keys()]
    severity_changes = [
        {
            "fingerprint": fingerprint,
            "rule_id": new_by_fingerprint[fingerprint].get("rule_id"),
            "old": old_by_fingerprint[fingerprint].get("severity"),
            "new": new_by_fingerprint[fingerprint].get("severity"),
        }
        for fingerprint in old_by_fingerprint.keys() & new_by_fingerprint.keys()
        if old_by_fingerprint[fingerprint].get("severity") != new_by_fingerprint[fingerprint].get("severity")
    ]

    old_security = _operation_security(old_spec)
    new_security = _operation_security(new_spec)
    weakenings: list[dict[str, Any]] = []
    new_unauthenticated = [
        operation
        for operation, requirements in new_security.items()
        if operation not in old_security and _anonymous(requirements)
    ]
    for operation in sorted(old_security.keys() & new_security.keys()):
        previous = old_security[operation]
        current = new_security[operation]
        if not _anonymous(previous) and _anonymous(current):
            weakenings.append(
                {
                    "type": "authentication_removed",
                    "operation": operation,
                    "old_security": previous,
                    "new_security": current,
                }
            )
        else:
            weakenings.extend(_scope_weakenings(operation, previous, current))

    return {
        "old_spec": old_spec.get("info", {}).get("title", "old spec"),
        "new_spec": new_spec.get("info", {}).get("title", "new spec"),
        "added_findings": sorted(added, key=lambda item: (item.get("rule_id", ""), item.get("fingerprint", ""))),
        "removed_findings": sorted(removed, key=lambda item: (item.get("rule_id", ""), item.get("fingerprint", ""))),
        "severity_changes": severity_changes,
        "security_weakening": weakenings,
        "new_unauthenticated_endpoints": sorted(new_unauthenticated),
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "severity_changes": len(severity_changes),
            "security_weakening": len(weakenings),
            "new_unauthenticated_endpoints": len(new_unauthenticated),
        },
    }
