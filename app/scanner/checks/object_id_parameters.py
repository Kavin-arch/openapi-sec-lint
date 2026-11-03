import re
from typing import Any

from app.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    iter_parameters,
    location,
)
from app.scanner.models import Finding
from app.scanner.references import pointer_fragment, pointer_join


def check_object_id_parameters(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str, str]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)
        for parameter, parameter_pointer in iter_parameters(spec, path_item, operation, operation_pointer):
            name = parameter.get("name")
            schema = parameter.get("schema")
            if parameter.get("in") not in {"path", "query"}:
                continue
            if not isinstance(name, str) or not isinstance(schema, dict):
                continue
            if not re.search(r"(?:^|[A-Za-z0-9_])id$", name, re.IGNORECASE):
                continue
            if schema.get("type") != "integer":
                continue
            pointer = pointer_join(parameter_pointer, "schema")
            matches.append(
                (operation_name, name, pointer_fragment(pointer), parameter.get("in", "parameter"))
            )

    if not matches:
        return []
    return [
        Finding(
            rule_id="BOLA-001",
            title="An object identifier uses a sequential integer schema",
            severity="low",
            confidence="low",
            summary="An identifier-like path or query parameter is documented as an integer. This is a manual BOLA/IDOR review hint; the schema does not reveal whether identifiers are guessable or access checks are missing.",
            impact="If callers can change an identifier and the API lacks object-level authorization, they may access another user's object.",
            remediation="Verify object-level authorization for every identifier. Consider opaque identifiers where appropriate, while keeping authorization checks as the primary control.",
            affected_operations=sorted({item[0] for item in matches})[:100],
            evidence={
                "parameters": [f"{item[3]} {item[1]}" for item in matches[:100]],
                "json_pointers": [item[2] for item in matches[:100]],
                "locations": [location(item[0], item[2]) for item in matches[:100]],
                "total_matches": len(matches),
                "truncated": len(matches) > 100,
            },
        )
    ]
