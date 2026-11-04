from typing import Any

from api_checker.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _walk_schema_locations,
    iter_request_schemas,
    location,
)
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment


def check_unbounded_request_arrays(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)
        for schema, schema_pointer in iter_request_schemas(spec, operation, operation_pointer, path_item):
            for field_path, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                schema_type = node.get("type")
                is_array = (
                    schema_type == "array"
                    or (isinstance(schema_type, list) and "array" in schema_type)
                    or (schema_type is None and "items" in node)
                )
                if is_array and "maxItems" not in node:
                    matches.append(
                        (operation_name, field_path or "request body (root array)", pointer_fragment(pointer))
                    )

    if not matches:
        return []
    return [
        Finding(
            rule_id="RESOURCE-001",
            title="A request array has no documented maximum size",
            severity="low",
            confidence="low",
            summary="The request schema contains an array without maxItems. This is a resource-consumption review hint, not proof that the API accepts unbounded input.",
            impact="Large inputs can consume disproportionate memory, CPU, or downstream service capacity if the implementation has no limits.",
            remediation="Set a realistic maxItems in the contract and enforce request-size and processing limits in the API.",
            affected_operations=sorted({item[0] for item in matches}),
            evidence={
                "schema_fields": [item[1] for item in matches],
                "json_pointers": [item[2] for item in matches],
                "locations": [location(item[0], item[2]) for item in matches],
                "total_matches": len(matches),
                "truncated": len(matches) > 100,
            },
        )
    ]
