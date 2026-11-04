from typing import Any

from api_checker.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _walk_schema_locations,
    iter_parameters,
    iter_request_schemas,
    iter_response_schemas,
    location,
)
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment

PAGINATION_NAMES = {
    "limit",
    "page",
    "page_size",
    "pagesize",
    "per_page",
    "perpage",
    "cursor",
    "offset",
    "continuation_token",
    "continuationtoken",
    "page_token",
}


def check_unbounded_strings_and_pagination(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str, str]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)
        for schema, schema_pointer in iter_request_schemas(spec, operation, operation_pointer, path_item):
            for field_path, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                schema_type = node.get("type")
                is_string = schema_type == "string" or (
                    isinstance(schema_type, list) and "string" in schema_type
                )
                if is_string and "maxLength" not in node:
                    matches.append(
                        (
                            operation_name,
                            field_path or "request input (root schema)",
                            pointer_fragment(pointer),
                            "unbounded_string",
                        )
                    )
                is_map = node.get("type") == "object" or "additionalProperties" in node
                has_open_map = "additionalProperties" in node and node["additionalProperties"] is not False
                if is_map and has_open_map and "maxProperties" not in node:
                    matches.append(
                        (
                            operation_name,
                            field_path or "request map (root schema)",
                            pointer_fragment(pointer),
                            "unbounded_map",
                        )
                    )

        if method != "GET":
            continue
        pagination = {
            str(parameter.get("name", "")).replace("-", "_").lower()
            for parameter, _ in iter_parameters(spec, path_item, operation, operation_pointer)
            if parameter.get("in") == "query"
        }
        if pagination & PAGINATION_NAMES:
            continue
        for status, media_type, schema, schema_pointer in iter_response_schemas(
            spec, operation, operation_pointer
        ):
            root = next(_walk_schema_locations(spec, schema, schema_pointer), None)
            if root is None:
                continue
            _, pointer, node = root
            schema_type = node.get("type")
            is_array = schema_type == "array" or (isinstance(schema_type, list) and "array" in schema_type)
            if is_array:
                matches.append(
                    (
                        operation_name,
                        f"response {status} {media_type}: top-level collection has no pagination parameter",
                        pointer_fragment(pointer),
                        "missing_pagination",
                    )
                )

    if not matches:
        return []
    return [
        Finding(
            rule_id="RESOURCE-002",
            title="A request or collection response lacks documented resource bounds",
            severity="low",
            confidence="low",
            summary="Request strings or maps lack schema limits, or a GET response returns a top-level array without a recognizable pagination parameter. These are contract review hints and do not establish runtime resource exposure.",
            impact="Large request values or unbounded collection responses can increase memory, CPU, and downstream load when runtime limits are also absent.",
            remediation="Document realistic maxLength and maxProperties values, enforce request limits in the service, and paginate large collection endpoints.",
            affected_operations=sorted({item[0] for item in matches}),
            evidence={
                "schema_fields": [item[1] for item in matches],
                "issue_types": [item[3] for item in matches],
                "json_pointers": [item[2] for item in matches],
                "locations": [location(item[0], item[2]) for item in matches],
                "total_matches": len(matches),
                "truncated": len(matches) > 100,
            },
        )
    ]
