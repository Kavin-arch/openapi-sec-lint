from typing import Any

from api_checker.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _walk_schema_locations,
    iter_request_schemas,
    location,
)
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment, pointer_join

SERVER_MANAGED_FIELDS = {"id", "role", "is_admin", "isadmin", "owner_id", "userid", "user_id"}


def check_permissive_request_objects(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str, str]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        if method not in {"POST", "PUT", "PATCH"}:
            continue
        operation_name = _operation_name(method, path)
        schemas = iter_request_schemas(
            spec, operation, operation_pointer, path_item, parameter_locations={"body"}
        )
        for schema, schema_pointer in schemas:
            for field_path, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                schema_type = node.get("type")
                is_object = schema_type == "object" or "properties" in node or "additionalProperties" in node
                if not is_object:
                    continue
                additional = node.get("additionalProperties")
                allows_additional = (
                    "additionalProperties" not in node or additional is True or isinstance(additional, dict)
                )
                if allows_additional:
                    matches.append(
                        (
                            operation_name,
                            f"{field_path or 'request body (root object)'}: undeclared properties are permitted by the schema default",
                            pointer_fragment(pointer),
                            "permissive_object",
                        )
                    )
                properties = node.get("properties")
                if isinstance(properties, dict):
                    for name, child in properties.items():
                        normalized = str(name).replace("-", "_").lower()
                        if (
                            normalized in SERVER_MANAGED_FIELDS
                            and isinstance(child, dict)
                            and child.get("readOnly") is not True
                        ):
                            property_pointer = pointer_join(pointer_join(pointer, "properties"), name)
                            matches.append(
                                (
                                    operation_name,
                                    f"{field_path + '.' if field_path else ''}{name}: server-managed field is not marked readOnly",
                                    pointer_fragment(property_pointer),
                                    "server_managed_field",
                                )
                            )

    if not matches:
        return []
    return [
        Finding(
            rule_id="MASS-001",
            title="A write request schema may accept mass-assignment fields",
            severity="low",
            confidence="low",
            summary="A write request permits undeclared object properties or includes a server-managed field without readOnly. These are schema review signals, not proof of how the server binds or authorizes fields.",
            impact="If the implementation binds untrusted request properties directly to protected model fields, callers may change ownership, role, or other privileged state.",
            remediation="Use explicit request DTOs or allowlists, reject unexpected properties where practical, and enforce authorization and ownership checks in the server.",
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
