from typing import Any

from app.scanner.common import _operation_entries, _operation_name, _walk_schema
from app.scanner.models import Finding
from app.scanner.references import resolve_local_ref


def check_unbounded_request_arrays(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str]] = []
    for method, path, path_item, operation in _operation_entries(spec):
        request_body = resolve_local_ref(spec, operation.get("requestBody", {}))
        content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
        candidate_schemas: list[dict[str, Any]] = []
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    candidate_schemas.append(media["schema"])
        # Swagger 2.0 body parameters use `in: body` and a schema.
        effective_parameters: dict[tuple[str, str], dict[str, Any]] = {}
        for source in (path_item.get("parameters", []), operation.get("parameters", [])):
            if not isinstance(source, list):
                continue
            for raw_parameter in source:
                parameter = resolve_local_ref(spec, raw_parameter)
                if not isinstance(parameter, dict):
                    continue
                name, location = parameter.get("name"), parameter.get("in")
                if not isinstance(name, str) or not isinstance(location, str):
                    continue
                effective_parameters[(name, location)] = parameter
        for parameter in effective_parameters.values():
            if parameter.get("in") == "body" and isinstance(parameter.get("schema"), dict):
                candidate_schemas.append(parameter["schema"])
        for schema in candidate_schemas:
            for field_path, node in _walk_schema(spec, schema):
                schema_type = node.get("type")
                is_array = schema_type == "array" or (
                    isinstance(schema_type, list) and "array" in schema_type
                ) or (schema_type is None and "items" in node)
                if is_array and "maxItems" not in node:
                    matches.append((_operation_name(method, path), field_path or "<request body>"))

    if not matches:
        return []
    return [Finding(
        rule_id="RESOURCE-001",
        title="A request array has no documented maximum size",
        severity="low",
        confidence="low",
        summary="The request schema contains an array without maxItems. This is a resource-consumption review hint, not proof that the API accepts unbounded input.",
        impact="Large inputs can consume disproportionate memory, CPU, or downstream service capacity if the implementation has no limits.",
        remediation="Set a realistic maxItems in the contract and enforce request-size and processing limits in the API.",
        affected_operations=sorted({item[0] for item in matches})[:100],
        evidence={"schema_fields": [item[1] for item in matches[:100]], "truncated": len(matches) > 100},
    )]
