"""Static API attack-surface summaries derived from OpenAPI contracts."""

from __future__ import annotations

import re
from typing import Any

from api_checker.scanner.checks.url_input_fields import URL_FIELD_NAMES, _looks_like_url_field
from api_checker.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _swagger_parameter_schema,
    _walk_schema_locations,
    iter_parameters,
    iter_request_schemas,
)
from api_checker.scanner.references import pointer_join

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ADMIN_HINT = re.compile(r"(?:^|[/_.-])(admin|manage(?:ment)?|internal|superuser|privileged)(?:$|[/_.-])", re.I)


def _is_anonymous(spec: dict[str, Any], operation: dict[str, Any]) -> bool:
    requirements = operation["security"] if "security" in operation else spec.get("security")
    return (
        not isinstance(requirements, list)
        or not requirements
        or any(not isinstance(item, dict) or not item for item in requirements)
    )


def _has_upload(spec: dict[str, Any], operation: dict[str, Any], operation_pointer: str, path_item: dict[str, Any]) -> bool:
    body = operation.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content", {})
        if isinstance(content, dict) and any(
            str(media).lower().startswith("multipart/") or str(media).lower() == "application/octet-stream"
            for media in content
        ):
            return True
    for parameter, _ in iter_parameters(spec, path_item, operation, operation_pointer):
        if parameter.get("in") == "formData" and parameter.get("type") == "file":
            return True
    for schema, pointer in iter_request_schemas(spec, operation, operation_pointer, path_item):
        for _, _, node in _walk_schema_locations(spec, schema, pointer):
            if node.get("format") == "binary" or node.get("type") == "file":
                return True
    return False


def _has_url_input(
    spec: dict[str, Any], operation: dict[str, Any], operation_pointer: str, path_item: dict[str, Any]
) -> bool:
    for schema, pointer in iter_request_schemas(spec, operation, operation_pointer, path_item):
        for field_path, _, node in _walk_schema_locations(spec, schema, pointer):
            leaf = field_path.rsplit(".", 1)[-1] if field_path else ""
            compact = leaf.replace("-", "_").replace("_", "").lower()
            if str(node.get("format", "")).lower() in {"uri", "url"} or _looks_like_url_field(leaf) or compact in URL_FIELD_NAMES:
                return True
    for parameter, parameter_pointer in iter_parameters(spec, path_item, operation, operation_pointer):
        name = str(parameter.get("name", ""))
        parameter_schema: Any = parameter.get("schema")
        schema_pointer = pointer_join(parameter_pointer, "schema")
        if not isinstance(parameter_schema, dict) and spec.get("swagger") == "2.0":
            parameter_schema = _swagger_parameter_schema(parameter)
            schema_pointer = parameter_pointer
        if isinstance(parameter_schema, dict):
            for field_path, _, node in _walk_schema_locations(spec, parameter_schema, schema_pointer):
                leaf = field_path.rsplit(".", 1)[-1] if field_path else name
                compact = leaf.replace("-", "_").replace("_", "").lower()
                if str(node.get("format", "")).lower() in {"uri", "url"} or _looks_like_url_field(leaf) or compact in URL_FIELD_NAMES:
                    return True
        content = parameter.get("content", {})
        if isinstance(content, dict):
            for media_type, media in content.items():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    content_pointer = pointer_join(
                        pointer_join(pointer_join(parameter_pointer, "content"), media_type), "schema"
                    )
                    for field_path, _, node in _walk_schema_locations(spec, media["schema"], content_pointer):
                        leaf = field_path.rsplit(".", 1)[-1] if field_path else name
                        compact = leaf.replace("-", "_").replace("_", "").lower()
                        if str(node.get("format", "")).lower() in {"uri", "url"} or _looks_like_url_field(leaf) or compact in URL_FIELD_NAMES:
                            return True
    return False


def build_attack_surface(
    spec: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    anonymous: list[dict[str, str]] = []
    writes: list[dict[str, str]] = []
    uploads: list[dict[str, str]] = []
    admin_paths: list[dict[str, str]] = []
    url_inputs: list[dict[str, str]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        endpoint = {"method": method, "path": path, "operation": _operation_name(method, path)}
        if _is_anonymous(spec, operation):
            anonymous.append(endpoint)
        if method in WRITE_METHODS:
            writes.append(endpoint)
        if _has_upload(spec, operation, operation_pointer, path_item):
            uploads.append(endpoint)
        if _has_url_input(spec, operation, operation_pointer, path_item):
            url_inputs.append(endpoint)
        if ADMIN_HINT.search(path) or ADMIN_HINT.search(str(operation.get("operationId", ""))):
            admin_paths.append(endpoint)

    return {
        "title": spec.get("info", {}).get("title", "API") if isinstance(spec.get("info"), dict) else "API",
        "operations": sum(1 for _ in _operation_entries_with_pointers(spec)),
        "unauthenticated_endpoints": anonymous,
        "write_operations": writes,
        "file_upload_endpoints": uploads,
        "url_accepting_endpoints": url_inputs,
        "admin_looking_endpoints": admin_paths,
    }
