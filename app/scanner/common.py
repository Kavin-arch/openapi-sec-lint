"""Shared OpenAPI traversal helpers used by individual scanner checks."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from app.scanner.references import (
    pointer_fragment,
    pointer_join,
    resolve_local_ref_with_pointer,
)

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")


def _openapi_31_or_later(version: Any) -> bool:
    """Return whether a version string denotes OpenAPI 3.1 or newer."""
    if not isinstance(version, str):
        return False
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version)
    return bool(match and (int(match.group(1)), int(match.group(2))) >= (3, 1))


def _operation_entries_with_pointers(
    spec: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any], dict[str, Any], str]]:
    collections = [("paths", spec.get("paths", {}))]
    if _openapi_31_or_later(spec.get("openapi")):
        collections.append(("webhooks", spec.get("webhooks", {})))
    for collection_name, items in collections:
        if not isinstance(items, dict):
            continue
        for path, raw_path_item in items.items():
            source_pointer = pointer_join(pointer_join("", collection_name), path)
            path_item, path_pointer = resolve_local_ref_with_pointer(spec, raw_path_item, source_pointer)
            if not isinstance(path_item, dict):
                continue
            path_label = str(path) if collection_name == "paths" else f"webhook:{path}"
            for method in HTTP_METHODS:
                operation = path_item.get(method)
                if isinstance(operation, dict):
                    yield (
                        method.upper(),
                        path_label,
                        path_item,
                        operation,
                        pointer_join(path_pointer, method),
                    )


def _operation_entries(
    spec: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    for method, path, path_item, operation, _ in _operation_entries_with_pointers(spec):
        yield method, path, path_item, operation


def operations(spec: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for method, path, _, operation in _operation_entries(spec):
        yield method, path, operation


def _operation_name(method: str, path: str) -> str:
    return f"{method} {path}"


def _walk_schema_locations(
    spec: dict[str, Any],
    schema: Any,
    pointer: str = "",
    trail: str = "",
    depth: int = 0,
    seen: set[int] | None = None,
) -> Iterator[tuple[str, str, dict[str, Any]]]:
    reference_context: tuple[str, str, dict[str, Any]] | None = None
    if (
        _openapi_31_or_later(spec.get("openapi"))
        and isinstance(schema, dict)
        and isinstance(schema.get("$ref"), str)
    ):
        siblings = {key: value for key, value in schema.items() if key != "$ref"}
        if siblings:
            target, target_pointer = resolve_local_ref_with_pointer(spec, {"$ref": schema["$ref"]}, pointer)
            if isinstance(target, dict):
                reference_context = (pointer, target_pointer, siblings)
    resolved, resolved_pointer = resolve_local_ref_with_pointer(
        spec, schema, pointer, merge_schema_siblings=_openapi_31_or_later(spec.get("openapi"))
    )
    if depth > 64 or not isinstance(resolved, dict):
        return
    seen = seen if seen is not None else set()
    identity = id(resolved)
    if identity in seen:
        return
    seen.add(identity)

    def child_base(keyword: str, child_key: object | None = None) -> str:
        if reference_context is None:
            return resolved_pointer
        source_pointer, target_pointer, siblings = reference_context
        sibling_value = siblings.get(keyword)
        includes_child = (
            child_key is None
            or (isinstance(sibling_value, dict) and child_key in sibling_value)
            or (
                isinstance(sibling_value, list)
                and isinstance(child_key, int)
                and child_key < len(sibling_value)
            )
        )
        return source_pointer if sibling_value is not None and includes_child else target_pointer

    try:
        yield trail, resolved_pointer, resolved

        properties = resolved.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                child_trail = f"{trail}.{name}" if trail else str(name)
                child_pointer = pointer_join(pointer_join(child_base("properties", name), "properties"), name)
                yield from _walk_schema_locations(spec, child, child_pointer, child_trail, depth + 1, seen)
        for keyword in (
            "items",
            "additionalProperties",
            "contains",
            "not",
            "if",
            "then",
            "else",
            "propertyNames",
            "unevaluatedItems",
            "unevaluatedProperties",
        ):
            child = resolved.get(keyword)
            if isinstance(child, dict):
                child_trail = f"{trail}.{keyword}" if trail else keyword
                yield from _walk_schema_locations(
                    spec,
                    child,
                    pointer_join(child_base(keyword), keyword),
                    child_trail,
                    depth + 1,
                    seen,
                )
            elif keyword == "items" and isinstance(child, list):
                for index, item in enumerate(child):
                    child_trail = f"{trail}.items[{index}]" if trail else f"items[{index}]"
                    child_pointer = pointer_join(pointer_join(child_base(keyword, index), keyword), index)
                    yield from _walk_schema_locations(spec, item, child_pointer, child_trail, depth + 1, seen)
        for keyword in ("allOf", "oneOf", "anyOf", "prefixItems"):
            children = resolved.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    child_trail = f"{trail}.{keyword}[{index}]" if trail else f"{keyword}[{index}]"
                    child_pointer = pointer_join(pointer_join(child_base(keyword, index), keyword), index)
                    yield from _walk_schema_locations(
                        spec, child, child_pointer, child_trail, depth + 1, seen
                    )
        for keyword in ("patternProperties", "dependentSchemas"):
            children = resolved.get(keyword)
            if isinstance(children, dict):
                for name, child in children.items():
                    child_trail = f"{trail}.{keyword}.{name}" if trail else f"{keyword}.{name}"
                    child_pointer = pointer_join(pointer_join(child_base(keyword, name), keyword), name)
                    yield from _walk_schema_locations(
                        spec, child, child_pointer, child_trail, depth + 1, seen
                    )
    finally:
        seen.remove(identity)


def _walk_schema(
    spec: dict[str, Any],
    schema: Any,
    trail: str = "",
    depth: int = 0,
    seen: set[int] | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Compatibility wrapper yielding the historic dotted trail and schema."""
    for field_path, _, node in _walk_schema_locations(spec, schema, trail=trail, depth=depth, seen=seen):
        yield field_path, node


def iter_request_schemas(
    spec: dict[str, Any],
    operation: dict[str, Any],
    operation_pointer: str,
    path_item: dict[str, Any] | None = None,
    parameter_locations: set[str] | None = None,
) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield request schemas with their source pointers for one operation."""
    raw_body = operation.get("requestBody")
    if isinstance(raw_body, dict):
        body, body_pointer = resolve_local_ref_with_pointer(
            spec, raw_body, pointer_join(operation_pointer, "requestBody")
        )
        content = body.get("content", {}) if isinstance(body, dict) else {}
        if isinstance(content, dict):
            for media_type, media in content.items():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    schema_pointer = pointer_join(
                        pointer_join(pointer_join(body_pointer, "content"), media_type), "schema"
                    )
                    yield media["schema"], schema_pointer

    if path_item is None:
        return
    path_pointer = operation_pointer.rsplit("/", 1)[0]
    for source, source_pointer in (
        (path_item, pointer_join(path_pointer, "parameters")),
        (operation, pointer_join(operation_pointer, "parameters")),
    ):
        if not isinstance(source, dict):
            continue
        parameters = source.get("parameters", [])
        if not isinstance(parameters, list):
            continue
        for index, raw_parameter in enumerate(parameters):
            parameter_pointer = pointer_join(source_pointer, index)
            parameter, actual_pointer = resolve_local_ref_with_pointer(spec, raw_parameter, parameter_pointer)
            if not isinstance(parameter, dict) or not isinstance(parameter.get("schema"), dict):
                continue
            if parameter_locations is not None and parameter.get("in") not in parameter_locations:
                continue
            # Swagger 2.0 body parameters and OpenAPI parameter schemas are
            # both useful request inputs to the checks.
            schema_pointer = pointer_join(actual_pointer, "schema")
            yield parameter["schema"], schema_pointer


def iter_response_schemas(
    spec: dict[str, Any],
    operation: dict[str, Any],
    operation_pointer: str,
) -> Iterator[tuple[str, Any, dict[str, Any], str]]:
    """Yield response status, media type, schema, and source pointer."""
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return
    for status, raw_response in responses.items():
        response_pointer = pointer_join(pointer_join(operation_pointer, "responses"), status)
        response, actual_pointer = resolve_local_ref_with_pointer(spec, raw_response, response_pointer)
        if not isinstance(response, dict):
            continue
        content = response.get("content", {})
        if isinstance(content, dict):
            for media_type, media in content.items():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    schema_pointer = pointer_join(
                        pointer_join(pointer_join(actual_pointer, "content"), media_type), "schema"
                    )
                    yield str(status), media_type, media["schema"], schema_pointer
        if isinstance(response.get("schema"), dict):
            # Swagger 2.0 responses keep their schema directly on the response.
            yield str(status), "", response["schema"], pointer_join(actual_pointer, "schema")


def iter_parameters(
    spec: dict[str, Any],
    path_item: dict[str, Any],
    operation: dict[str, Any],
    operation_pointer: str,
) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield effective path/operation parameters and their pointers."""
    effective: dict[tuple[str, str], tuple[dict[str, Any], str]] = {}
    path_pointer = operation_pointer.rsplit("/", 1)[0]
    for source, source_pointer in (
        (path_item.get("parameters", []), pointer_join(path_pointer, "parameters")),
        (operation.get("parameters", []), pointer_join(operation_pointer, "parameters")),
    ):
        if not isinstance(source, list):
            continue
        for index, raw_parameter in enumerate(source):
            parameter, parameter_pointer = resolve_local_ref_with_pointer(
                spec, raw_parameter, pointer_join(source_pointer, index)
            )
            if (
                isinstance(parameter, dict)
                and isinstance(parameter.get("name"), str)
                and isinstance(parameter.get("in"), str)
            ):
                effective[(parameter["name"], parameter["in"])] = (parameter, parameter_pointer)
    yield from effective.values()


def location(operation: str, pointer: str) -> dict[str, str]:
    fragment = pointer if pointer.startswith("#") else pointer_fragment(pointer)
    return {"operation": operation, "pointer": fragment}


def collect_suppressions(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect operation-level and schema-property x-security-ignore entries."""
    suppressions: list[dict[str, Any]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        ignored = operation.get("x-security-ignore")
        if isinstance(ignored, list):
            ids = sorted({item for item in ignored if isinstance(item, str)})
            if ids:
                suppressions.append(
                    {
                        "operation": _operation_name(method, path),
                        "pointer": pointer_fragment(operation_pointer),
                        "scope": "operation",
                        "rule_ids": ids,
                    }
                )
        op_name = _operation_name(method, path)
        for schema, schema_pointer in iter_request_schemas(spec, operation, operation_pointer, path_item):
            for _, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                ignored = node.get("x-security-ignore")
                if "/properties/" in pointer and isinstance(ignored, list):
                    ids = sorted({item for item in ignored if isinstance(item, str)})
                    if ids:
                        suppressions.append(
                            {
                                "operation": op_name,
                                "pointer": pointer_fragment(pointer),
                                "scope": "property",
                                "rule_ids": ids,
                            }
                        )
        for _, _, schema, schema_pointer in iter_response_schemas(spec, operation, operation_pointer):
            for _, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                ignored = node.get("x-security-ignore")
                if "/properties/" in pointer and isinstance(ignored, list):
                    ids = sorted({item for item in ignored if isinstance(item, str)})
                    if ids:
                        suppressions.append(
                            {
                                "operation": op_name,
                                "pointer": pointer_fragment(pointer),
                                "scope": "property",
                                "rule_ids": ids,
                            }
                        )
    return suppressions
