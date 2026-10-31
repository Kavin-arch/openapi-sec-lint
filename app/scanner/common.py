"""Shared OpenAPI traversal helpers used by individual scanner checks."""

from collections.abc import Iterator
from typing import Any

from app.scanner.references import resolve_local_ref

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")


def _operation_entries(
    spec: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any], dict[str, Any]]]:
    collections = [("paths", spec.get("paths", {}))]
    version = spec.get("openapi")
    try:
        supports_webhooks = isinstance(version, str) and tuple(
            int(part) for part in version.split(".")[:2]
        ) >= (3, 1)
    except ValueError:
        supports_webhooks = False
    if supports_webhooks:
        collections.append(("webhooks", spec.get("webhooks", {})))
    for collection_name, items in collections:
        if not isinstance(items, dict):
            continue
        for path, raw_path_item in items.items():
            path_item = resolve_local_ref(spec, raw_path_item)
            if not isinstance(path_item, dict):
                continue
            path_label = str(path) if collection_name == "paths" else f"webhook:{path}"
            for method in HTTP_METHODS:
                operation = path_item.get(method)
                if isinstance(operation, dict):
                    yield method.upper(), path_label, path_item, operation


def operations(spec: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for method, path, _, operation in _operation_entries(spec):
        yield method, path, operation


def _operation_name(method: str, path: str) -> str:
    return f"{method} {path}"


def _walk_schema(
    spec: dict[str, Any], schema: Any, trail: str = "", depth: int = 0,
    seen: set[int] | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    schema = resolve_local_ref(spec, schema)
    if depth > 64 or not isinstance(schema, dict):
        return
    seen = seen if seen is not None else set()
    identity = id(schema)
    if identity in seen:
        return
    seen.add(identity)
    try:
        yield trail, schema

        properties = schema.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                yield from _walk_schema(spec, child, f"{trail}.{name}" if trail else str(name), depth + 1, seen)
        for keyword in (
            "items", "additionalProperties", "contains", "not", "if", "then",
            "else", "propertyNames", "unevaluatedItems", "unevaluatedProperties",
        ):
            child = schema.get(keyword)
            if isinstance(child, dict):
                yield from _walk_schema(spec, child, f"{trail}.{keyword}" if trail else keyword, depth + 1, seen)
            elif keyword == "items" and isinstance(child, list):
                for index, item in enumerate(child):
                    yield from _walk_schema(
                        spec, item, f"{trail}.items[{index}]" if trail else f"items[{index}]",
                        depth + 1, seen,
                    )
        for keyword in ("allOf", "oneOf", "anyOf", "prefixItems"):
            children = schema.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    yield from _walk_schema(spec, child, f"{trail}.{keyword}[{index}]", depth + 1, seen)
        for keyword in ("patternProperties", "dependentSchemas"):
            children = schema.get(keyword)
            if isinstance(children, dict):
                for name, child in children.items():
                    yield from _walk_schema(
                        spec, child, f"{trail}.{keyword}.{name}" if trail else f"{keyword}.{name}",
                        depth + 1, seen,
                    )
    finally:
        seen.remove(identity)
