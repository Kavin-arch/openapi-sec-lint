import re
from functools import lru_cache
from typing import Any

from api_checker.scanner.common import (
    _openapi_31_or_later,
    _operation_entries_with_pointers,
    _operation_name,
    check_schema_time,
    iter_response_schemas,
    location,
    visit_schema_node,
)
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment, pointer_join, resolve_local_ref_with_pointer

SENSITIVE_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "passwords",
    "password_hash",
    "passwordhash",
    "tokens",
    "api_key",
    "api_keys",
    "apikey",
    "private_key",
    "ssn",
    "credit_card",
    "credit_cards",
    "client_secret",
    "secrets",
    "authtoken",
    "cvv",
    "cvc",
    "dob",
    "date_of_birth",
    "secretkey",
    "auth_token",
    "credential",
    "credentials",
}
_PAGINATION_NAMES = {"cursor", "page_token", "next_page_token", "next_cursor", "continuation_token", "pagination_token", "next_token"}

_SensitiveMatch = tuple[str, str]
_CachedSchemaMatches = tuple[dict[str, Any], str, str, tuple[_SensitiveMatch, ...]]


@lru_cache(maxsize=8192)
def _is_sensitive_name(name: str) -> bool:
    leaf = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    leaf = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", leaf).lower().replace("-", "_")
    tokens = set(re.findall(r"[a-z0-9]+", leaf))
    return (
        leaf in SENSITIVE_NAMES
        or bool(tokens & {"password", "passwd", "secret", "token", "ssn", "cvv", "cvc", "dob"})
        or ("key" in tokens and bool(tokens & {"api", "private", "secret", "access"}))
        or ("birth" in tokens and "date" in tokens)
    )


def _rebase_trail(value: str, source: str, target: str) -> str:
    if value == source:
        return target
    if source and value.startswith(source + "."):
        return target + value[len(source):]
    if not source and target and value:
        return f"{target}.{value}"
    return value


def _rebase_pointer(value: str, source: str, target: str) -> str:
    if value == source:
        return target
    if source and value.startswith(source + "/"):
        return target + value[len(source):]
    if not source and value.startswith("/"):
        return target + value
    return value


def _sensitive_fields(
    spec: dict[str, Any],
    schema: Any,
    pointer: str,
    trail: str,
    depth: int,
    active: set[int],
    cache: dict[int, _CachedSchemaMatches],
) -> list[_SensitiveMatch]:
    is_openapi_31 = _openapi_31_or_later(spec.get("openapi"))
    reference_context: tuple[str, str, dict[str, Any]] | None = None
    if is_openapi_31 and isinstance(schema, dict) and isinstance(schema.get("$ref"), str):
        siblings = {key: value for key, value in schema.items() if key != "$ref"}
        if siblings:
            target, target_pointer = resolve_local_ref_with_pointer(
                spec, {"$ref": schema["$ref"]}, pointer
            )
            if isinstance(target, dict):
                reference_context = (pointer, target_pointer, siblings)
    resolved, resolved_pointer = resolve_local_ref_with_pointer(
        spec, schema, pointer, merge_schema_siblings=is_openapi_31
    )
    if depth > 64 or not isinstance(resolved, dict):
        return []

    identity = id(resolved)
    if identity in active:
        return []
    cached = cache.get(identity)
    if cached is not None:
        _, source_trail, source_pointer, cached_matches = cached
        check_schema_time()
        return [
            (_rebase_trail(field_path, source_trail, trail), _rebase_pointer(field_pointer, source_pointer, resolved_pointer))
            for field_path, field_pointer in cached_matches
        ]

    visit_schema_node()
    active.add(identity)
    matches: list[_SensitiveMatch] = []
    field_name = trail.rsplit(".", 1)[-1].replace("-", "_").lower() if trail else ""
    pagination_token = "token" in field_name and any(part in field_name for part in ("page", "cursor", "continuation", "next"))
    if trail and field_name not in _PAGINATION_NAMES and not pagination_token and _is_sensitive_name(trail.rsplit(".", 1)[-1]) and resolved.get("writeOnly") is not True:
        matches.append((trail, resolved_pointer))

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

    def visit(child: Any, child_pointer: str, child_trail: str) -> None:
        matches.extend(
            _sensitive_fields(spec, child, child_pointer, child_trail, depth + 1, active, cache)
        )

    try:
        properties = resolved.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                child_trail = f"{trail}.{name}" if trail else str(name)
                child_pointer = pointer_join(pointer_join(child_base("properties", name), "properties"), name)
                visit(child, child_pointer, child_trail)
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
                visit(child, pointer_join(child_base(keyword), keyword), child_trail)
            elif keyword == "items" and isinstance(child, list):
                for index, item in enumerate(child):
                    child_trail = f"{trail}.items[{index}]" if trail else f"items[{index}]"
                    child_pointer = pointer_join(pointer_join(child_base(keyword, index), keyword), index)
                    visit(item, child_pointer, child_trail)
        for keyword in ("allOf", "oneOf", "anyOf", "prefixItems"):
            children = resolved.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    child_trail = f"{trail}.{keyword}[{index}]" if trail else f"{keyword}[{index}]"
                    child_pointer = pointer_join(pointer_join(child_base(keyword, index), keyword), index)
                    visit(child, child_pointer, child_trail)
        for keyword in ("patternProperties", "dependentSchemas"):
            children = resolved.get(keyword)
            if isinstance(children, dict):
                for name, child in children.items():
                    child_trail = f"{trail}.{keyword}.{name}" if trail else f"{keyword}.{name}"
                    child_pointer = pointer_join(pointer_join(child_base(keyword, name), keyword), name)
                    visit(child, child_pointer, child_trail)
    finally:
        active.remove(identity)

    cache[identity] = (resolved, trail, resolved_pointer, tuple(matches))
    return matches


def check_sensitive_response_fields(spec: dict[str, Any]) -> list[Finding]:
    matches: dict[str, tuple[str, set[str]]] = {}
    schema_cache: dict[int, _CachedSchemaMatches] = {}
    for method, path, _, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)
        for status, media_type, schema, schema_pointer in iter_response_schemas(
            spec, operation, operation_pointer
        ):
            label = f"response {status} {media_type}".strip()
            for field_path, pointer in _sensitive_fields(
                spec, schema, schema_pointer, "", 0, set(), schema_cache
            ):
                pointer_fragment_value = pointer_fragment(pointer)
                field_label = f"{label}: {field_path}"
                if pointer_fragment_value not in matches:
                    matches[pointer_fragment_value] = (field_label, {operation_name})
                else:
                    matches[pointer_fragment_value][1].add(operation_name)

    if not matches:
        return []
    entries = list(matches.items())
    affected_operations = sorted(
        {operation for _, operations in matches.values() for operation in operations}
    )
    locations = []
    for pointer, (_, operations) in entries:
        operation_names = sorted(operations)
        item = location(operation_names[0], pointer)
        item["affected_operations"] = operation_names
        locations.append(item)
    return [
        Finding(
            rule_id="DATA-001",
            title="A response schema contains a potentially sensitive field",
            severity="medium",
            confidence="low",
            summary="A response schema uses a field name commonly associated with secrets or personal data. This heuristic may flag legitimate fields and does not inspect live responses.",
            impact="If the field contains a real secret or sensitive value, returning it to an unintended caller could expose data.",
            remediation="Review the field and access policy. Omit secrets from responses, and mark request-only fields as writeOnly where appropriate.",
            affected_operations=affected_operations,
            evidence={
                "schema_fields": [field_label for _, (field_label, _) in entries],
                "json_pointers": [pointer for pointer, _ in entries],
                "locations": locations,
            },
        )
    ]
