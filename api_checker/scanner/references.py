"""Local JSON Pointer reference resolution for OpenAPI documents."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, unquote_to_bytes


def pointer_token(value: object) -> str:
    """Escape one token for a JSON Pointer string."""
    return str(value).replace("~", "~0").replace("/", "~1")


def pointer_join(pointer: str, token: object) -> str:
    return f"{pointer}/{pointer_token(token)}"


def pointer_fragment(pointer: str) -> str:
    """Render a JSON Pointer as a URI fragment identifier."""
    return f"#{quote(pointer, safe='/~')}" if pointer else "#"


def _decode_fragment(fragment: str) -> str:
    # A fragment is percent-decoded as a whole before JSON Pointer token
    # splitting. Keep this distinct from the JSON Pointer ~0/~1 decoding.
    if re.search(r"%(?![0-9A-Fa-f]{2})", fragment):
        raise ValueError("Invalid percent escape in JSON Pointer fragment.")
    return unquote_to_bytes(fragment).decode("utf-8", errors="strict")


def _decode_pointer_token(token: str) -> str:
    if re.search(r"~(?![01])", token):
        raise ValueError("Invalid JSON Pointer escape.")
    return token.replace("~1", "/").replace("~0", "~")


def _pointer_tokens(reference: str) -> list[str]:
    if not reference.startswith("#"):
        raise ValueError("Only local references are supported.")
    pointer = _decode_fragment(reference[1:])
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise ValueError("A JSON Pointer fragment must start with '/'.")
    return [_decode_pointer_token(token) for token in pointer[1:].split("/")]


def _follow_pointer(spec: dict[str, Any], reference: str) -> tuple[Any, str]:
    target: Any = spec
    pointer = ""
    for token in _pointer_tokens(reference):
        if isinstance(target, list):
            # RFC 6901 permits only unsigned decimal indices without leading
            # zeroes. In particular, Python's negative list indexing is not a
            # valid JSON Pointer operation.
            if not re.fullmatch(r"(?:0|[1-9][0-9]*)", token):
                raise ValueError("Invalid JSON Pointer array index.")
            index = int(token)
            target = target[index]
            pointer = pointer_join(pointer, index)
        elif isinstance(target, dict):
            if token in target:
                target = target[token]
                pointer = pointer_join(pointer, token)
            else:
                # PyYAML preserves unquoted numeric mapping keys as integers;
                # OpenAPI response maps commonly use status keys such as 200.
                if not re.fullmatch(r"(?:0|[1-9][0-9]*)", token):
                    raise KeyError(token)
                numeric_key = int(token)
                if numeric_key not in target:
                    raise KeyError(token)
                target = target[numeric_key]
                pointer = pointer_join(pointer, numeric_key)
        else:
            raise TypeError("JSON Pointer traversed a scalar value.")
    return target, pointer


def resolve_local_ref_with_pointer(
    spec: dict[str, Any], value: Any, source_pointer: str = "", *, merge_schema_siblings: bool = False
) -> tuple[Any, str]:
    """Resolve a local $ref and return its resolved value and document pointer.

    Schema Object siblings are combined only when the caller explicitly asks
    for schema resolution. Generic Reference Objects keep OpenAPI's
    context-specific behavior and are not blindly merged.
    """
    return _resolve_ref_chain(spec, value, source_pointer, merge_schema_siblings, set())


def _resolve_ref_chain(
    spec: dict[str, Any],
    value: Any,
    source_pointer: str,
    merge_schema_siblings: bool,
    visited: set[int],
) -> tuple[Any, str]:
    if not isinstance(value, dict) or not isinstance(value.get("$ref"), str):
        return value, source_pointer
    reference = value["$ref"]
    if not reference.startswith("#"):
        return value, source_pointer
    try:
        target, target_pointer = _follow_pointer(spec, reference)
    except (KeyError, IndexError, ValueError, TypeError, UnicodeDecodeError):
        return value, source_pointer
    if not isinstance(target, dict | list) or id(target) in visited:
        return target, target_pointer
    visited.add(id(target))
    resolved_target, resolved_pointer = _resolve_ref_chain(
        spec, target, target_pointer, merge_schema_siblings, visited
    )
    siblings = {key: child for key, child in value.items() if key != "$ref"}
    if merge_schema_siblings and isinstance(resolved_target, dict) and siblings:
        # Schema Object siblings in OpenAPI 3.1 remain active alongside the
        # referenced schema. Preserve object-valued keyword maps for traversal.
        return _merge_schema_maps(resolved_target, siblings), source_pointer or resolved_pointer
    return resolved_target, resolved_pointer


def _merge_schema_maps(target: dict[str, Any], siblings: dict[str, Any]) -> dict[str, Any]:
    merged = dict(target)
    for key, sibling in siblings.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(sibling, dict):
            merged[key] = _merge_schema_maps(existing, sibling)
        else:
            merged[key] = sibling
    return merged


def resolve_local_ref(spec: dict[str, Any], value: Any) -> Any:
    """Follow local JSON Pointer references without retrieving external files."""
    return resolve_local_ref_with_pointer(spec, value)[0]


def resolve_schema_ref(spec: dict[str, Any], value: Any) -> Any:
    """Resolve schema references while retaining OpenAPI 3.1 schema siblings."""
    from api_checker.scanner.common import _openapi_31_or_later

    if _openapi_31_or_later(spec.get("openapi")):
        return resolve_local_ref_with_pointer(spec, value, merge_schema_siblings=True)[0]
    return resolve_local_ref(spec, value)
