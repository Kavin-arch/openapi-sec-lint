from typing import Any
from urllib.parse import unquote


def resolve_local_ref(spec: dict[str, Any], value: Any) -> Any:
    """Follow local JSON Pointer references without retrieving external files."""
    visited: set[int] = set()
    while isinstance(value, dict) and isinstance(value.get("$ref"), str):
        reference = value["$ref"]
        if reference != "#" and not reference.startswith("#/"):
            return value

        target: Any = spec
        try:
            pointer = unquote(reference[1:])
            tokens = pointer.split("/")[1:] if pointer else []
            for token in tokens:
                token = token.replace("~1", "/").replace("~0", "~")
                target = target[int(token)] if isinstance(target, list) else target[token]
        except (KeyError, IndexError, ValueError, TypeError):
            return value

        if not isinstance(target, (dict, list)) or id(target) in visited:
            return target
        visited.add(id(target))
        value = target
    return value
