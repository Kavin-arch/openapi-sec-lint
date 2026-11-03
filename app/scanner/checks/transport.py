from collections.abc import Iterator
from typing import Any

from app.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    location,
)
from app.scanner.models import Finding
from app.scanner.references import pointer_fragment, pointer_join, resolve_local_ref_with_pointer


def _server_entries(spec: dict[str, Any]) -> Iterator[tuple[Any, str, str | None]]:
    for index, server in enumerate(spec.get("servers", []) if isinstance(spec.get("servers"), list) else []):
        yield server, pointer_join("/servers", index), None
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        path_pointer = operation_pointer.rsplit("/", 1)[0]
        for index, server in enumerate(
            path_item.get("servers", []) if isinstance(path_item.get("servers"), list) else []
        ):
            yield (
                server,
                pointer_join(pointer_join(path_pointer, "servers"), index),
                _operation_name(method, path),
            )
        for index, server in enumerate(
            operation.get("servers", []) if isinstance(operation.get("servers"), list) else []
        ):
            yield (
                server,
                pointer_join(pointer_join(operation_pointer, "servers"), index),
                _operation_name(method, path),
            )


def check_transport(spec: dict[str, Any]) -> list[Finding]:
    insecure: list[tuple[str, str, str | None]] = []
    for server, server_pointer, operation in _server_entries(spec):
        resolved, actual_pointer = resolve_local_ref_with_pointer(spec, server, server_pointer)
        if isinstance(resolved, dict) and isinstance(resolved.get("url"), str):
            url = resolved["url"]
            if url.lower().startswith("http://"):
                insecure.append((url, pointer_fragment(actual_pointer), operation))

    # Swagger 2.0 stores schemes and host/basePath separately.
    if spec.get("swagger") == "2.0":
        schemes = spec.get("schemes")
        if isinstance(schemes, list) and "http" in [str(item).lower() for item in schemes]:
            url = f"http://{spec.get('host', '<host>')}{spec.get('basePath', '')}"
            insecure.append((url, pointer_fragment("/schemes"), None))

    if not insecure:
        return []
    operations = sorted({operation for _, _, operation in insecure if operation})
    return [
        Finding(
            rule_id="TRANSPORT-001",
            title="The specification advertises an unencrypted HTTP server",
            severity="medium",
            confidence="high",
            summary="At least one declared server uses HTTP. The specification does not prove whether HTTPS is also configured or enforced.",
            impact="Traffic sent over plain HTTP can be read or modified by parties on the network path.",
            remediation="Prefer HTTPS for API traffic and redirect or reject plaintext HTTP at the service boundary.",
            affected_operations=operations[:100],
            evidence={
                "servers": [url for url, _, _ in insecure[:100]],
                "json_pointers": [pointer for _, pointer, _ in insecure[:100]],
                "locations": [
                    location(operation or "API server", pointer) for _, pointer, operation in insecure[:100]
                ],
                "total_matches": len(insecure),
                "truncated": len(insecure) > 100,
            },
        )
    ]


def check_server_variables_and_websockets(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str | None]] = []
    for server, server_pointer, operation in _server_entries(spec):
        resolved, actual_pointer = resolve_local_ref_with_pointer(spec, server, server_pointer)
        if not isinstance(resolved, dict) or not isinstance(resolved.get("url"), str):
            continue
        url = resolved["url"].strip()
        if url.lower().startswith("ws://"):
            matches.append(
                (f"Unencrypted WebSocket server: {url}", pointer_fragment(actual_pointer), operation)
            )
            continue
        if not url.startswith("{") or "://" not in url:
            continue
        variable_name = url[1:].split("}", 1)[0]
        if not variable_name or not url.startswith(f"{{{variable_name}}}://"):
            continue
        variables = resolved.get("variables", {})
        variable = variables.get(variable_name) if isinstance(variables, dict) else None
        if not isinstance(variable, dict):
            continue
        values = [variable.get("default")]
        enum = variable.get("enum")
        if isinstance(enum, list):
            values.extend(enum)
        if any(isinstance(value, str) and value.lower() == "http" for value in values):
            matches.append(
                (
                    f"Server scheme variable {variable_name!r} permits plain HTTP",
                    pointer_fragment(actual_pointer),
                    operation,
                )
            )

    if not matches:
        return []
    return [
        Finding(
            rule_id="TRANSPORT-002",
            title="A server template permits unencrypted transport",
            severity="medium",
            confidence="medium",
            summary="A templated server scheme permits HTTP or a server uses unencrypted WebSocket transport. This is a specification review signal; runtime routing may impose stricter transport rules.",
            impact="Clients may send credentials or data over an unencrypted connection if they select the insecure value.",
            remediation="Remove HTTP from server variable defaults and enums, and use wss:// for WebSocket endpoints.",
            affected_operations=sorted({item[2] for item in matches if item[2]})[:100],
            evidence={
                "servers": [item[0] for item in matches[:100]],
                "json_pointers": [item[1] for item in matches[:100]],
                "locations": [location(item[2] or "API server", item[1]) for item in matches[:100]],
                "total_matches": len(matches),
                "truncated": len(matches) > 100,
            },
        )
    ]
