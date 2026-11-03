from collections.abc import Iterator
from typing import Any

from app.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    location,
)
from app.scanner.models import Finding
from app.scanner.references import pointer_fragment, pointer_join


def _schemes(spec: dict[str, Any]) -> dict[str, Any]:
    components = spec.get("components", {})
    if (
        isinstance(components, dict)
        and isinstance(components.get("securitySchemes"), dict)
        and components["securitySchemes"]
    ):
        return {str(name): value for name, value in components["securitySchemes"].items()}
    legacy = spec.get("securityDefinitions", {})
    return {str(name): value for name, value in legacy.items()} if isinstance(legacy, dict) else {}


def _requirements(value: Any) -> Iterator[tuple[int, str]]:
    if not isinstance(value, list):
        return
    for index, requirement in enumerate(value):
        if isinstance(requirement, dict):
            for name in requirement:
                if isinstance(name, str):
                    yield index, name


def _effective_servers(
    spec: dict[str, Any], path_item: dict[str, Any], operation: dict[str, Any]
) -> list[Any]:
    if isinstance(operation.get("servers"), list):
        return [server for server in operation["servers"]]
    if isinstance(path_item.get("servers"), list):
        return [server for server in path_item["servers"]]
    servers = spec.get("servers", [])
    return [server for server in servers] if isinstance(servers, list) else []


def check_dangling_security_schemes(spec: dict[str, Any]) -> list[Finding]:
    defined = _schemes(spec)
    evidence: list[tuple[str, str, str]] = []
    global_security = spec.get("security", [])
    for index, name in _requirements(global_security) or ():
        if name not in defined:
            pointer = pointer_join(pointer_join("/security", index), name)
            evidence.append(
                (f"Global security uses undefined scheme {name!r}", pointer_fragment(pointer), "API")
            )

    insecure_basic = {
        name
        for name, scheme in defined.items()
        if isinstance(scheme, dict)
        and (
            scheme.get("type") == "basic"
            or (scheme.get("type") == "http" and str(scheme.get("scheme", "")).lower() == "basic")
        )
    }
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)
        has_operation_security = "security" in operation
        requirements = operation["security"] if has_operation_security else global_security
        for index, name in _requirements(requirements) or ():
            if has_operation_security:
                pointer = pointer_join(pointer_join(pointer_join(operation_pointer, "security"), index), name)
                pointer = pointer_fragment(pointer)
            else:
                pointer = pointer_fragment("/security")
            if name not in defined and has_operation_security:
                evidence.append((f"{operation_name} uses undefined scheme {name!r}", pointer, operation_name))
            elif name in insecure_basic:
                if isinstance(operation.get("servers"), list):
                    server_source_pointer = pointer_join(operation_pointer, "servers")
                elif isinstance(path_item.get("servers"), list):
                    server_source_pointer = pointer_join(operation_pointer.rsplit("/", 1)[0], "servers")
                else:
                    server_source_pointer = "/servers"
                for server_index, server in enumerate(_effective_servers(spec, path_item, operation)):
                    if (
                        isinstance(server, dict)
                        and isinstance(server.get("url"), str)
                        and server["url"].lower().startswith("http://")
                    ):
                        server_pointer = pointer_join(server_source_pointer, server_index)
                        evidence.append(
                            (
                                f"{operation_name} uses HTTP Basic with a plain HTTP server",
                                pointer_fragment(server_pointer),
                                operation_name,
                            )
                        )
                swagger_schemes = spec.get("schemes", [])
                if (
                    spec.get("swagger") == "2.0"
                    and isinstance(swagger_schemes, list)
                    and "http" in [str(item).lower() for item in swagger_schemes]
                ):
                    evidence.append(
                        (
                            f"{operation_name} uses HTTP Basic with Swagger's plain HTTP scheme",
                            pointer_fragment("/schemes"),
                            operation_name,
                        )
                    )

    if not evidence:
        return []
    return [
        Finding(
            rule_id="AUTH-002",
            title="A security requirement is unresolved or uses Basic over HTTP",
            severity="high",
            confidence="high",
            summary="A security requirement names no declared scheme, or HTTP Basic is paired with a declared plain HTTP server. This checks the contract only.",
            impact="An undefined scheme can leave clients and reviewers with an incomplete security model. Basic credentials sent over HTTP are exposed to network observers.",
            remediation="Define each referenced scheme and use HTTPS for every server that accepts HTTP Basic credentials.",
            affected_operations=sorted({item[2] for item in evidence if item[2] != "API"})[:100],
            evidence={
                "issues": [item[0] for item in evidence[:100]],
                "json_pointers": [item[1] for item in evidence[:100]],
                "locations": [location(item[2], item[1]) for item in evidence[:100]],
                "total_matches": len(evidence),
                "truncated": len(evidence) > 100,
            },
        )
    ]
