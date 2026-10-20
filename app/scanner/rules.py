from collections.abc import Iterator
import re
from typing import Any

from app.scanner.models import Finding

HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
SENSITIVE_NAMES = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "private_key", "ssn", "credit_card", "client_secret",
}


def operations(spec: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if isinstance(operation, dict):
                yield method.upper(), str(path), operation


def _operation_name(method: str, path: str) -> str:
    return f"{method} {path}"


def _check_auth(spec: dict[str, Any]) -> list[Finding]:
    missing = []
    global_security = spec.get("security")
    for method, path, operation in operations(spec):
        requirements = operation["security"] if "security" in operation else global_security
        if not requirements:
            missing.append(_operation_name(method, path))
    if not missing:
        return []
    return [Finding(
        rule_id="AUTH-001",
        title="Authentication is not declared for some operations",
        severity="medium",
        confidence="high",
        summary=(
            "The specification has no effective security requirement for the listed operations. "
            "This is a documentation signal; the live API may enforce authentication separately."
        ),
        impact="If these operations are also unauthenticated at runtime, callers may reach data or actions without signing in.",
        remediation="Declare the appropriate OpenAPI security requirement and verify authentication is enforced by the API for each operation.",
        affected_operations=missing[:100],
        evidence={"operation_count": len(missing), "truncated": len(missing) > 100},
    )]


def _check_transport(spec: dict[str, Any]) -> list[Finding]:
    insecure_urls: list[str] = []
    for server in spec.get("servers", []) if isinstance(spec.get("servers", []), list) else []:
        if isinstance(server, dict) and isinstance(server.get("url"), str) and server["url"].lower().startswith("http://"):
            insecure_urls.append(server["url"])

    # Swagger 2.0 stores schemes and host/basePath separately.
    if spec.get("swagger") == "2.0":
        schemes = spec.get("schemes")
        if isinstance(schemes, list) and "http" in [str(item).lower() for item in schemes]:
            insecure_urls.append(f"http://{spec.get('host', '<host>')}{spec.get('basePath', '')}")

    if not insecure_urls:
        return []
    return [Finding(
        rule_id="TRANSPORT-001",
        title="The specification advertises an unencrypted HTTP server",
        severity="medium",
        confidence="high",
        summary="At least one declared server uses HTTP. The specification does not prove whether HTTPS is also configured or enforced.",
        impact="Traffic sent over plain HTTP can be read or modified by parties on the network path.",
        remediation="Prefer HTTPS for API traffic and redirect or reject plaintext HTTP at the service boundary.",
        evidence={"servers": sorted(set(insecure_urls))[:20]},
    )]


def _resolve_local_ref(spec: dict[str, Any], value: Any) -> Any:
    """Resolve internal JSON Pointers without fetching external references."""
    visited: set[int] = set()
    while isinstance(value, dict) and isinstance(value.get("$ref"), str):
        reference = value["$ref"]
        if not reference.startswith("#/"):
            return value
        target: Any = spec
        try:
            for token in reference[2:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                target = target[int(token)] if isinstance(target, list) else target[token]
        except (KeyError, IndexError, ValueError, TypeError):
            return value
        if not isinstance(target, (dict, list)) or id(target) in visited:
            return target
        visited.add(id(target))
        value = target
    return value


def _walk_schema(
    spec: dict[str, Any], schema: Any, trail: str = "", depth: int = 0,
    seen: set[int] | None = None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    schema = _resolve_local_ref(spec, schema)
    if depth > 12 or not isinstance(schema, dict):
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
        for keyword in ("items", "additionalProperties"):
            child = schema.get(keyword)
            if isinstance(child, dict):
                yield from _walk_schema(spec, child, f"{trail}.{keyword}" if trail else keyword, depth + 1, seen)
        for keyword in ("allOf", "oneOf", "anyOf"):
            children = schema.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    yield from _walk_schema(spec, child, f"{trail}.{keyword}[{index}]", depth + 1, seen)
    finally:
        seen.remove(identity)


def _check_sensitive_response_fields(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str]] = []
    for method, path, operation in operations(spec):
        responses = operation.get("responses", {})
        if not isinstance(responses, dict):
            continue
        for status, response in responses.items():
            response = _resolve_local_ref(spec, response)
            if not isinstance(response, dict):
                continue
            content = response.get("content", {})
            schemas = []
            if isinstance(content, dict):
                for media_type, media in content.items():
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                        schemas.append((f"response {status} {media_type}", media["schema"]))
            # Swagger 2.0 response schemas live directly on the response object.
            if isinstance(response.get("schema"), dict):
                schemas.append((f"response {status}", response["schema"]))
            for label, schema in schemas:
                for field_path, node in _walk_schema(spec, schema):
                    leaf = field_path.rsplit(".", 1)[-1]
                    leaf = re.sub(r"(?<!^)([A-Z])", r"_\1", leaf).lower().replace("-", "_")
                    if leaf in SENSITIVE_NAMES and node.get("writeOnly") is not True:
                        matches.append((_operation_name(method, path), f"{label}: {field_path}"))

    if not matches:
        return []
    return [Finding(
        rule_id="DATA-001",
        title="A response schema contains a potentially sensitive field",
        severity="medium",
        confidence="low",
        summary="A response schema uses a field name commonly associated with secrets or personal data. This heuristic may flag legitimate fields and does not inspect live responses.",
        impact="If the field contains a real secret or sensitive value, returning it to an unintended caller could expose data.",
        remediation="Review the field and access policy. Omit secrets from responses, and mark request-only fields as writeOnly where appropriate.",
        affected_operations=sorted({item[0] for item in matches})[:100],
        evidence={"schema_fields": [item[1] for item in matches[:100]], "truncated": len(matches) > 100},
    )]


def _check_unbounded_arrays(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str]] = []
    for method, path, operation in operations(spec):
        request_body = _resolve_local_ref(spec, operation.get("requestBody", {}))
        content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
        candidate_schemas: list[dict[str, Any]] = []
        if isinstance(content, dict):
            for media in content.values():
                if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                    candidate_schemas.append(media["schema"])
        # Swagger 2.0 body parameters use `in: body` and a schema.
        for parameter in operation.get("parameters", []) if isinstance(operation.get("parameters", []), list) else []:
            if isinstance(parameter, dict) and parameter.get("in") == "body" and isinstance(parameter.get("schema"), dict):
                candidate_schemas.append(parameter["schema"])
        for schema in candidate_schemas:
            for field_path, node in _walk_schema(spec, schema):
                if node.get("type") == "array" and "maxItems" not in node:
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


def run_rules(spec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for check in (_check_auth, _check_transport, _check_sensitive_response_fields, _check_unbounded_arrays):
        findings.extend(check(spec))
    return findings
