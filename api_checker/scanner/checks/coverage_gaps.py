"""Heuristic checks for common API security contract gaps."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from api_checker.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _swagger_parameter_schema,
    iter_parameters,
    location,
)
from api_checker.scanner.models import Finding, Severity
from api_checker.scanner.references import pointer_fragment, pointer_join

_ADMIN = re.compile(r"(?:^|[/_.-])(admin|administrator|manage|management|moderator|privileged)(?:$|[/_.-])", re.I)
_BUSINESS_FLOWS = re.compile(r"\b(transfers?|checkouts?|purchases?|payments?|payouts?|withdraw(?:al)?s?|coupons?|vouchers?|invites?|signups?|registrations?|votes?|likes?|follows?|messages?|comments?)\b", re.I)
_PAGINATION = re.compile(r"(?:^|[_-])(page|pagesize|perpage|limit|offset|cursor|continuationtoken|nexttoken|sort|order)(?:$|[_-])", re.I)
_SECRET = re.compile(r"(?:^|[_-])(api[_-]?key|access[_-]?token|token|password|passwd|secret|authorization|auth)(?:$|[_-])", re.I)


def _finding(rule_id: str, title: str, summary: str, remediation: str, items: list[tuple[str, str, str]], severity: Severity = "medium") -> list[Finding]:
    if not items:
        return []
    return [Finding(
        rule_id=rule_id, title=title, severity=severity, confidence="low",
        summary=summary, impact="Review the contract signal against runtime behavior and the intended API design.",
        remediation=remediation,
        affected_operations=sorted({op for op, _, _ in items if op != "API"}),
        evidence={"issues": [issue for _, _, issue in items],
                  "json_pointers": [pointer_fragment(ptr) for _, ptr, _ in items],
                  "locations": [location(op, ptr) for op, ptr, _ in items],
                  "total_matches": len(items), "truncated": len(items) > 100},
    )]


def _responses(operation: dict[str, Any]) -> dict[str, Any]:
    value = operation.get("responses", {})
    return value if isinstance(value, dict) else {}


def _request_schemas(spec: dict[str, Any], operation: dict[str, Any], pointer: str) -> Iterator[tuple[str, dict[str, Any], str]]:
    body = operation.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content", {})
        if isinstance(content, dict):
            for media, entry in content.items():
                if isinstance(entry, dict) and isinstance(entry.get("schema"), dict):
                    yield str(media), entry["schema"], pointer_join(pointer_join(pointer_join(pointer, "requestBody"), "content"), media)
    if spec.get("swagger") == "2.0":
        for index, param in enumerate(operation.get("parameters", [])):
            if isinstance(param, dict) and param.get("in") == "formData":
                yield "multipart/form-data", param, pointer_join(pointer_join(pointer, "parameters"), index)


def _schema_inputs(schema: Any, pointer: str, trail: str = "", depth: int = 0) -> Iterator[tuple[dict[str, Any], str, str]]:
    if depth > 32 or not isinstance(schema, dict):
        return
    yield schema, pointer, trail
    props = schema.get("properties")
    if isinstance(props, dict):
        for name, child in props.items():
            yield from _schema_inputs(child, pointer_join(pointer_join(pointer, "properties"), name), f"{trail}.{name}" if trail else str(name), depth + 1)
    for key in ("items", "additionalProperties"):
        child = schema.get(key)
        if isinstance(child, dict):
            yield from _schema_inputs(child, pointer_join(pointer, key), f"{trail}.{key}" if trail else key, depth + 1)
    for key in ("allOf", "oneOf", "anyOf"):
        children = schema.get(key)
        if isinstance(children, list):
            for index, child in enumerate(children):
                yield from _schema_inputs(child, pointer_join(pointer_join(pointer, key), index), trail, depth + 1)


def check_function_authorization(spec: dict[str, Any]) -> list[Finding]:
    items = []
    security = spec.get("security", [])
    for method, path, _, operation, ptr in _operation_entries_with_pointers(spec):
        if not _ADMIN.search(path) and not _ADMIN.search(str(operation.get("operationId", ""))):
            continue
        requirements = operation.get("security", security)
        scopes = {scope.lower() for req in requirements if isinstance(req, dict) for values in req.values() if isinstance(values, list) for scope in values} if isinstance(requirements, list) else set()
        role_scoped = any(any(word in scope for word in ("admin", "write", "manage", "moderate")) for scope in scopes)
        has_auth = bool(requirements) and isinstance(requirements, list) and all(isinstance(req, dict) and req for req in requirements)
        if not (has_auth and role_scoped):
            items.append((_operation_name(method, path), ptr, "Admin-looking operation lacks documented authentication or a role-like scope"))
    return _finding("AUTH-004", "Admin-looking operations lack role scope documentation", "Path and operation names are heuristics; role-based authorization may be enforced outside OpenAPI.", "Document required authentication and function-level scopes for privileged operations.", items)


def check_sensitive_business_flows(spec: dict[str, Any]) -> list[Finding]:
    items = []
    for method, path, _, operation, ptr in _operation_entries_with_pointers(spec):
        text = f"{path} {operation.get('operationId', '')} {operation.get('summary', '')} {operation.get('description', '')}"
        if method in {"POST", "PUT", "PATCH", "DELETE"} and _BUSINESS_FLOWS.search(text):
            items.append((_operation_name(method, path), ptr, "Potentially abuse-prone business flow should be reviewed for rate, replay, and eligibility controls"))
    return _finding("FLOW-001", "Sensitive business flow needs abuse-control review", "Names associated with financial or user-amplifying actions can identify flows that need runtime business controls.", "Verify rate limits, idempotency, eligibility checks, and abuse monitoring for the operation.", items, "low")


def check_configuration_exposure(spec: dict[str, Any]) -> list[Finding]:
    items = []
    for method, path, _, operation, op_ptr in _operation_entries_with_pointers(spec):
        for status, response in _responses(operation).items():
            if str(status).startswith("5") and isinstance(response, dict):
                schema = response.get("content", {})
                text = str(schema).lower()
                if any(term in text for term in ("stacktrace", "stack_trace", "exception", "debug", "traceback", "internalerror")):
                    items.append((_operation_name(method, path), pointer_join(pointer_join(op_ptr, "responses"), status), "5xx response schema appears to expose verbose error details"))
        for media in (operation.get("requestBody", {}).get("content", {}) if isinstance(operation.get("requestBody"), dict) else {}):
            if isinstance(media, str) and (media == "*/*" or media.endswith("/*")):
                items.append((_operation_name(method, path), pointer_join(pointer_join(pointer_join(op_ptr, "requestBody"), "content"), media), "Wildcard request media type broadens accepted input types"))
    servers = spec.get("servers", [])
    for index, server in enumerate(servers if isinstance(servers, list) else []):
        if not isinstance(server, dict):
            continue
        url = str(server.get("url", "")).lower()
        if any(host in url for host in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", ".internal", ".local")):  # nosec B104 - inspect untrusted URL text; no socket is bound here.
            items.append(("API", pointer_join(pointer_join("", "servers"), index), "Server URL points to a localhost or internal-looking host"))
    return _finding("CONFIG-001", "Potential information exposure or unsafe configuration", "Error schemas, wildcard media types, and internal server addresses can indicate deployment or contract misconfiguration.", "Remove implementation details from public errors, constrain media types, and keep internal server URLs out of public specs.", items)


def check_inventory_lifecycle(spec: dict[str, Any]) -> list[Finding]:
    items = []
    for method, path, _, operation, ptr in _operation_entries_with_pointers(spec):
        if operation.get("deprecated") is True:
            items.append((_operation_name(method, path), pointer_join(ptr, "deprecated"), "Deprecated operation remains exposed in the specification"))
        if re.search(r"(?:^|/)v(?:1|beta|alpha|preview)(?:/|$)", path, re.I):
            items.append((_operation_name(method, path), ptr, "Version or prerelease route may represent an unmanaged API inventory entry"))
    return _finding("INV-001", "Deprecated or prerelease API surface needs inventory review", "Deprecated and prerelease routes can remain accessible after their intended lifetime.", "Document ownership, exposure, and retirement dates for each API version and deprecated route.", items, "low")


def check_unsafe_consumption(spec: dict[str, Any]) -> list[Finding]:
    items = []
    for method, path, _, operation, op_ptr in _operation_entries_with_pointers(spec):
        text = f"{path} {operation.get('operationId', '')} {operation.get('summary', '')} {operation.get('description', '')}"
        if re.search(r"(?:third.party|external|provider|partner|import|synchroni[sz]e|fetch|consume)", text, re.I):
            items.append((_operation_name(method, path), op_ptr, "Operation appears to consume or import data from an external system"))
    return _finding("CONSUME-001", "External data consumption needs validation review", "Operation metadata suggests that the service may import or consume data from an external system; the specification cannot establish whether that data is trusted or validated.", "Validate upstream responses against explicit schemas, constrain content types and sizes, and treat third-party data as untrusted input.", items, "medium")


def check_operation_contract_gaps(spec: dict[str, Any]) -> list[Finding]:
    items = []
    for method, path, path_item, operation, op_ptr in _operation_entries_with_pointers(spec):
        responses = _responses(operation)
        for status in ("401", "403", "429"):
            if not any(str(code) == status or str(code).lower() == "default" for code in responses):
                items.append((_operation_name(method, path), pointer_join(pointer_join(op_ptr, "responses"), status), f"No documented {status} response"))
        for param, param_ptr in iter_parameters(spec, path_item, operation, op_ptr):
            if not isinstance(param, dict) or param.get("in") not in {"query", "cookie"}:
                continue
            param_name = str(param.get("name", ""))
            if _SECRET.search(param_name):
                items.append((_operation_name(method, path), param_ptr, "Credential-like value appears in a query or cookie parameter"))
        for param, param_ptr in iter_parameters(spec, path_item, operation, op_ptr):
            name = str(param.get("name", ""))
            schema = param.get("schema")
            schema_ptr = pointer_join(param_ptr, "schema")
            if not isinstance(schema, dict) and spec.get("swagger") == "2.0":
                schema = _swagger_parameter_schema(param)
                schema_ptr = param_ptr
            for node, ptr, trail in _schema_inputs(schema, schema_ptr, name):
                if node.get("type") == "string" and not _PAGINATION.search(name) and not node.get("maxLength") and not node.get("pattern"):
                    items.append((_operation_name(method, path), ptr, f"String parameter {name or trail} has no maxLength or pattern"))
        for media, schema, schema_ptr in _request_schemas(spec, operation, op_ptr):
            if media.startswith("multipart/"):
                items.append((_operation_name(method, path), schema_ptr, "Multipart upload contract does not declare a portable request-size limit"))
            for node, ptr, trail in _schema_inputs(schema, schema_ptr):
                leaf = trail.rsplit(".", 1)[-1] if trail else ""
                if re.search(r"(?:^|[_-])(password|passwd)(?:$|[_-])", leaf, re.I) and node.get("format") != "password":
                    items.append((_operation_name(method, path), ptr, f"Credential-like field {trail or '<body>'} lacks format: password"))
                if node.get("type") == "string" and node.get("format") == "password" and not node.get("maxLength"):
                    items.append((_operation_name(method, path), ptr, f"Password input {trail or '<body>'} has no maxLength"))
                if node.get("type") == "string" and not _PAGINATION.search(trail.rsplit(".", 1)[-1] if trail else "") and not node.get("maxLength") and not node.get("pattern"):
                    items.append((_operation_name(method, path), ptr, f"String input {trail or '<body>'} has no maxLength or pattern"))
    return _finding("CONTRACT-001", "Request or response contract has common security gaps", "Credential placement, response codes, upload limits, and bounded string inputs are not fully described by this contract.", "Keep credentials out of URLs, document relevant error responses, limit upload bytes at the API gateway, and bound untrusted strings.", items, "low")


def check_oauth_unsafe_flows(spec: dict[str, Any]) -> list[Finding]:
    items = []
    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    schemes = schemes if isinstance(schemes, dict) else {}
    if spec.get("swagger") == "2.0":
        schemes = spec.get("securityDefinitions", {}) if isinstance(spec.get("securityDefinitions"), dict) else {}
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict) or scheme.get("type") != "oauth2":
            continue
        flows = scheme.get("flows") if isinstance(scheme.get("flows"), dict) else {}
        if spec.get("swagger") == "2.0":
            flow = str(scheme.get("flow", "")).lower()
            if flow in {"implicit", "password"}:
                items.append(("API", pointer_join(pointer_join("/securityDefinitions", name), "flow"), f"OAuth {flow} flow is discouraged"))
        else:
            for flow in ("implicit", "password"):
                if not isinstance(flows, dict):
                    continue
                if flow in flows:
                    items.append(("API", pointer_join(pointer_join(pointer_join("/components/securitySchemes", name), "flows"), flow), f"OAuth {flow} flow is discouraged"))
    return _finding("AUTH-005", "Discouraged OAuth flow is documented", "Implicit and resource-owner password flows expose tokens or credentials to clients and are deprecated by current OAuth security guidance.", "Prefer authorization code with PKCE for user authorization or client credentials for machine-to-machine access.", items)
