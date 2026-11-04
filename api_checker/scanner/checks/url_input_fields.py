from typing import Any

from api_checker.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _walk_schema_locations,
    iter_parameters,
    iter_request_schemas,
    location,
)
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment, pointer_join

URL_FIELD_NAMES = {
    "url",
    "uri",
    "webhook_url",
    "webhookurl",
    "callback_url",
    "callbackurl",
    "redirect_uri",
    "redirecturi",
    "return_url",
    "returnurl",
    "endpoint_url",
    "endpointurl",
}


def _looks_like_url_field(name: str) -> bool:
    normalized = name.replace("-", "_").lower()
    compact = normalized.replace("_", "")
    return normalized in URL_FIELD_NAMES or compact in URL_FIELD_NAMES


def check_url_input_fields(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str]] = []
    for method, path, path_item, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)

        def inspect(
            schema: Any,
            schema_pointer: str,
            name_hint: str = "",
            operation_label: str = operation_name,
        ) -> None:
            if not isinstance(schema, dict):
                return
            for field_path, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                leaf = field_path.rsplit(".", 1)[-1] if field_path else name_hint
                normalized = leaf.replace("-", "_").lower()
                compact = normalized.replace("_", "")
                is_url = (
                    str(node.get("format", "")).lower() in {"uri", "url"}
                    or _looks_like_url_field(leaf)
                    or compact in URL_FIELD_NAMES
                )
                if is_url and "enum" not in node and "pattern" not in node:
                    matches.append(
                        (
                            operation_label,
                            field_path or name_hint or "<request URL input>",
                            pointer_fragment(pointer),
                        )
                    )

        # Request bodies, including Swagger body parameters.
        for schema, schema_pointer in iter_request_schemas(
            spec, operation, operation_pointer, path_item, parameter_locations={"body"}
        ):
            inspect(schema, schema_pointer)

        # Query, path, header, and cookie parameters may also carry URLs.
        for parameter, parameter_pointer in iter_parameters(spec, path_item, operation, operation_pointer):
            name = parameter.get("name", "")
            parameter_schema = parameter.get("schema")
            if isinstance(parameter_schema, dict):
                inspect(parameter_schema, pointer_join(parameter_pointer, "schema"), str(name))
            content = parameter.get("content", {})
            if isinstance(content, dict):
                for media_type, media in content.items():
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                        schema_pointer = pointer_join(
                            pointer_join(pointer_join(parameter_pointer, "content"), media_type), "schema"
                        )
                        inspect(media["schema"], schema_pointer, str(name))

    if not matches:
        return []
    return [
        Finding(
            rule_id="SSRF-001",
            title="A request accepts a URL without a documented allowlist",
            severity="medium",
            confidence="low",
            summary="A request URL field lacks an enum or pattern constraint in the contract. This is an SSRF review hint; runtime validation, network egress controls, and allowlists may exist outside the specification.",
            impact="If user-controlled URLs are fetched by the service without validation or network controls, attackers may reach internal or otherwise restricted systems.",
            remediation="Validate destinations against an explicit allowlist, restrict schemes and redirects, and block access to internal address ranges at the network layer.",
            affected_operations=sorted({item[0] for item in matches}),
            evidence={
                "fields": [item[1] for item in matches],
                "json_pointers": [item[2] for item in matches],
                "locations": [location(item[0], item[2]) for item in matches],
                "total_matches": len(matches),
                "truncated": len(matches) > 100,
            },
        )
    ]
