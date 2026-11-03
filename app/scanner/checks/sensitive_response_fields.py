import re
from typing import Any

from app.scanner.common import (
    _operation_entries_with_pointers,
    _operation_name,
    _walk_schema_locations,
    iter_response_schemas,
    location,
)
from app.scanner.models import Finding
from app.scanner.references import pointer_fragment

SENSITIVE_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "passwords",
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
}


def check_sensitive_response_fields(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str, str]] = []
    for method, path, _, operation, operation_pointer in _operation_entries_with_pointers(spec):
        operation_name = _operation_name(method, path)
        for status, media_type, schema, schema_pointer in iter_response_schemas(
            spec, operation, operation_pointer
        ):
            label = f"response {status} {media_type}".strip()
            for field_path, pointer, node in _walk_schema_locations(spec, schema, schema_pointer):
                leaf = field_path.rsplit(".", 1)[-1]
                leaf = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", leaf)
                leaf = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", leaf).lower().replace("-", "_")
                if leaf in SENSITIVE_NAMES and node.get("writeOnly") is not True:
                    matches.append((operation_name, f"{label}: {field_path}", pointer_fragment(pointer)))

    if not matches:
        return []
    return [
        Finding(
            rule_id="DATA-001",
            title="A response schema contains a potentially sensitive field",
            severity="medium",
            confidence="low",
            summary="A response schema uses a field name commonly associated with secrets or personal data. This heuristic may flag legitimate fields and does not inspect live responses.",
            impact="If the field contains a real secret or sensitive value, returning it to an unintended caller could expose data.",
            remediation="Review the field and access policy. Omit secrets from responses, and mark request-only fields as writeOnly where appropriate.",
            affected_operations=sorted({item[0] for item in matches})[:100],
            evidence={
                "schema_fields": [item[1] for item in matches[:100]],
                "json_pointers": [item[2] for item in matches[:100]],
                "locations": [location(item[0], item[2]) for item in matches[:100]],
                "total_matches": len(matches),
                "truncated": len(matches) > 100,
            },
        )
    ]
