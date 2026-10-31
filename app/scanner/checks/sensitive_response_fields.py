import re
from typing import Any

from app.scanner.common import _operation_name, _walk_schema, operations
from app.scanner.models import Finding
from app.scanner.references import resolve_local_ref

SENSITIVE_NAMES = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "private_key", "ssn", "credit_card", "client_secret",
}


def check_sensitive_response_fields(spec: dict[str, Any]) -> list[Finding]:
    matches: list[tuple[str, str]] = []
    for method, path, operation in operations(spec):
        responses = operation.get("responses", {})
        if not isinstance(responses, dict):
            continue
        for status, response in responses.items():
            response = resolve_local_ref(spec, response)
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
