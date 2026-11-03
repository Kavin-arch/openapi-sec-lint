"""Compatibility facade and ordered registry for built-in scanner checks."""

from collections.abc import Callable
from typing import Any

from app.scanner.checks.authentication import check_authentication
from app.scanner.checks.dangling_security_schemes import check_dangling_security_schemes
from app.scanner.checks.oauth_scopes import check_oauth_scopes
from app.scanner.checks.object_id_parameters import check_object_id_parameters
from app.scanner.checks.permissive_request_objects import check_permissive_request_objects
from app.scanner.checks.sensitive_response_fields import check_sensitive_response_fields
from app.scanner.checks.transport import check_server_variables_and_websockets, check_transport
from app.scanner.checks.unbounded_request_arrays import check_unbounded_request_arrays
from app.scanner.checks.unbounded_strings_and_pagination import check_unbounded_strings_and_pagination
from app.scanner.checks.url_input_fields import check_url_input_fields
from app.scanner.common import operations
from app.scanner.models import Finding

RuleCheck = Callable[[dict[str, Any]], list[Finding]]

# Keep ordering stable so reports and the UI remain predictable as checks grow.
RULES: tuple[RuleCheck, ...] = (
    check_authentication,
    check_dangling_security_schemes,
    check_oauth_scopes,
    check_object_id_parameters,
    check_permissive_request_objects,
    check_transport,
    check_server_variables_and_websockets,
    check_sensitive_response_fields,
    check_unbounded_request_arrays,
    check_unbounded_strings_and_pagination,
    check_url_input_fields,
)
RULE_COUNT = len(RULES)


def run_rules(spec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for check in RULES:
        findings.extend(check(spec))
    return findings


__all__ = ["RULES", "RULE_COUNT", "operations", "run_rules"]
