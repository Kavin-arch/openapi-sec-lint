"""Compatibility facade and ordered registry for built-in scanner checks."""

from collections.abc import Callable
from typing import Any

from api_checker.scanner.checks.authentication import check_authentication
from api_checker.scanner.checks.dangling_security_schemes import check_dangling_security_schemes
from api_checker.scanner.checks.oauth_scopes import check_oauth_scopes
from api_checker.scanner.checks.object_id_parameters import check_object_id_parameters
from api_checker.scanner.checks.permissive_request_objects import check_permissive_request_objects
from api_checker.scanner.checks.sensitive_response_fields import check_sensitive_response_fields
from api_checker.scanner.checks.transport import check_server_variables_and_websockets, check_transport
from api_checker.scanner.checks.unbounded_request_arrays import check_unbounded_request_arrays
from api_checker.scanner.checks.unbounded_strings_and_pagination import check_unbounded_strings_and_pagination
from api_checker.scanner.checks.url_input_fields import check_url_input_fields
from api_checker.scanner.common import operations
from api_checker.scanner.models import Finding

RuleCheck = Callable[[dict[str, Any]], list[Finding]]
RULE_IDS = (
    "AUTH-001",
    "AUTH-002",
    "AUTH-003",
    "BOLA-001",
    "MASS-001",
    "TRANSPORT-001",
    "TRANSPORT-002",
    "DATA-001",
    "RESOURCE-001",
    "RESOURCE-002",
    "SSRF-001",
)

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


def run_rules(spec: dict[str, Any], disabled_rules: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    disabled = disabled_rules or set()
    for rule_id, check in zip(RULE_IDS, RULES, strict=True):
        if rule_id in disabled:
            continue
        findings.extend(check(spec))
    return findings


__all__ = ["RULES", "RULE_COUNT", "RULE_IDS", "operations", "run_rules"]
