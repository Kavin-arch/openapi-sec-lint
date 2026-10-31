"""Compatibility facade and ordered registry for built-in scanner checks."""

from collections.abc import Callable
from typing import Any

from app.scanner.checks.authentication import check_authentication
from app.scanner.checks.sensitive_response_fields import check_sensitive_response_fields
from app.scanner.checks.transport import check_transport
from app.scanner.checks.unbounded_request_arrays import check_unbounded_request_arrays
from app.scanner.common import operations
from app.scanner.models import Finding

RuleCheck = Callable[[dict[str, Any]], list[Finding]]

# Keep ordering stable so reports and the UI remain predictable as checks grow.
RULES: tuple[RuleCheck, ...] = (
    check_authentication,
    check_transport,
    check_sensitive_response_fields,
    check_unbounded_request_arrays,
)
RULE_COUNT = len(RULES)


def run_rules(spec: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for check in RULES:
        findings.extend(check(spec))
    return findings


__all__ = ["RULES", "RULE_COUNT", "operations", "run_rules"]
