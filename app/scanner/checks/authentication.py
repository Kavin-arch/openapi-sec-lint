from typing import Any

from app.scanner.models import Finding
from app.scanner.common import _operation_name, operations


def check_authentication(spec: dict[str, Any]) -> list[Finding]:
    missing = []
    global_security = spec.get("security")
    for method, path, operation in operations(spec):
        requirements = operation["security"] if "security" in operation else global_security
        # Security Requirement Objects are alternatives (OR). An empty object
        # is an explicit anonymous alternative, so authentication is optional.
        if not isinstance(requirements, list) or not requirements or any(
            not isinstance(requirement, dict) or not requirement
            for requirement in requirements
        ):
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
