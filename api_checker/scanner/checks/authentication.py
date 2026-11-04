from typing import Any

from api_checker.scanner.common import _operation_entries_with_pointers, _operation_name, location
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment


def check_authentication(spec: dict[str, Any]) -> list[Finding]:
    missing: list[tuple[str, str]] = []
    global_security = spec.get("security")
    for method, path, _, operation, operation_pointer in _operation_entries_with_pointers(spec):
        requirements = operation["security"] if "security" in operation else global_security
        # Security Requirement Objects are alternatives (OR). An empty object
        # is an explicit anonymous alternative, so authentication is optional.
        if (
            not isinstance(requirements, list)
            or not requirements
            or any(not isinstance(requirement, dict) or not requirement for requirement in requirements)
        ):
            missing.append((_operation_name(method, path), operation_pointer))
    if not missing:
        return []
    return [
        Finding(
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
            affected_operations=[item[0] for item in missing],
            evidence={
                "operation_count": len(missing),
                "total_matches": len(missing),
                "json_pointers": [pointer_fragment(item[1]) for item in missing],
                "locations": [location(item[0], item[1]) for item in missing],
                "truncated": len(missing) > 100,
            },
        )
    ]
