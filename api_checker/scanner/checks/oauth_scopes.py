from typing import Any

from api_checker.scanner.common import _operation_entries_with_pointers, _operation_name, location
from api_checker.scanner.models import Finding
from api_checker.scanner.references import pointer_fragment, pointer_join


def check_oauth_scopes(spec: dict[str, Any]) -> list[Finding]:
    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    if not isinstance(schemes, dict) or not schemes:
        schemes = spec.get("securityDefinitions", {})
    if not isinstance(schemes, dict):
        return []

    evidence: list[tuple[str, str, str]] = []
    oauth_names: set[str] = set()
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        scheme_type = scheme.get("type")
        scheme_pointer = pointer_join("/components/securitySchemes", name)
        if spec.get("swagger") == "2.0":
            scheme_pointer = pointer_join("/securityDefinitions", name)
        if scheme_type == "oauth2" or (spec.get("swagger") == "2.0" and scheme.get("type") == "oauth2"):
            oauth_names.add(name)
            flows = scheme.get("flows")
            if isinstance(flows, dict):
                if not flows:
                    pointer = pointer_join(scheme_pointer, "flows")
                    evidence.append(
                        (
                            f"OAuth2 scheme {name!r} has no documented flows or scopes",
                            pointer_fragment(pointer),
                            "API",
                        )
                    )
                for flow_name, flow in flows.items():
                    scopes = flow.get("scopes") if isinstance(flow, dict) else None
                    if not isinstance(scopes, dict) or not scopes:
                        pointer = pointer_join(
                            pointer_join(pointer_join(scheme_pointer, "flows"), flow_name), "scopes"
                        )
                        evidence.append(
                            (
                                f"OAuth2 scheme {name!r} has no documented scopes in flow {flow_name!r}",
                                pointer_fragment(pointer),
                                "API",
                            )
                        )
            elif spec.get("swagger") == "2.0":
                scopes = scheme.get("scopes")
                if not isinstance(scopes, dict) or not scopes:
                    pointer = pointer_join(scheme_pointer, "scopes")
                    evidence.append(
                        (f"OAuth2 scheme {name!r} has no scope definitions", pointer_fragment(pointer), "API")
                    )
            else:
                evidence.append(
                    (
                        f"OAuth2 scheme {name!r} has no documented flows or scope definitions",
                        pointer_fragment(scheme_pointer),
                        "API",
                    )
                )
        elif scheme_type == "openIdConnect":
            oauth_names.add(name)

    for method, path, _, operation, operation_pointer in _operation_entries_with_pointers(spec):
        requirements = operation["security"] if "security" in operation else spec.get("security", [])
        if not isinstance(requirements, list):
            continue
        operation_name = _operation_name(method, path)
        for index, requirement in enumerate(requirements):
            if not isinstance(requirement, dict):
                continue
            for name, scopes in requirement.items():
                if name in oauth_names and isinstance(scopes, list) and not scopes:
                    pointer = pointer_join(
                        pointer_join(pointer_join(operation_pointer, "security"), index), name
                    )
                    evidence.append(
                        (
                            f"{operation_name} uses {name!r} without selecting any scopes",
                            pointer_fragment(pointer),
                            operation_name,
                        )
                    )

    if not evidence:
        return []
    return [
        Finding(
            rule_id="AUTH-003",
            title="OAuth scopes are empty or undocumented",
            severity="medium",
            confidence="low",
            summary="The contract has an OAuth flow without documented scope names or an operation that selects no scopes. Some APIs intentionally use scope-free flows, so review this signal against the authorization design.",
            impact="Missing scope documentation can make it difficult to verify function-level access rules and client permissions.",
            remediation="Document OAuth scopes and declare the scopes required by each operation where the API uses scope-based authorization.",
            affected_operations=sorted({item[2] for item in evidence if item[2] != "API"}),
            evidence={
                "issues": [item[0] for item in evidence],
                "json_pointers": [item[1] for item in evidence],
                "locations": [location(item[2], item[1]) for item in evidence],
                "total_matches": len(evidence),
                "truncated": len(evidence) > 100,
            },
        )
    ]
