from api_checker.scanner.checks.coverage_gaps import (
    check_configuration_exposure,
    check_function_authorization,
    check_inventory_lifecycle,
    check_oauth_unsafe_flows,
    check_operation_contract_gaps,
    check_sensitive_business_flows,
    check_unsafe_consumption,
)
from api_checker.scanner.checks.sensitive_response_fields import check_sensitive_response_fields


def _spec(operation, path="/items"):
    return {"openapi": "3.0.3", "info": {"title": "Rules", "version": "1"}, "paths": {path: operation}}


def test_function_level_authorization_flags_admin_operation_without_role_scope():
    spec = _spec({"post": {"security": [{"bearer": []}] }}, "/admin/users")
    assert check_function_authorization(spec)[0].rule_id == "AUTH-004"


def test_function_level_authorization_accepts_admin_scope():
    spec = _spec({"post": {"security": [{"bearer": ["admin:write"]}] }}, "/admin/users")
    assert check_function_authorization(spec) == []


def test_sensitive_business_flow_and_external_consumption_are_flagged():
    operation = {"post": {"summary": "Import partner payments", "description": "Synchronize external provider data"}}
    spec = _spec(operation, "/payments/import")
    assert check_sensitive_business_flows(spec)[0].rule_id == "FLOW-001"
    assert check_unsafe_consumption(spec)[0].rule_id == "CONSUME-001"


def test_configuration_exposure_flags_internal_server_and_verbose_errors():
    spec = _spec({"get": {"responses": {"500": {"content": {"application/json": {"schema": {"properties": {"stackTrace": {"type": "string"}}}}}}}}})
    spec["servers"] = [{"url": "http://localhost:8080"}]
    assert check_configuration_exposure(spec)[0].rule_id == "CONFIG-001"


def test_inventory_and_discouraged_oauth_flows_are_flagged():
    spec = _spec({"get": {"deprecated": True}}, "/v1/users")
    spec["components"] = {"securitySchemes": {"legacy": {"type": "oauth2", "flows": {"password": {"tokenUrl": "https://idp/token", "scopes": {}}}}}}
    assert check_inventory_lifecycle(spec)[0].rule_id == "INV-001"
    assert check_oauth_unsafe_flows(spec)[0].rule_id == "AUTH-005"


def test_contract_gaps_cover_auth_responses_credentials_strings_and_uploads():
    spec = _spec({"post": {
        "parameters": [{"name": "apiKey", "in": "query", "schema": {"type": "string"}}],
        "requestBody": {"content": {"multipart/form-data": {"schema": {"properties": {
            "password": {"type": "string", "format": "password"},
            "label": {"type": "string"},
            "password_hint": {"type": "string"},
        }}}}},
        "responses": {"200": {"description": "ok"}},
    }})
    issues = check_operation_contract_gaps(spec)[0].evidence["issues"]
    assert any("query or cookie" in issue for issue in issues)
    assert any("401" in issue for issue in issues)
    assert any("429" in issue for issue in issues)
    assert any("Multipart" in issue for issue in issues)
    assert any("maxLength" in issue for issue in issues)
    assert any("format: password" in issue for issue in issues)


def test_pagination_tokens_are_not_reported_as_sensitive_response_fields():
    response_schema = {
        "type": "object",
        "properties": {
            "nextPageToken": {"type": "string"},
            "accessToken": {"type": "string"},
        },
    }
    spec = _spec({"get": {"responses": {"200": {"content": {"application/json": {"schema": response_schema}}}}}})
    finding = check_sensitive_response_fields(spec)[0]
    assert len(finding.evidence["json_pointers"]) == 1
    assert "accessToken" in finding.evidence["schema_fields"][0]
