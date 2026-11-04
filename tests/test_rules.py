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


def _base(paths):
    return {"openapi": "3.0.3", "info": {"title": "Test", "version": "1"}, "paths": paths}


def test_auth_001_flags_operations_without_security():
    findings = check_authentication(_base({"/x": {"get": {}}}))
    assert findings[0].rule_id == "AUTH-001"
    assert findings[0].evidence["locations"][0]["pointer"] == "#/paths/~1x/get"


def test_auth_002_flags_dangling_scheme_and_basic_over_http():
    spec = _base({"/x": {"get": {"security": [{"missing": []}, {"basic": []}]}}})
    spec["components"] = {"securitySchemes": {"basic": {"type": "http", "scheme": "basic"}}}
    spec["servers"] = [{"url": "http://api.example"}]
    assert "AUTH-002" == check_dangling_security_schemes(spec)[0].rule_id


def test_auth_003_flags_empty_oauth_scope_definitions_and_requirements():
    spec = _base({"/x": {"get": {"security": [{"oauth": []}]}}})
    spec["components"] = {
        "securitySchemes": {"oauth": {"type": "oauth2", "flows": {"clientCredentials": {"scopes": {}}}}}
    }
    assert "AUTH-003" == check_oauth_scopes(spec)[0].rule_id


def test_bola_001_flags_integer_object_id_parameter():
    spec = _base(
        {
            "/users/{userId}": {
                "get": {"parameters": [{"name": "userId", "in": "path", "schema": {"type": "integer"}}]}
            }
        }
    )
    assert "BOLA-001" == check_object_id_parameters(spec)[0].rule_id


def test_bola_001_includes_uuid_strings_without_matching_words_ending_in_id():
    spec = _base(
        {
            "/users/{userUUID}": {
                "get": {
                    "parameters": [
                        {"name": "userUUID", "in": "path", "schema": {"type": "string", "format": "uuid"}}
                    ]
                }
            },
            "/payments/{paid}": {
                "get": {
                    "parameters": [{"name": "paid", "in": "path", "schema": {"type": "integer"}}]
                }
            },
        }
    )
    findings = check_object_id_parameters(spec)
    assert len(findings) == 1
    assert findings[0].evidence["parameters"] == ["path userUUID"]


def test_mass_001_flags_permissive_and_server_managed_fields():
    spec = _base(
        {
            "/users": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"role": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    finding = check_permissive_request_objects(spec)[0]
    assert finding.rule_id == "MASS-001"
    assert len(finding.evidence["json_pointers"]) == 2


def test_transport_001_flags_plain_http():
    spec = _base({"/x": {"get": {}}})
    spec["servers"] = [{"url": "http://api.example"}]
    assert "TRANSPORT-001" == check_transport(spec)[0].rule_id


def test_transport_002_flags_template_and_unencrypted_websocket():
    spec = _base({"/x": {"get": {}}})
    spec["servers"] = [
        {
            "url": "{scheme}://api.example",
            "variables": {"scheme": {"default": "https", "enum": ["https", "http"]}},
        },
        {"url": "ws://api.example/socket"},
    ]
    finding = check_server_variables_and_websockets(spec)[0]
    assert finding.rule_id == "TRANSPORT-002"
    assert len(finding.evidence["json_pointers"]) == 2


def test_data_001_normalizes_acronyms_and_plural_sensitive_fields():
    spec = _base(
        {
            "/x": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "APIKey": {"type": "string"},
                                            "SSN": {"type": "string"},
                                            "passwords": {"type": "array"},
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            }
        }
    )
    finding = check_sensitive_response_fields(spec)[0]
    assert finding.rule_id == "DATA-001"
    assert len(finding.evidence["json_pointers"]) == 3


def test_resource_001_flags_unbounded_request_array():
    spec = _base(
        {
            "/x": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                }
                            }
                        }
                    }
                }
            }
        }
    )
    assert "RESOURCE-001" == check_unbounded_request_arrays(spec)[0].rule_id


def test_resource_002_flags_string_map_and_unpaginated_collection():
    spec = _base(
        {
            "/x": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "labels": {
                                            "type": "object",
                                            "additionalProperties": {"type": "string"},
                                        },
                                    },
                                }
                            }
                        }
                    }
                },
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {"schema": {"type": "array", "items": {"type": "object"}}}
                            },
                        }
                    }
                },
            }
        }
    )
    finding = check_unbounded_strings_and_pagination(spec)[0]
    assert finding.rule_id == "RESOURCE-002"
    assert {"unbounded_string", "unbounded_map", "missing_pagination"}.issubset(
        set(finding.evidence["issue_types"])
    )


def test_ssrf_001_flags_unconstrained_url_inputs():
    spec = _base(
        {
            "/hooks": {
                "post": {
                    "parameters": [
                        {"name": "callback_url", "in": "query", "schema": {"type": "string", "format": "uri"}}
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "webhook_url": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                }
            }
        }
    )
    finding = check_url_input_fields(spec)[0]
    assert finding.rule_id == "SSRF-001"
    assert len(finding.evidence["json_pointers"]) == 2
