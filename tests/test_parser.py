import json

import pytest

from api_checker.scanner.parser import SpecError, _UniqueKeySafeLoader, parse_spec, source_line_map


def test_json_duplicate_keys_are_rejected():
    source = '{"openapi":"3.0.3","info":{"title":"A","title":"B","version":"1"},"paths":{}}'
    with pytest.raises(SpecError, match="duplicate object key"):
        parse_spec(source, "api.json")


def test_yaml_duplicate_keys_are_rejected():
    source = "openapi: 3.0.3\ninfo:\n  title: A\n  title: B\n  version: '1'\npaths: {}\n"
    with pytest.raises(SpecError, match="duplicate object key"):
        parse_spec(source, "api.yaml")


def test_yaml_merge_defaults_allow_explicit_override():
    source = """openapi: 3.0.3
defaults: &defaults
  title: Shared
info:
  <<: *defaults
  title: API
  version: '1'
paths: {}
"""
    assert parse_spec(source)["info"]["title"] == "API"


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0", "3.1.0-rc0"])
def test_openapi_versions(version):
    document = {"openapi": version, "info": {"title": "A", "version": "1"}, "paths": {}}
    assert parse_spec(json.dumps(document))["openapi"] == version


def test_swagger_20_is_supported():
    document = {"swagger": "2.0", "info": {"title": "A", "version": "1"}, "paths": {}}
    assert parse_spec(json.dumps(document))["swagger"] == "2.0"


def test_openapi_31_allows_components_without_paths():
    document = {"openapi": "3.1.0", "info": {"title": "A", "version": "1"}, "components": {"schemas": {}}}
    assert parse_spec(json.dumps(document))["components"] == {"schemas": {}}


def test_specs_are_limited_by_bytes_instead_of_operation_count():
    methods = ("get", "post", "put", "patch", "delete", "options", "head", "trace")
    paths = {f"/items/{index}": {method: {} for method in methods} for index in range(250)}
    document = {"openapi": "3.0.3", "info": {"title": "A", "version": "1"}, "paths": paths}
    assert parse_spec(json.dumps(document))["info"]["title"] == "A"
    paths["/items/extra"] = {"get": {}}
    assert parse_spec(json.dumps(document))["info"]["title"] == "A"


def test_large_invalid_json_does_not_fall_back_to_yaml():
    with pytest.raises(SpecError):
        parse_spec("{" + (" " * (300 * 1024)) + "!", "broken.json")


def test_custom_loader_uses_c_loader_when_available():
    import yaml

    assert issubclass(_UniqueKeySafeLoader, getattr(yaml, "CSafeLoader", yaml.SafeLoader))


def test_source_line_map_uses_escaped_json_pointer_tokens():
    source = """openapi: 3.0.3
info:
  title: A
  version: '1'
paths:
  /users:
    get:
      responses:
        '200':
          description: ok
"""
    lines = source_line_map(source)
    assert lines["#/paths/~1users/get/responses/200/description"] == 10
