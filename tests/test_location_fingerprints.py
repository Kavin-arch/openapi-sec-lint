from api_checker.scanner.engine import analyze


def test_shared_yaml_schema_aliases_keep_both_source_locations():
    source = """openapi: 3.0.3
info:
  title: Alias API
  version: '1'
paths:
  /users:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  primary: &shared
                    type: object
                    properties:
                      password_hash:
                        type: string
                  secondary: *shared
"""
    findings, _ = analyze(source, "api.yaml")
    sensitive = [finding for finding in findings if finding["rule_id"] == "DATA-001"]
    assert len(sensitive) == 2
    assert len({finding["fingerprint"] for finding in sensitive}) == 2
    assert all(finding["evidence"]["locations"][0].get("start_line") for finding in sensitive)


def test_location_fingerprint_does_not_change_when_line_numbers_move():
    first = """openapi: 3.0.3
info:
  title: API
  version: '1'
paths:
  /users:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  password_hash:
                    type: string
"""
    shifted = "# comment\n" + first
    original, _ = analyze(first, "api.yaml")
    moved, _ = analyze(shifted, "api.yaml")
    original_fingerprint = next(item["fingerprint"] for item in original if item["rule_id"] == "DATA-001")
    moved_fingerprint = next(item["fingerprint"] for item in moved if item["rule_id"] == "DATA-001")
    assert original_fingerprint == moved_fingerprint
