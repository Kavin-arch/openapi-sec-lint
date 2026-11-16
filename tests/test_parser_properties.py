from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from api_checker.scanner.parser import SpecError, parse_spec


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=512))
def test_parser_rejects_or_accepts_arbitrary_hostile_text_without_crashing(source: str) -> None:
    try:
        parse_spec(source, "fuzz.yaml")
    except SpecError:
        pass


@settings(max_examples=100, deadline=None)
@given(
    title=st.text(min_size=1, max_size=40).filter(lambda value: bool(value.strip())),
    parameter_name=st.text(min_size=1, max_size=40),
    value=st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=80)),
)
def test_parser_preserves_generated_openapi_shapes(title: str, parameter_name: str, value: object) -> None:
    document = {
        "openapi": "3.0.3",
        "info": {"title": title, "version": "1"},
        "paths": {
            "/generated": {
                "get": {
                    "parameters": [{"name": parameter_name, "in": "query", "example": value}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    parsed = parse_spec(json.dumps(document), "generated.json")
    assert parsed["openapi"] == "3.0.3"
    assert parsed["paths"]["/generated"]["get"]["parameters"][0]["example"] == value
