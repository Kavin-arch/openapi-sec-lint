# Contributing

Issues and pull requests are welcome. For a behavior change, describe the
contract signal it detects and the false positives or false negatives a user
should expect. Never add live API probing or send an uploaded specification to
an external service.

## Development

Use Python 3.11 or 3.12, then install the project and development tools:

```sh
python -m pip install -e ".[dev]"
ruff check api_checker tests
mypy api_checker
pytest --cov=api_checker --cov-fail-under=60
```

## Writing a rule

1. Add a focused check under `api_checker/scanner/checks/` and return `Finding`
   objects from the shared model.
2. Reuse the traversal helpers in `api_checker/scanner/common.py` so local
   references, JSON Pointer locations, and traversal budgets stay consistent.
3. Describe an observable specification pattern, its possible impact, the
   limits of the heuristic, and a concrete remediation.
4. Register the rule and its stable ID in `api_checker/scanner/rules.py`.
5. Add the rule to `docs/rules/` with OWASP API Security Top 10 and CWE mappings.
6. Keep user-controlled strings out of HTML without escaping. Prefer DOM text
   APIs in the interface.

Findings must not claim that a runtime vulnerability has been confirmed. Never
fetch external `$ref` values.
