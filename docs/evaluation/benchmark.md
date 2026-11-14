# Single-spec lint benchmark

Recorded on Windows (`win32`), Python 3.12.5, Node 22.17.1, on
`corpus/specs/petstore.yaml`. The Spectral and Vacuum package caches were warm;
times include the CLI process startup and `npx` launcher but not package
installation. Runs use each tool's default OpenAPI ruleset; these rules are not
equivalent, so finding counts are workload context, not a quality ranking.

| Tool and version | Configuration | Elapsed | Results |
|---|---|---:|---:|
| Spectral 6.17.1 | `spectral:oas`, JSON output | 6.16 s | 2 diagnostics |
| Vacuum 0.41.0 | Default ruleset, JSON output | 2.94 s | 102 diagnostics |
| openapi-sec-lint 0.3.0 (working tree) | All 18 security checks, JSON output | 0.95 s | 75 findings |

The Vacuum npm wrapper warned that this Node 22.17.1 runtime is below its
declared Node 24.16 minimum, although its CLI completed and emitted JSON. Treat
that timing as indicative only. This one small specification is not a broad
performance comparison, and the result counts cannot be compared as precision
or recall. Repeat on larger identical inputs with supported runtimes and
matched rule behavior before making performance or accuracy claims.

Commands used:

```powershell
npx --yes --package=@stoplight/spectral-cli@6.17.1 spectral lint corpus/specs/petstore.yaml --ruleset .spectral.yaml --format json --output spectral.json
npx --yes --package=@quobix/vacuum@0.41.0 vacuum --no-update-check lint corpus/specs/petstore.yaml --format json --output json=vacuum.json
python -m api_checker.cli scan corpus/specs/petstore.yaml --output openapi-sec-lint.json
```

The Spectral ruleset file contained `extends: spectral:oas`.
