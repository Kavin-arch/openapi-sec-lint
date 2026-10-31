# API Vulnerability Checker

A lightweight, local-first API specification reviewer. It accepts an OpenAPI 3.x or Swagger 2.0 JSON/YAML file, queues an offline analysis, and stores scan history and findings in a local SQLite database.

The first release is intentionally small enough to run on a development PC. **It does not send HTTP requests to the target API.** The target URL is saved as report metadata only. Findings are specification review signals, not confirmation of runtime vulnerabilities.

## Included checks

| Rule | What it flags | Interpretation |
|---|---|---|
| `AUTH-001` | Operations without an effective OpenAPI security requirement | The contract does not document authentication. Runtime enforcement may still exist. |
| `TRANSPORT-001` | A server definition using plain HTTP | Review whether HTTPS is available and enforced. |
| `DATA-001` | Sensitive-looking field names in response schemas | A low-confidence name heuristic; confirm whether the field contains sensitive data. |
| `RESOURCE-001` | Request arrays without a documented `maxItems` | A low-confidence resource-limit review hint. |

Each report includes severity, confidence, evidence, affected operations, impact, and remediation guidance. Confidence is separate from severity because a noteworthy signal can still be uncertain.

Local JSON Pointer references (such as `#/components/schemas/Record`) are followed within the uploaded file. External references are never fetched.

## Run locally on Windows

Python 3.11 or newer is recommended. From PowerShell in this folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000>. The interactive API documentation is at <http://127.0.0.1:8000/docs>.

On macOS or Linux, create and activate a virtual environment with `python3 -m venv .venv` and `source .venv/bin/activate`, then install the same requirements and run Uvicorn.

The app is designed for local use. Keep it bound to `127.0.0.1`; do not expose it to a network because this starter does not include user accounts or authentication.

## Try the sample

Upload [`examples/sample-openapi.yaml`](examples/sample-openapi.yaml) from the UI. It deliberately includes several signals for demonstration.

## API

- `GET /health` — local process status.
- `POST /api/v1/scans` — queue a scan. The JSON body contains `name` (optional), `target_url`, `filename`, and `spec_text`.
- `GET /api/v1/scans?limit=50` — list recent scans.
- `GET /api/v1/scans/{id}` — read scan status, summary, and findings.

Uploads are limited to 2 MB and 2,000 operations, including OpenAPI 3.1+ webhooks. JSON and YAML are parsed locally; duplicate object keys and missing required top-level metadata are rejected. The parser performs structural checks, not full OpenAPI schema validation. The original specification is removed from the database when analysis completes; findings and scan metadata remain in `data/scanner.sqlite3`. The `data/` folder is ignored by Git.

To store the SQLite file elsewhere, set `API_VULN_DB` before starting the server, for example:

```powershell
$env:API_VULN_DB = "D:\api-checker-data\scanner.sqlite3"
python -m uvicorn app.main:app --reload
```

## Current boundaries

- The worker is an in-process, single-worker queue backed by SQLite. Queued jobs survive a restart; a scan interrupted during shutdown is put back in the queue on the next startup.
- The local queue accepts at most 10 queued or running scans to keep disk use bounded.
- External `$ref` references are not fetched, so checks that depend on those references may be incomplete.
- There are no live probes, credentials, BOLA/IDOR checks, rate-limit tests, injection payloads, or runtime header checks yet.
- No full request/response captures are retained.
- Keep this server local. Before adding live scanning or remote users, add target authorization and scope controls, worker egress restrictions, authentication, secret handling, scan cancellation and rate limits.

## Scanner structure

- `app/scanner/parser.py` parses the uploaded document and applies the starter's structural checks.
- `app/scanner/common.py` contains shared operation and schema traversal helpers.
- `app/scanner/checks/` contains one module per built-in review check.
- `app/scanner/rules.py` is the ordered rule registry and retains the scanner's stable import interface.
- `app/scanner/engine.py` coordinates parsing, rule execution, and summary counts.

To add a check, implement it in `app/scanner/checks/` and register it in `RULES`. The report and home-page check count are derived from that registry.

## Next implementation stages

1. Add opt-in, low-rate runtime checks behind explicit target scope controls.
2. Add authenticated scan profiles and evidence redaction.
3. Replace the local queue with Celery/Redis and move persistence to PostgreSQL when deploying on Linux or serving multiple users.
4. Add report export and retention controls.

The scanner engine and database access live behind separate modules so the scan rules can grow independently and the local queue/database can be replaced as the deployment needs change.
