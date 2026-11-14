# Evaluation and regression evidence

Run a repeatable corpus scan and create a 100-case, rule-stratified annotation
sheet:

```powershell
openapi-sec-lint scan corpus/specs --output corpus-report.json
python scripts/sample_findings.py corpus-report.json precision-review.csv --count 100
```

Review each sampled finding against the source contract and label `true` when
the documented rule condition is present, `false` when it is not, or
`uncertain` when the contract alone cannot settle the question. This measures
precision of the static signal, not runtime exploitability. Add short evidence
in `notes`, retain the unedited sample and completed annotations, then compute
per-rule rates:

```powershell
python scripts/evaluate_precision.py precision-review.csv
```

No precision percentages are published yet: the first 100-case annotation
sheet is checked in as [precision-review.csv](precision-review.csv), and still
requires review and labels. The tool must not treat heuristic findings as
confirmed vulnerabilities.

## Known-issue and competitor comparisons

The regression corpus includes pinned OpenAPI snapshots from OWASP crAPI and
VAmPI with source URLs, hashes, licenses, and expected rule IDs in
`corpus/vulnerable-manifest.json`. CI verifies those rule signals offline.
The current static overlap is 8/8 mapped challenge categories for crAPI and
4/5 mapped categories for VAmPI. This is not “vulnerabilities caught”: the
upstream challenge lists include runtime flaws that an OpenAPI contract cannot
prove, and the category-to-rule mapping is explicitly limited to issues with a
matching contract signal. SQL injection, enumeration, weak JWT signing, and
RegexDOS are outside the scanner's scope. The snapshots are not sent to a live
API.

A one-spec, version-pinned timing run for Spectral and Vacuum is recorded in
[benchmark.md](benchmark.md). It reports raw counts and elapsed times only;
rulesets differ and Vacuum's Node engine warning limits the timing result.
Do not treat it as a precision, recall, or broad speed comparison.

## Parser and worker robustness

Regression tests exercise the YAML alias limit, a 524,288-property input shape,
the schema-node budget, output truncation at 10,000 findings, subprocess
timeout/cancel handling, and Hypothesis-generated arbitrary text and structured
OpenAPI documents. `truncated_findings: 1` means the cap was reached; it does
not claim an exact count of omitted findings. The scan child is capped at 1 GiB
resident memory.
GitHub Actions runs on Windows, macOS, and Linux with Python 3.11 through 3.13;
the coverage gate is 85%.

The large-input regression verifies safe rejection at the 250,000-document-node
limit before rules run; it does not construct half a million serialized
findings in memory.
