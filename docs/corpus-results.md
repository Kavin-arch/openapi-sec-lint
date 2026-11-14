# Real specification corpus

These local snapshots form a regression corpus for parsing and scan performance.
The manifest records the upstream URL, upstream license, retrieval date, and
SHA-256 for every exact input. Recompute the expected finding totals with:

```sh
python -m api_checker.cli scan corpus/specs --output corpus-report.json
python scripts/verify_corpus.py corpus-report.json
```

Findings are unique specification locations after shared component references
are coalesced; `affected_operations` lists operations that use each location.
They remain heuristic contract signals, not confirmed live vulnerabilities.

| Snapshot | Operations | Findings | Critical | High | Medium | Low |
|---|---:|---:|---:|---:|---:|---:|
| Petstore | 19 | 75 | 0 | 0 | 12 | 63 |
| GitHub REST | 1,259 | 8,937 | 0 | 0 | 1,407 | 7,530 |
| Stripe | 612 | 10,000* | 0 | 0 | 104 | 9,896 |

`*` Stripe reached the 10,000-finding output cap. The summary reports
`truncated_findings: 1`; that flag indicates truncation without estimating the
number of omitted records.

The GitHub and Stripe snapshots each contain thousands of low-severity
resource-bound signals. Review the rule reference and configure `--disable`
for checks that are not useful to a particular API. Upstream specifications
change over time; update the snapshots and manifest together when refreshing
the corpus.
