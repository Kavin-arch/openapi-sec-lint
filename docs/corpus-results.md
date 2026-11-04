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
| Petstore | 19 | 60 | 0 | 0 | 11 | 49 |
| GitHub REST | 1,259 | 4,201 | 0 | 0 | 1,353 | 2,848 |
| Stripe | 612 | 8,780 | 0 | 0 | 90 | 8,690 |

The GitHub and Stripe snapshots each contain thousands of low-severity
resource-bound signals. Review the rule reference and configure `--disable`
for checks that are not useful to a particular API. Upstream specifications
change over time; update the snapshots and manifest together when refreshing
the corpus.
