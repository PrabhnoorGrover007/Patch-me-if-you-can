# Data audit

## 1. What we verified in the source files

| File | Rows | Check |
|---|---|---|
| `vulnerabilities.csv` | 401,082 | matches documentation; published 1988-10-01 → 2026-11-06 |
| `affected_products.csv` | 3,155,934 | aggregated with `vulnerable = 'Y'` only |
| `references.csv` | 1,360,487 | summarised by domain; **never** joined as features |
| `known_exploited.csv` | 1,484 | `date_added` 2021-11-03 → 2025-12-29 |
| `exploit_signals_2024/2025.csv` | 3,023,284 + 3,440,450 = 6,463,734 | 24 months, 2024-01 → 2025-12 |
| `scoreboard_2026.csv` | 72,670 | 8 distinct snapshot months (June folds to July), published 2026-01-01 → 2026-09-30 |
| `weakness_types.csv` | 1,374 | CWE names |

Join integrity: every one of the 72,670 scoreboard rows matched a `vulnerabilities.csv` record
(description coverage 100%), and the `published` dates agreed exactly with the source (`mismatch 0`).
Product aggregation produced 324,005 CVEs with at least one vulnerable CPE — 77k CVEs have none,
consistent with NIST's deferred analysis.

## 2. Known data caveats, and how each is handled

| Caveat | Effect | Handling |
|---|---|---|
| NVD files are today's state; `last_modified` is mid-2026+ | post-attack enrichment | columns excluded (below) |
| 62 KEV entries predate publication | negative lags pollute "time to exploitation" | dropped from lag analysis (64% ≤ 30 days rather than 67%) |
| February 2025 signals missing ~14,500 CVEs | EPSS missing for that cohort | kept as a missing flag (`epss_missing`); numeric EPSS is median-imputed inside each training fold |
| ~11,800 signal IDs are rejected, not in `vulnerabilities.csv` | fan-out risk on joins | signals joined to the vulnerability table, never the reverse |
| EPSS model changed March 2025 | levels not comparable across time | EPSS used as a snapshot level plus within-month rank, never as a cross-year trend |
| `cve_id` year ≠ publication year | wrong cohort assignment | cohorts keyed on `published` only |
| 49.6% of 2026 CVEs have no CPE list | product features would encode NVD attention | CPE fields excluded from the model |
| 8.7% of 2026 rows have blank CVSS | blankness is an NVD-review leak | score median-imputed before the model sees it; no `has_score` indicator |

## 3. Leakage audit

The organisers' warning list maps to explicit exclusions, each documented in
[FEATURE_AUDIT.md](FEATURE_AUDIT.md):

- `nvd_status` — excluded.
- `n_affected_cpes`, `n_references` — excluded.
- `references.csv` URLs, domains and tags — excluded from features; only used to describe the corpus
  (37,853 IBM X-Force links, 111,423 `Exploit`-tagged references).
- Blank severity as a signal — excluded.
- `last_modified` — excluded.
- CISA-ADP assigner GUID — collapsed to a neutral category, because ADP enrichment is applied after
  publication.
- CPE vendor/product — excluded from the model for the same reason (see caveat table).

Reasoning: NIST analyses vulnerabilities that are attacked first, so *the presence of analysis* is
itself a label proxy. A model that uses it would look excellent in the 2026 pool and be worthless in
deployment.

## 4. Label construction

```
candidate  : published in month m, in_kev == 0 in the month-m signal snapshot
snapshot_end: month end of m
label_any  : 1 iff exists a KEV date_added with (snapshot_end, 2025-12-29]
```
Right-censoring: cohorts published late in 2025 have shorter observed windows (September 2025 has
90 days). We carry `horizon_days` as a feature, report the same metric on the fixed nine-month
2025 pool, and state the censoring explicitly in LIMITATIONS.md rather than pretending the windows
are equal.

Verification: no positive label has `days_to_kev <= 0`; all negatives with an observed KEV date are
`<= 0` (i.e. already in KEV at the snapshot and therefore filtered out). Asserted in
`tests/test_pipeline.py`.

**Follow-up audit (2026-11-08).** The original candidate filter used the monthly signal file's
`in_kev` flag after filling absent monthly rows with zero. A join to the authoritative KEV table found
**14 CVEs that were already on KEV at their snapshot** but had no signal row for that month. They were
being treated as candidates and, because their KEV addition preceded the observation window, as
negatives. The cohort now filters on `kev_added <= snapshot_end` before labels are built; the training
table is **87,907 rows / 122 positives**, and the offending rows are gone. This is a correction to the
original audit, not a new limitation.

## 5. What we did not do

- No external datasets. Adding e.g. a vendor breach feed would risk importing post-snapshot knowledge.
- No scraping of current KEV. The supplied KEV file ends 2025-12-29 and we respected that boundary.
- No cohort-mean imputation. Numeric columns, including EPSS and CVSS, are median-imputed inside
  each training fold for both model families; missingness is available only through explicit flags such as `epss_missing`.
