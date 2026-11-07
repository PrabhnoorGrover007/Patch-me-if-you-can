# Data contract: `outputs/train.csv` and `outputs/predict_2026.csv`

Produced by `prepare_data.py`. Consumed by `model.py` (and `ranked_2026.csv` is consumed by the dashboard).
Both files are UTF-8 CSV, comma separated, header row, no index column. Dates are `YYYY-MM-DD`,
months are `YYYY-MM`.

## 1. What one row means
One row = one CVE **as it looked at the end of its snapshot month** (the "prediction cutoff").
Every feature must be something a security team could have known at that cutoff.

## 2. Prediction cutoff rules
| Rows | Who | `snapshot_month` |
|---|---|---|
| Train | CVEs published 2024-01-01 to 2025-11-30 | Publish month, except publish month 2025-02 → `2025-03` (Feb 2025 signal file is missing ~14,500 CVEs; only 77% of Feb-2025 CVEs have a Feb row vs 99.9% in March) |
| Predict | The 72,670 rows of `scoreboard_2026.csv` | Taken as given (publish month; June 2026 → July) |

`snapshot_end` = last calendar day of `snapshot_month` (the cutoff date).

Training rows are **dropped** when the CVE was already on KEV by `snapshot_end`
(KEV `date_added <= snapshot_end`, or `in_kev = 1` in that month's signals). This mirrors the
scoreboard, which only contains CVEs not on KEV at the end of their snapshot month.
CVEs published in Dec 2025 are not used: they would have an outcome window of 0 days.

## 3. Label definition (train only)
```
label = 1  if  snapshot_end < KEV date_added <= 2025-12-31
label = 0  otherwise
```
- The outcome window runs from the day after the cutoff to the last KEV date we have (2025-12-31).
  `label_window_days` records its length (31 to ~700 days). The 2026 scoreboard is judged on a similar
  varying window (through 2026-11-04), so we keep the variable window instead of throwing away data.
- `label = 0` means "not confirmed on KEV by 2025-12-31". It does **not** mean the CVE was never attacked.
- Late-2025 cohorts have short windows, so they carry fewer positives. Expect ~120 positives in ~85k rows.

## 4. Columns

### 4a. Identifier / context columns (in both files, NOT model features)
| Column | Type | Meaning |
|---|---|---|
| `cve_id` | str | Unique per file |
| `published` | date | NIST publish date |
| `snapshot_month` | str `YYYY-MM` | Month the features are taken from |
| `snapshot_end` | date | Prediction cutoff (last day of `snapshot_month`) |
| `description` | str | English description (for display and Granite; free text, not a model input) |

### 4b. Train-only columns
| Column | Type | Meaning |
|---|---|---|
| `label` | int 0/1 | Target (section 3) |
| `label_window_days` | int | Days from `snapshot_end` to 2025-12-31 |

`predict_2026.csv` never contains `label`, `label_window_days`, or any KEV date.

### 4c. Model features (identical names, order and types in both files)
| Column | Type | Definition | Missing → |
|---|---|---|---|
| `epss` | float 0–1 | EPSS score at the end of `snapshot_month` | 0.0 |
| `epss_missing` | int 0/1 | 1 if no EPSS score existed at the cutoff | — |
| `epss_pct_in_month` | float 0–1 | Percentile rank of `epss` among rows of the same file with the same `snapshot_month`. Makes EPSS v3 (before 2025-03) and v4 comparable | 0.0 |
| `epss_v4` | int 0/1 | 1 if `snapshot_month >= 2025-03` (new EPSS model) | — |
| `exploitdb`, `metasploit`, `nuclei`, `poc_github` | int 0/1 | Public exploit / scanner / PoC code existed at the cutoff | 0 |
| `n_exploit_sources` | int 0–4 | Sum of the four flags | — |
| `days_public_at_cutoff` | int | `snapshot_end - published` in days | — |
| `cvss_score` | float 0–10 | CVSS 3 base score, else CVSS 4 base score | **7.5 constant** (see 6) |
| `cvss_network` | int 0/1 | Attack vector is Network (CVSS 3 vector, else CVSS 4 vector) | 0 |
| `cvss_no_privileges` | int 0/1 | Privileges required = None | 0 |
| `cvss_no_user_interaction` | int 0/1 | No user interaction needed | 0 |
| `kw_rce` | int 0/1 | Description mentions remote code execution / arbitrary code | 0 |
| `kw_command_injection` | int 0/1 | OS command / code injection | 0 |
| `kw_auth_bypass` | int 0/1 | Authentication bypass / missing authentication | 0 |
| `kw_unauthenticated` | int 0/1 | "unauthenticated" / "remote attacker without authentication" | 0 |
| `kw_deserialization` | int 0/1 | Deserialization of untrusted data | 0 |
| `kw_path_traversal` | int 0/1 | Path / directory traversal | 0 |
| `kw_sql_injection` | int 0/1 | SQL injection | 0 |
| `kw_memory_corruption` | int 0/1 | Buffer overflow, use-after-free, out-of-bounds write, type confusion, heap corruption | 0 |
| `kw_privilege_escalation` | int 0/1 | Privilege escalation / elevation of privilege | 0 |
| `kw_xss` | int 0/1 | Cross-site scripting | 0 |
| `kw_dos` | int 0/1 | Denial of service | 0 |
| `kw_edge_device` | int 0/1 | VPN, firewall, gateway, router, load balancer, remote access, appliance | 0 |
| `kw_exploited_in_wild` | int 0/1 | Vendor text says it "may have been exploited" / "exploited in the wild" | 0 |
| `kw_wordpress` | int 0/1 | WordPress plugin/theme (huge volume, rarely on KEV) | 0 |
| `desc_length` | int | Characters in the description | — |
| `vendor_prior_kev_count` | int | Max, over KEV vendor names mentioned in the description, of KEV additions for that vendor dated **before** the first day of `snapshot_month` | 0 |
| `assigner_prior_kev_count` | int | KEV additions dated before the first day of `snapshot_month` whose CVE has the same `assigner` (the CNA, e.g. `secure@microsoft.com`) | 0 |

`model.py` reads the feature list from this table (it is also the constant `FEATURE_COLUMNS` in
`prepare_data.py`) and fails fast if a column is missing or extra.

## 5. Columns deliberately NOT used
| Column | Why |
|---|---|
| `nvd_status`, `n_affected_cpes`, `n_references`, `last_modified` | NIST reviews KEV CVEs first, so these leak the outcome for 2026 |
| `references.csv` (all) | Links/tags are added after attacks |
| `affected_products.csv` | Blank for most unreviewed 2026 CVEs, so its presence leaks review status |
| `cwe_ids` | Blank for 95% of `Received` 2026 CVEs vs ~98% present otherwise; keyword flags cover the same ideas from text |
| "CVSS is blank" indicator | Proxy for NIST review status (explicit ban) |
| `in_kev`, KEV `date_added` | Target information |
| CVE-ID year, calendar publish month | ID year ≠ publish date; calendar month is not a causal signal |

## 6. Missing-value conventions
- No feature column contains blanks: every blank is filled as listed above.
- Blank EPSS / flags follow the scoreboard convention (no signal row → EPSS blank, flags 0);
  `epss_missing` keeps that information because it comes from FIRST, not NIST.
- Blank CVSS is filled with the constant 7.5 (the most common CVSS 3 score) and **no missing flag** is
  created, so the model cannot learn "unreviewed by NIST".

## 7. Known limitations (honest leakage statement)
- NIST files are 2026 snapshots. Descriptions and CVSS values may have been edited after a CVE was
  exploited. We cannot prove they existed at the cutoff. Description text is usually set by the vendor at
  publication, so we accept this risk. CVSS is a weaker case: NIST sometimes replaces a vendor score
  after review.
- In training data (2024–2025) almost every CVE has a CVSS score. In 2026 ~10% do not. The constant
  fill avoids leakage but creates a small train/predict distribution shift.
- EPSS coverage in the publish month is ~95–99% for most months but only 55% for Jan 2025 and 85% for
  Dec 2025, so `epss_missing` is noisier in those months.
- The KEV labels end 2025-12-31, so late-2025 cohorts are under-labelled.
- The time-based validation in `model.py` trains on 2024 cohorts whose labels extend into 2025. The
  rows and labels of the validation cohorts are never used in training, but the training labels
  were observed at the same time as the validation outcomes.
