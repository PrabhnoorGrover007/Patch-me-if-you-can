# Findings: what the historical data says

These numbers come from the real challenge files (`known_exploited.csv`, the 2024/2025 signal files
and `vulnerabilities.csv`), using `outputs/train.csv`. That file holds 82,427 CVEs published from
Jan 2024 to Nov 2025, each captured at the end of its publish month. 119 of them (0.14%) were added
to KEV after that cutoff and by 2025-12-31.
"Lift" means how many times more likely a group is to be exploited than the average CVE.

## 1. Most KEV additions happen before the scoreboard even starts, so the leftovers are a hard problem
Of the 303 KEV entries for CVEs published Jan 2024 to Nov 2025, **26% were added on or before the day
the CVE was published** and **49% within 5 days** (median 6 days). **60% were added in the same
calendar month** as publication. The scoreboard drops anything already on KEV by the end of its
snapshot month, so these fast cases are gone. What's left to predict is the slower 40%. That's why the
public baselines only find 6 to 8 of them, and why our training set mirrors the same exclusion
(185 already-on-KEV CVEs removed).

## 2. Public exploit code is the strongest single signal, but more than half the exploited CVEs have none
- Any exploit flag (Exploit-DB, Metasploit, Nuclei or GitHub PoC): 2.4% exploited, **lift 17x**.
- **A Nuclei scanner template: 8.0% exploited (22 of 274), lift 56x.** A scanner template means
  defenders, and attackers, can already test for the bug at scale.
- But **62% of later-exploited CVEs (74 of 119) had no exploit flag at the cutoff.** Ranking by flags
  alone can't find them.

## 3. Vendor text that admits exploitation is rare but very strong
Descriptions that say the bug "may have been exploited" or was "exploited in the wild" (wording
Apple and others use) appear on only 48 training CVEs, and **7 of them (15%) were later added to
KEV, lift 101x.** Bug-type wording also matters:
| Description mentions | CVEs | KEV rate | Lift |
|---|---|---|---|
| Authentication bypass | 1,112 | 1.08% | 7.5x |
| Command / code injection | 2,708 | 0.59% | 4.1x |
| Remote code execution | 7,605 | 0.39% | 2.7x |
| VPN / firewall / gateway / router | 2,258 | 0.35% | 2.5x |
| Cross-site scripting | 15,238 | 0.03% | 0.2x |
| SQL injection | 6,302 | 0.05% | 0.3x |
| **WordPress plugin/theme** | **8,325** | **0 of 8,325** | **0x** |

WordPress plugins make up 10% of all new CVEs and none were exploited in this window. Pushing them
down the list frees space in the top 500.

## 4. Severity (CVSS) helps a little, but "critical" is far too big a group to fix first
CVSS 9+ CVEs are exploited at 0.55% (lift 3.8x), and CVSS under 7 at 0.03%. But there are 10,808
critical CVEs in the training window, 20x more than a top-500 list. In our 2025 validation, ranking
by CVSS found **10** exploited CVEs in the top 500. Exploit-flags-then-EPSS found **20**.

## 5. Past exploitation of a vendor shows up where exploit code is missing
For each CVE we count how many KEV entries its vendor (named in the description) or its assigning
organization had **before** the snapshot month. This is point-in-time, so it doesn't leak. On its
own it's a modest signal (lift 1.5x for 10+ prior KEV entries, because Microsoft-sized vendors
publish thousands of CVEs). But **62% of exploited CVEs with no exploit code (46 of 74) came from
vendors with 10+ prior KEV entries.** It covers the gap that finding 2 leaves.

## How this shaped the model (historical validation, not the official score)
We trained on the 2024 cohorts and tested on 2025 (42,559 CVEs, 52 later-exploited). Top 293 is the
same 0.69% share as the top 500 of the scoreboard.
| Ranking | Hits in top 293 | Hits in top 500 |
|---|---|---|
| CVSS first | 5 | 10 |
| EPSS first | 11 | 13 |
| Exploit flags then EPSS | 15 | **20** |
| Our logistic regression | **17** | 18 |
| Gradient boosting | 11 | 12 |

The logistic regression is roughly level with the strongest simple baseline. With only 52
validation positives, a difference of 1 to 3 hits is noise. These are 2024–2025 numbers. They don't
tell us how we'll score on the official 2026 check, and we make no claim to beat the challenge
benchmarks.

## What we tried from the teammate's branch (and why it isn't in the model)
We tested the teammate's ideas the same way: picked settings with 6-fold month-grouped
cross-validation on 2024, then checked once on the 2025 holdout, with a 500-sample bootstrap of the
difference against our logistic regression.
| Candidate | CV 2024, top 274 | 2025, top 293 | 2025, top 500 | 2025 difference vs ours (90% range) |
|---|---|---|---|---|
| Our logistic regression | 12 | **17** | 18 | 0 |
| Gradient boosting (all features) | 18 | 11 | 12 | −6.5 (−12 to −2) |
| Gradient boosting without raw EPSS | 17 | 11 | 12 | −6.5 (−12 to −2) |
| Blend: 15% logistic + 85% boosting | 18 | 12 | 17 | −5.7 (−10 to −2) |
| Blend: 80% logistic + 20% flags rule | 14 | 17 | 17 | −0.5 (−2 to 0) |
| + CWE one-hots, CWE KEV count, cwe×exploit, epss×exploit | 10–11 | 9–12 | 11–13 | worse |

Boosting looks better inside 2024 but doesn't carry over to 2025, so we keep the simpler model.
CWE features were also worse, and a blank CWE gives away NIST review status for 2026.
The Granite KEV-similarity feature is point-in-time safe as the teammate built it (it only compares
against KEV entries added by each snapshot month end). We could not re-test it here because the
model download was blocked, and the teammate's own ablation was mixed (+2 for logistic, −1 for
boosting at top 500).

## Limits to mention in the write-up
- Columns used: `published`, `description`, `assigner`, CVSS 3/4 score and vector (blank filled with
  7.5, no missing flag), the EPSS and exploit flags at the snapshot, and KEV dates (for labels and
  for prior-KEV counts dated before each cutoff). Not used: `nvd_status`, `n_affected_cpes`,
  `n_references`, `references.csv`, `affected_products.csv`, `cwe_ids`.
- Descriptions and CVSS are NIST's 2026 versions, so we can't prove they looked the same at each
  cutoff.
- A CVE missing from KEV may still have been attacked. Labels stop at 2025-12-31.
