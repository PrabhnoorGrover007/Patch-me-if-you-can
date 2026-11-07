# Findings: what the historical data says

These numbers come from the real challenge files (`known_exploited.csv`, the 2024/2025 signal files
and `vulnerabilities.csv`), using `outputs/train.csv`. That file holds 78,287 CVEs published from
Jan 2024 to Nov 2025, each captured at the end of its publish month. 111 of them (0.14%) were added
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
- **A Nuclei scanner template: 8.0% exploited (22 of 274), lift 57x.** A scanner template means
  defenders, and attackers, can already test for the bug at scale.
- But **59% of later-exploited CVEs (66 of 111) had no exploit flag at the cutoff.** Ranking by flags
  alone can't find them.

## 3. Vendor text that admits exploitation is rare but very strong
Descriptions that say the bug "may have been exploited" or was "exploited in the wild" (wording
Apple and others use) appear on only 47 training CVEs, and **7 of them (15%) were later added to
KEV, lift 105x.** Bug-type wording also matters:
| Description mentions | CVEs | KEV rate | Lift |
|---|---|---|---|
| Authentication bypass | 1,087 | 1.10% | 7.8x |
| Command / code injection | 2,599 | 0.58% | 4.1x |
| Remote code execution | 7,311 | 0.37% | 2.6x |
| VPN / firewall / gateway / router | 2,193 | 0.36% | 2.6x |
| Cross-site scripting | 14,149 | 0.04% | 0.2x |
| SQL injection | 5,921 | 0.03% | 0.2x |
| **WordPress plugin/theme** | **8,149** | **0 of 8,149** | **0x** |

WordPress plugins make up 10% of all new CVEs and none were exploited in this window. Pushing them
down the list frees space in the top 500.

## 4. Severity (CVSS) helps a little, but "critical" is far too big a group to fix first
CVSS 9+ CVEs are exploited at 0.56% (lift 3.9x), and CVSS under 7 at 0.03%. But there are 10,227
critical CVEs in the training window, 20x more than a top-500 list. In our 2025 validation, ranking
by CVSS found **10** exploited CVEs in the top 500. Exploit-flags-then-EPSS found **20**.

## 5. Past exploitation of a vendor shows up where exploit code is missing
For each CVE we count how many KEV entries its vendor (named in the description) or its assigning
organization had **before** the snapshot month. This is point-in-time, so it doesn't leak. On its
own it's a modest signal (lift 1.4x for 10+ prior KEV entries, because Microsoft-sized vendors
publish thousands of CVEs). But **61% of exploited CVEs with no exploit code (40 of 66) came from
vendors with 10+ prior KEV entries.** It covers the gap that finding 2 leaves.

## How this shaped the model (historical validation, not the official score)
We trained on the 2024 cohorts and tested on 2025 (39,859 CVEs, 48 later-exploited). Top 274 is the
same 0.69% share as the top 500 of the scoreboard.
| Ranking | Hits in top 274 | Hits in top 500 |
|---|---|---|
| CVSS first | 5 | 10 |
| EPSS first | 11 | 13 |
| Exploit flags then EPSS | 15 | **20** |
| Our logistic regression | **17** | 18 |
| Gradient boosting | 11 | 17 |

The logistic regression is roughly level with the strongest simple baseline. With only 48
validation positives, a difference of 1 to 3 hits is noise. These are 2024–2025 numbers. They don't
tell us how we'll score on the official 2026 check, and we make no claim to beat the challenge
benchmarks.

## Limits to mention in the write-up
- Columns used: `published`, `description`, `assigner`, CVSS 3/4 score and vector (blank filled with
  7.5, no missing flag), the EPSS and exploit flags at the snapshot, and KEV dates (for labels and
  for prior-KEV counts dated before each cutoff). Not used: `nvd_status`, `n_affected_cpes`,
  `n_references`, `references.csv`, `affected_products.csv`, `cwe_ids`.
- Descriptions and CVSS are NIST's 2026 versions, so we can't prove they looked the same at each
  cutoff.
- A CVE missing from KEV may still have been attacked. Labels stop at 2025-12-31.
