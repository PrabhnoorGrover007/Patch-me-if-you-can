# Model evaluation

All numbers on this page come from the artefacts in `artifacts/` and were regenerated after the
2026-11-08 cohort audit. Nothing is estimated.

- `model_selection.json` — selection table, held-out table, permutation importance
- `granite_ablation.json` — Granite on/off comparison
- `gap_analysis.json` — baselines' blind spot and what the model recovers
- `backtest_baselines.json` — baseline reproduction

## Protocol

| Stage | Cohorts | Candidates | Positives | Used for |
| :-- | :-- | --: | --: | :-- |
| Selection | 2024-01 … 2024-12 (6 folds, grouped by month, **folds inside 2024 only**) | 39,868 | 67 | model choice, blend weight |
| Held-out | 2025-01 … 2025-09 (nine months, mirrors the 2026 benchmark shape) | 35,280 | 52 | confirmation only |
| Final refit | 2024-01 … 2025-12 | 87,907 | 122 | the shipped model |
| Prediction | 2026-01 … 2026-09 | 72,670 | unknown | `top500.csv` |

Label: KEV added **strictly after** the end of the row's `snapshot_month`. Splits are grouped by
month, never random. The candidate population excludes every CVE that was already on KEV at its
snapshot; this is enforced from the authoritative KEV date, not from the monthly signal file's
`in_kev` flag.

The follow-up audit found that the old code filled a missing monthly signal row with
`in_kev = 0`, which admitted **14 already-exploited CVEs** into the candidate cohort. Removing them
changed the training table from 87,921 to **87,907** rows. The target count stayed at 122. The
selection table and every downstream metric below are from the corrected population.

## Held-out results (Jan–Sep 2025, 35,280 candidates, 52 positives)

| Ranker | hits@500 | P@50 | P@100 | AP | ROC-AUC | 95% bootstrap @500 |
| :-- | --: | --: | --: | --: | --: | --: |
| CVSS 3.1 descending | 5 | 0.06 | 0.04 | 0.006 | 0.732 | 2–11 |
| EPSS descending | 8 | 0.06 | 0.04 | 0.031 | 0.707 | 3–14 |
| Public exploit first, then EPSS | 18 | 0.08 | 0.08 | 0.047 | 0.768 | 10–27 |
| Gradient boosting, no Granite (`histgb_lean`) | 17 | 0.14 | 0.09 | 0.060 | 0.834 | 9–25 |
| Granite-augmented logistic (`logit_core_g`) | 20 | 0.08 | 0.09 | 0.057 | 0.835 | 11–28 |
| **Final blend (shipped)** | **22** | **0.24** | **0.14** | **0.119** | **0.848** | 13–31 |

What this says, without inflation:

- **We find 22 of 52 exploited CVEs at a 500-row budget**; the strongest publication-style baseline
  finds 18. The four-hit gap is inside the bootstrap interval on a 52-positive pool, so we claim the
  direction, not the magnitude.
- **The advantage is concentrated where it matters.** P@50 is 0.24 against 0.08 for the best baseline:
  for the ten CVEs an analyst opens first, we are right about 3× as often. AP is 2.5× the baseline's,
  so the ordering is better throughout, not just at the cut-off.
- **ROC-AUC 0.848 vs 0.768** is the cleanest separation and does not depend on a budget.
- The model is a blend of `histgb_lean` (no Granite) and `logit_core_g` (Granite-augmented logistic).
  It is not a pure Granite model, and the ablation below shows Granite's contribution separately.

The competition's published reference numbers (7 / 6 / 8 hits) come from a different pool, so they
are not directly comparable to the 5 / 8 / 18 above. We reproduce baselines on the same historical
pool to check that the implementations are sane; the ordering is consistent.

## Blind spot analysis

`eval/gap.py` asks a sharper question than "how many do we find": of the exploited CVEs that *no*
conventional ranking surfaces, how many do we recover?

| Quantity | Value |
| :-- | --: |
| Exploited CVEs in the held-out pool | 52 |
| Missed by all three baselines' top 500 | 33 (63%) |
| Found by our top 500 | 22 |
| Baselines' union top-500 hits | 19 |
| Model hits | 22 |
| Blind-spot CVEs recovered by the model | **7 of 33** |

The seven recoveries are `CVE-2024-53704`, `CVE-2024-54085`, `CVE-2025-2746`, `CVE-2025-2747`,
`CVE-2025-9242`, `CVE-2025-24472` and `CVE-2025-41244`: products with a KEV history and/or a
description/weakness pattern the conventional rankings ignore, often with no public exploit code at
snapshot time.

## Selection table (2024 out-of-fold, folds inside 2024)

Hits@500 / hits@100 across six month-grouped folds.

| Model | Features | 2024 OOF @500 / @100 |
| :-- | --: | :-- |
| `histgb_full` | 71 | 25 / 11 |
| `histgb_lean` | 70 | 29 / 13 |
| `histgb_deep` | 71 | 24 / 10 |
| `logit_core` | 26 | 21 / 10 |
| `logit_core_reg` | 26 | 23 / 11 |
| `histgb_lean_g` | 72 | 29 / 14 |
| `logit_core_g` | 28 | 23 / 10 |

**Shipped configuration:** `histgb_lean + logit_core_g`, `w_b = 0.8` on the Granite-augmented
logistic model. Its 2024 OOF score is 26 @500 / 18 @100. The pair's maximum @500 is 29 at `w_b=0.2`;
the rule treats weights within three hits@500 as tied and uses hits@100 to choose inside the plateau.
That is a noisy tie-break. We report both facts because the selected weight is not the OOF maximum,
and the held-out 22 is confirmation rather than an independent choice.

The Granite preference rule selected a pair whose best OOF score (29) is within two hits of the
outright best (30), so `granite_preference_applied` is true. The selected weight was then chosen by
the same @100 tie-break. This is a documented judgement call, not a statistically established
improvement over every nearby configuration.

## Permutation importance (held-out pool, AP drop)

| Feature | ΔAP |
| :-- | --: |
| `epss_x_exploit` | 0.035 |
| `con_ord` | 0.010 |
| `desc_words` | 0.008 |
| `cvss3` | 0.006 |
| `nuclei` | 0.005 |
| `n_exploit_sources` | 0.004 |
| `epss_rank` | 0.004 |
| `pub_month` | 0.003 |
| `any_exploit` | 0.002 |
| `vendor_is_generic_cna` | 0.001 |
| `vendor_kev_n_log` | 0.001 |
| `pr_ord` | 0.001 |

EPSS × exploit-code dominates. Granite is not in the top twelve permutation features; its measured
contribution is in the controlled ablation, not the headline importance table.

## Corrections after independent review

### 1. NIST-review leakage through blank severity and CWE (real)

The first model kept blank CVSS as `NaN` (a tree can split on missing) and shipped `cwe_missing`,
`n_cwe` and 35 CWE dummies. Blank severity and blank CWE are recorded when NIST has not analysed the
record, and NIST analyses attacked CVEs first. The top 500 had 0.0% blank severity and 0.0% blank CWE
against an 8.7% / 6.8% pool. Those CWE-derived columns were removed and every CVSS column is
median-imputed before the model sees it, for both model families.

### 2. Selection trained on the future (real)

The first `oof_scores()` ran `GroupKFold` over 2024–2025 and then read the 2024 rows out, so each 2024
prediction came from folds containing 2025 months. Folds now live entirely inside 2024.

### 3. Candidate cohort admitted already-exploited CVEs (real, fixed in this audit)

`build_train` filtered on the signal file's `in_kev` flag after filling missing rows with zero. The
authoritative KEV date showed **14 rows already on KEV at their snapshot**. The cohort now filters on
`kev_added <= snapshot_end` before labels are constructed, and `test_labels_only_count_future_additions`
asserts that no such row remains. Training rows: 87,921 → 87,907.

### 4. Blend weight chosen on a noisy cut-off (partly real)

The first version picked the weight on hits@500 alone. The current rule treats a three-hit plateau as
tied and breaks the tie on hits@100. That selected `w_b=0.8` for the mixed pair, with 26 OOF hits
rather than the pair maximum 29. The choice is transparent but not strongly identified; nearby
weights have overlapping uncertainty.

### 5. Residual review-status tilt (real, reduced but not eliminated)

After the cohort fix, the top 500 is **0.2% blank severity**, **0.4% blank CWE** and **56.2%
NIST-Analyzed** against a pool that is roughly 43% Analyzed and 8.7% blank-severity. The tilt is
smaller than the pre-fix 62.4% Analyzed, but it is not zero. Correlation between review status and
description/vendor features can still influence the ranking; closing that completely would require a
review-status audit of every text and metadata feature.

### 6. Single-batch concentration (real, reduced)

**63 of 500 rows (12.6%)** are CVEs published on 2026-07-21, and 80 rows are assigned to
`vulncheck`; formerly 107 rows were from one July batch. This is still a visible vendor/date prior,
not a model bug, and it is documented as a risk rather than hidden.

## What we did not do

- **No random split, no stratified shuffle, no cross-month leakage.** Grouping is by `snapshot_month`.
- **No target encoding on the full training set.** Priors are computed as-of each row's snapshot month.
- **No CWE-derived feature and no un-imputed severity column.**
- **No 2026 data in any fit, weight, threshold or feature choice.** The 2026 scoreboard appears only in
  `predict.py`.
- **No threshold tuning on held-out.** The submission is a ranking; no probability cut-off is tuned.

## Reporting limitation

The official 2026 answer key does not exist in the release (KEV entries end 2025-12-29), so the 2026
performance of this submission is **unknown until judges score it**. Everything above is historical
validation on 2024–2025 cohorts, plus a diagnostic count on the live 2026 KEV feed that was used to
*report*, never to select.
