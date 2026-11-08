# Model evaluation

All numbers on this page come from the artefacts in `artifacts/`; nothing is estimated.

- `artifacts/model_selection.json` — selection table, held-out table, permutation importance
- `artifacts/granite_ablation.json` — Granite on/off comparison
- `artifacts/gap_analysis.json` — baselines' blind spot and what we recover
- `artifacts/backtest_baselines.json` — baseline reproduction

## Protocol

| Stage | Cohorts | Positives | Used for |
| :-- | :-- | --: | :-- |
| Selection | 2024-01 … 2024-12 (6 folds, grouped by month, **folds inside 2024 only**) | 67 | model choice, blend weight |
| Held-out | 2025-01 … 2025-09 (nine months, mirrors the 2026 benchmark shape) | 52 | confirmation only |
| Final refit | 2024-01 … 2025-12 | 122 | the shipped model |
| Prediction | 2026-01 … 2026-09 | unknown | `top500.csv` |

Label: KEV added **strictly after** the end of the row's `snapshot_month`. Splits are grouped by
month, never random — a random split would let the same month's exploit chatter appear on both sides
and inflate every score. Selection folds were restricted to 2024 after an independent review caught
the earlier version training them on 2024–2025 and reading the 2024 rows out (see the correction log
below).

## Held-out results (Jan–Sep 2025, 35,289 candidates, 52 positives)

| Ranker | hits@500 | P@50 | P@100 | AP | ROC-AUC | 95% bootstrap @500 |
| :-- | --: | --: | --: | --: | --: | --: |
| CVSS 3.1 descending | 5 | 0.04 | 0.04 | 0.006 | 0.732 | 2–11 |
| EPSS descending | 8 | 0.06 | 0.04 | 0.031 | 0.707 | 3–14 |
| Public exploit first, then EPSS | 18 | 0.08 | 0.08 | 0.047 | 0.768 | 10–27 |
| Gradient boosting + Granite | 16 | 0.12 | 0.11 | 0.064 | 0.851 | 8–25 |
| Logistic + Granite | 20 | 0.06 | 0.09 | 0.057 | 0.835 | 11–29 |
| **Final blend (shipped)** | **20** | **0.22** | **0.12** | **0.110** | **0.857** | 12–31 |

What this says, without inflation:

- **We find 20 of 52 exploited CVEs at a 500-row budget**; the strongest publication-style baseline
  finds 18. The two-hit gap is inside sampling noise on a 52-positive pool, so we claim the direction,
  not the magnitude.
- **The advantage is concentrated where it matters.** P@50 is 0.22 against 0.08 for the best baseline:
  for the ten CVEs an analyst opens first, we are right about 2.75× as often. AP is 2.3× the
  baseline's, so the ordering is better throughout, not just at the cut-off.
- **ROC-AUC 0.857 vs 0.768** is the cleanest separation and does not depend on a budget.
- **This is 4 hits fewer than the first version of this report claimed.** That version scored 24/500
  by using NIST-review metadata; the correction log below explains why the lower number is the
  trustworthy one.

The competition's published reference numbers (7 / 6 / 8 hits) come from a different pool, so they
are not directly comparable to the 5 / 8 / 18 above; we reproduce them on our pool to check that our
baseline implementations are sane, and they order correctly.

## Blind spot analysis

`eval/gap.py` asks a sharper question than "how many do we find": of the exploited CVEs that *no*
conventional ranking surfaces, how many do we recover?

| Quantity | Value |
| :-- | --: |
| Exploited CVEs in the held-out pool | 52 |
| Missed by all three baselines' top 500 | 33 (63%) |
| Found by our top 500 | 5 of those 33 |
| Baselines' union top-500 hits | 19 |
| Our hits | 20 |

The five recoveries are `CVE-2024-53704`, `CVE-2025-6554`, `CVE-2025-9242`, `CVE-2025-24472` and
`CVE-2025-41244`: products with a KEV history but no public exploit code at snapshot time, which is
precisely the case a severity-plus-EPSS pipeline ignores. The pre-correction model recovered 8 of 33;
most of that extra reach came from the review-status shortcut, so we report the smaller number.

## Selection table (2024 out-of-fold, folds inside 2024)

Hits@500 / hits@100 across six month-grouped folds.

Pool: 39,873 candidates, 67 positives.

| Model | Features | 2024 OOF @500 / @100 |
| :-- | --: | :-- |
| `histgb_full` | 73 | 28 / 10 |
| `histgb_lean` | 70 | 30 / 13 |
| `histgb_deep` | 73 | 24 / 10 |
| `logit_core` | 26 | 21 / 10 |
| `logit_core_reg` | 26 | 23 / 11 |
| `histgb_lean_g` (Granite) | 72 | 30 / 13 |
| `logit_core_g` (Granite) | 28 | 23 / 10 |

Blend of two ranker families on rank-averaged scores. For
`histgb_lean_g + logit_core_g`, the weight is a plateau: w=0.0 scores 30/13, w=0.2 scores 27/16, w=0.35
scores 26/17 on @500/@100. One standard error on 67 positives is roughly four hits, so those @500
values are tied; the rule picks the best @100 inside that plateau, giving **w_b = 0.2**. That is also
the weight the first version shipped, chosen before the leakage correction, so the choice is not
tuned to the held-out pool.

**Shipped configuration:** `histgb_lean_g + logit_core_g`, w_b = 0.2 (rank average), OOF 27 @500 /
16 @100, held-out 20 @500. The Granite preference rule that made the family choice is stated in
`IBM_INTEGRATION.md` and in `model_selection.json:selection_rule`.

## Permutation importance (held-out pool, AP drop)

| Feature | ΔAP |
| :-- | --: |
| `epss_x_exploit` | 0.107 |
| `nuclei` | 0.061 |
| `n_exploit_sources` | 0.056 |
| `kw_unauthenticated` | 0.053 |
| `granite_knn_max` | 0.037 |
| `desc_len_log` | 0.037 |
| `cvss3` | 0.036 |
| `is_wordpress_eco` | 0.022 |
| `con_ord` | 0.022 |
| `kw_buffer_overflow` | 0.010 |
| `any_exploit` | 0.010 |
| `poc_github` | 0.009 |

EPSS × exploit-code dominates. Granite's similarity feature is fifth: we keep it, and we do not call
it the engine. CWE-derived columns no longer appear because they were removed (see below).

## Corrections after independent review

A second team reviewed this submission. Three of its criticisms were correct and are fixed here; two
did not survive checking. Each entry states the problem and the reasoning, because the reasoning is
the part that transfers.

### 1. NIST-review leakage through blank severity and CWE (problem: real)

The assignment warns that blank severity scores, `nvd_status`, `n_affected_cpes`, `n_references` and
reference links give the answer away, because NIST reviews attacked CVEs first. The first model
respected the letter of that list and broke its intent:

- `cwe_missing`, `n_cwe` and 35 CWE dummies were features. In training, `cwe_missing = 1` covered
  5,189 rows with **zero** positives.
- Blank CVSS was left as `NaN`. `HistGradientBoostingClassifier` splits on missing values natively,
  so "no score" was a learnable signal even without a `has_score` flag; blank-CVSS rows (3,089) also
  held zero positives.
- The result was visible in the submission: **0.0%** blank severity and **0.0%** blank CWE against a
  pool base rate of 8.7% and 6.8%, and 61.6% NIST-Analyzed against 43.0%. A leak-blind
  exploit-then-EPSS ranking puts 5.6% blank rows in its top 500, so the avoidance was not explained by
  risk: blank-CVSS rows had essentially the same EPSS and exploit rate as scored rows.

**Reasoning:** if every positive has a complete record and completeness is a consequence of being
reviewed, a model that avoids incomplete records is reading the label's shadow. The earlier defence in
`FEATURE_AUDIT.md` ("kept as NaN, no indicator") was wrong for tree models, and the earlier claim that
0% blank was *conservative* was backwards.

**Fix:** CWE-derived features are gone (dummies, `cwe_missing`, `n_cwe`, CWE KEV rates and the
CWE × exploit interaction), and every CVSS column is median-imputed before the model sees it, for both
the booster and the logistic model. 73 features remain.

**Measured cost:** 2 hits on the 2026 pool (15 → 13 of 53 scorable positives) and 4 on the 2025
held-out pool (24 → 20).

### 2. Selection trained on the future (problem: real)

`oof_scores()` ran `GroupKFold` over the whole 2024–2025 matrix and then read the 2024 rows out of it.
Each 2024 prediction therefore came from a model fitted on folds containing 2025 months. The old text
called this "2024 out-of-fold", which overstated it.

**Reasoning:** a selection metric that has seen the future selects for whatever generalises to 2025,
which is the same error as tuning on the held-out pool, one level up.

**Fix:** folds now live entirely inside the 2024 cohort, and the 2025 pool is scored only by models
refit on 2024.

### 3. Blend weight chosen on a noisy cut-off (problem: partly real)

The first version picked the weight by hits@500 alone (30 vs 27 for w=0.0 vs 0.2), which selected the
single booster even though @100 preferred the blend (13 vs 16). At 67 positives the @500 gap is inside
one standard error.

**Fix:** weights within 3 hits@500 of their pair's best are treated as tied and broken on hits@100;
Granite preference is unchanged at ±2. The shipped w=0.2 equals the weight chosen before the
correction, so nothing here is tuned to the held-out result.

### 4. Residual review-status tilt (problem: real, not fixed)

After removing CWE features and imputing severity, the new top 500 is still **0.0%** blank severity,
**0.2%** blank CWE and **62.4%** NIST-Analyzed against a 43% base rate. Deterministic imputation
removes the `NaN` split but not the correlation: reviewed records differ in description length,
keyword mix and Granite similarity too.

**Reasoning:** a model can infer "reviewed" from correlated metadata even when the banned columns are
absent. We report the residual instead of claiming the list is clean; closing it needs an explicit
review-status audit of every feature's missingness, which is not done here.

### 5. Single-batch concentration (problem: real, not fixed)

**107 of 500 rows (21.4%)** are CVEs published on 2026-07-21, and 114 are Oracle-assigned. A large
share of one vendor's patch-day output is a vendor prior doing too much work, and only a handful of
those rows carry an exploit signal. Recorded as the first next step; not corrected before submission.

### Claims that did not survive checking

- **"Our list was chosen using 2026 answers."** `top500.csv` has existed since the first commit
  (`672090f`) and its content is unchanged through the correction; the 2026 scoring script was added
  two commits later (`2fa32e6`, `7682450`). The 2026 pool was used for evaluation only, and no weight,
  feature or list choice was made from it.
- **"The two lists are tied 15–15 (16–15 at the cut-off)."** Under our label definition we measured
  20 vs 13 at the 2026-11-04 cut-off on the pre-correction list, and 13 vs 13 after the correction —
  not 15–15, and not at any of the six cut-offs checked. The tie claim is not reproducible from our
  code and is not used to justify anything.

## What we did not do

- **No random split, no stratified shuffle, no cross-month leakage.** Grouping is by `snapshot_month`.
- **No target encoding on the full training set.** Priors (vendor KEV rate, EPSS rank) are computed
  as-of the row's own snapshot month.
- **No CWE-derived feature and no un-imputed severity column.**
- **No 2026 data in any fit, weight, threshold or feature choice.** The 2026 scoreboard appears only
  in `predict.py`.
- **No threshold tuning on held-out.** The submission is a ranking; no probability cut-off is tuned.

## Reporting limitation

The official 2026 answer key does not exist in the release (KEV entries end 2025-12-29), so the 2026
performance of this submission is **unknown until judges score it**. Everything above is historical
validation on 2024–2025 cohorts, plus a diagnostic count on the live 2026 KEV feed that was used to
*report*, never to select.
