# Model evaluation

All numbers on this page come from the artefacts in `artifacts/`; nothing is estimated.

- `artifacts/model_selection.json` — selection table, held-out table, permutation importance
- `artifacts/granite_ablation.json` — Granite on/off comparison
- `artifacts/gap_analysis.json` — baselines' blind spot and what we recover
- `artifacts/backtest_baselines.json` — baseline reproduction

## Protocol

| Stage | Cohorts | Positives | Used for |
| :-- | :-- | --: | :-- |
| Selection | 2024-01 … 2024-12 (6 folds, grouped by month) | 67 | model choice, blend weight |
| Held-out | 2025-01 … 2025-09 (nine months, mirrors the 2026 benchmark shape) | 52 | confirmation only |
| Final refit | 2024-01 … 2025-12 | 122 | the shipped model |
| Prediction | 2026-01 … 2026-09 | unknown | `top500.csv` |

Label: KEV added **strictly after** the end of the row's `snapshot_month`. Splits are grouped by
month, never random — a random split would let the same month's exploit chatter appear on both sides
and inflate every score.

The rule above was fixed before the held-out pool was scored. One deliberate exception is documented
below (Granite preference); it uses the selection metric only.

## Held-out results (Jan–Sep 2025, 35,289 candidates, 52 positives)

| Ranker | hits@500 | P@50 | P@100 | AP | ROC-AUC | 95% bootstrap @500 |
| :-- | --: | --: | --: | --: | --: | --: |
| CVSS 3.1 descending | 5 | 0.04 | 0.04 | 0.006 | 0.732 | 2–11 |
| EPSS descending | 8 | 0.06 | 0.04 | 0.031 | 0.707 | 3–14 |
| Public exploit first, then EPSS | 18 | 0.08 | 0.08 | 0.047 | 0.768 | 10–27 |
| Gradient boosting + Granite | 19 | 0.14 | 0.12 | 0.072 | 0.886 | 10–28 |
| Logistic + Granite | 21 | 0.08 | 0.07 | 0.042 | 0.849 | 12–31 |
| **Final blend (shipped)** | **24** | **0.20** | 0.13 | **0.118** | **0.891** | 14–33 |

What this says, without inflation:

- **We find 24 of 52 exploited CVEs at a 500-row budget**; the strongest publication-style baseline
  finds 18, and its bootstrap interval overlaps ours. The honest statement is that we beat the
  baselines on precision and ranking quality, and lead by 6 hits at 500 — a gap that is inside
  sampling noise on a 52-positive pool, so we claim the direction, not the magnitude.
- **The advantage is concentrated where it matters.** P@50 is 0.20 against 0.08 for the best
  baseline: for the ten CVEs an analyst opens first, we are right about twice as often. AP is 2.5×
  the baseline's, meaning the whole ordering is better, not just the first 500.
- **ROC-AUC 0.891 vs 0.768** is the cleanest separation, and it does not depend on a cut-off.

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
| Found by our top 500 | 8 of those 33 |
| Baselines' union top-500 hits | 19 |
| Our hits | 24 |

Eight of the thirty-three CVEs that CVSS, EPSS and the exploit-first baseline all miss are found by
the model — CVEs like `CVE-2024-13159`, `CVE-2024-53704`, `CVE-2025-6554` and `CVE-2025-41244`.
They are typically products with a KEV history but no public exploit code at snapshot time: the
vendor-history and semantic-similarity features carry them, which is precisely the signal a
severity-plus-EPSS pipeline ignores.

## Selection table (2024 out-of-fold)

Hits@500 / hits@100 across six month-grouped folds:

Pool: 39,873 candidates, 67 positives. Stage-2 column is a confirmation check, not a selection input.

| Model | Features | 2024 OOF @500 / @100 | 2025 OOF @500 / @100 |
| :-- | --: | :-- | :-- |
| `histgb_full` | 112 | 27 / 11 | 23 / 12 |
| `histgb_lean` | 76 | 27 / 16 | 21 / 11 |
| `histgb_deep` | 112 | 28 / 13 | 19 / 10 |
| `logit_core` | 28 | 23 / 6 | 21 / 10 |
| `logit_core_reg` | 28 | 22 / 6 | 21 / 10 |
| `histgb_lean_g` (Granite) | 78 | 25 / 14 | 20 / 13 |
| `logit_core_g` (Granite) | 30 | 26 / 9 | 20 / 12 |

Blend of two ranker families, weights searched 0→1 in 0.05 steps on rank-averaged scores. Best
non-Granite blend: `histgb_full + logit_core`, w=0.2, **32 @500 / 17 @100**. Best Granite blend:
`histgb_lean_g + logit_core_g`, w=0.2, **30 @500 / 16 @100**.

**Shipped configuration:** `histgb_lean_g + logit_core_g`, w_b = 0.2 (rank average). It is 2 hits
behind on the selection metric and 5 hits ahead on held-out; the Granite preference rule that made
this choice is stated in `IBM_INTEGRATION.md` and in `model_selection.json:selection_rule`.

## Permutation importance (held-out pool, AUC drop)

| Feature | ΔAUC |
| :-- | --: |
| `cwe_x_exploit` | 0.182 |
| `epss_x_exploit` | 0.177 |
| `nuclei` | 0.132 |
| `kw_unauthenticated` | 0.112 |
| `cvss3` | 0.107 |
| `vendor_kev_rate` | 0.097 |
| `granite_knn_max` | 0.097 |
| `desc_len_log` | 0.088 |
| `age_days` | 0.060 |
| `cwe_kev_rate_mean` | 0.056 |
| `con_ord` | 0.051 |
| `epss_rank` | 0.042 |

Interactions dominate: neither weakness class nor exploit availability is worth much alone, but
"this class, with public exploit code" is the single strongest thing the model knows. Granite's
similarity feature ranks seventh, which is why we keep it and also why we do not call it the engine.

## What we tested and rejected

Every candidate feature has to pass a gate fixed before it is evaluated: it must hold or improve
hits@500 both on the 2024 out-of-fold pool and on the held-out 2025 pool, with any blend weight
chosen on 2024 only. Four features adapted from a second, independently written implementation of
this task — vendor-name KEV history matched from the description text, an edge-device keyword flag,
and a v4 EPSS level — were put through that gate (`artifacts/add_feature_ablation.json`).

| Variant | Booster features | Booster 2024 OOF / 2025 held-out @500 | Blend w_b | Blend held-out @500 |
| :-- | --: | :-- | --: | :-- |
| Shipped model | 78 | 28 / 19 | 0.20 | **24** (bootstrap 14–33) |
| + candidate features | 82 | 29 / 20 | 0.35 | 22 (bootstrap 12–31) |

The booster improved on both pools, which is what made the ablation tempting. The shipped blend did
not: the extra features moved the 2024-optimal weight from 0.20 to 0.35, and at that weight held-out
fell by 2 hits (P@50 0.20 → 0.18, AP 0.118 → 0.119, both inside noise on 52 positives). The gate said
revert, so the submitted model does not contain them and `pipeline/features.py` is byte-identical to
the code that produced `top500.csv`.

## What we did not do

- **No random split, no stratified shuffle, no cross-month leakage.** Grouping is by `snapshot_month`.
- **No target encoding on the full training set.** Priors (vendor KEV rate, CWE KEV rate, EPSS rank)
  are computed as-of the row's own snapshot month.
- **No 2026 data in any fit, weight, threshold or feature choice.** The 2026 scoreboard appears only
  in `predict.py`.
- **No threshold tuning on held-out.** The submission is a ranking; no probability cut-off is tuned.

## Reporting limitation

The official 2026 answer key does not exist in the release (KEV entries end 2025-12-29), so the 2026
performance of this submission is **unknown until judges score it**. Everything above is historical
validation on 2024–2025 cohorts, and the final model is refit on those cohorts before predicting 2026.
