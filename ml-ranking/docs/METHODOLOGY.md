# Methodology

## 1. The prediction problem, stated precisely

The organisers define the benchmark as vulnerabilities published January–September 2026 that were
**not on KEV at the end of their `snapshot_month`**, scored with only what was known at that month
end, judged by how many appear in KEV by 4 November 2026.

That definition determines the label. If we trained on "is in KEV at all", roughly half our
positives would be CVEs that were added to KEV *within their publication month* — CVEs that are
**excluded from the 2026 pool by construction**. We would be optimising a distribution we are never
scored on. So:

> **Label = CISA added the CVE to KEV strictly after the end of its `snapshot_month`.**

Same filter, same snapshot semantics, same target as the scoreboard.

## 2. Rebuilding the benchmark from history

`exploit_signals_2024.csv` and `exploit_signals_2025.csv` hold, for every month, each
vulnerability's EPSS, KEV membership and public-exploit flags **as of that month end**. That is
exactly the shape of `scoreboard_2026.csv`, which is why the historical cohorts are trustworthy:

| | 2026 benchmark | Reconstructed cohort |
|---|---|---|
| Candidate | published in month *m*, not in KEV at month end | same |
| Snapshot | `snapshot_month` (publish month; June → July) | publish month |
| Features | scoreboard row + static record | signal row + static record |
| Label | KEV add before 4 Nov 2026 (**unknown**) | KEV add after month end, observed to 2025-12-29 |

Nine-month pools (Jan–Sep) mirror the 2026 shape exactly. Jan–Sep 2025 is the primary held-out pool.
2024 slots are excluded from training (no signal file) rather than imputed with all-missing EPSS,
which would teach the model a spurious "missing EPSS" prior that does not hold in 2026 (2% missing).

## 3. Features (112)

Built by `pipeline/features.py`; every group and its availability argument is in
[FEATURE_AUDIT.md](FEATURE_AUDIT.md).

- **Calendar / horizon** — publish month, weekday, day, age at snapshot, days from snapshot to the
  evaluation cutoff (the nine cohorts have very different exposure windows).
- **CVSS** — score, severity ordinal, vector decomposition, exploitability/impact sub-scores, CVSS4/2.
  The *missingness* of CVSS is deliberately not a feature (it is an NVD-review leak).
- **Weakness** — 35 CWE dummies plus as-of CWE KEV rate (KEV additions before month end only).
- **EPSS / exploit code** — EPSS, logit, within-month percentile, missing flag, and the four public
  exploit flags summed.
- **Vendor history** — vendor key from the CVE assigner, KEV counts/rates with `date_added <= month end`,
  90- and 365-day recency windows, ransomware share of that vendor's KEV entries.
- **Text** — 26 regex indicators plus length. Chosen for interpretability, not accuracy.
- **Interactions** — EPSS × exploit code, CWE-rate × exploit code, WordPress-ecosystem and GitHub-CNA
  flags, "silent critical" (CVSS ≥ 9 with no public exploit).
- **IBM Granite** — cosine similarity of each description to KEV descriptions available at that
  snapshot; `max` and `mean-of-top-5`. The reference set is nested by month, so the feature cannot
  see a future addition.

## 4. Models compared

Tuned for ~120 positive labels, not for leaderboard theatre. Deep boosting overfits this sample,
which the out-of-fold numbers showed, so a strongly regularised logistic regression is a legitimate
contender rather than a token baseline.

| Candidate | Why it is here |
|---|---|
| CVSS-first, EPSS-first, PoC-then-EPSS | The published baselines, reproduced with deterministic tie-breaks |
| `histgb_full` / `histgb_lean` / `histgb_deep` | Histogram gradient boosting, three capacity settings |
| `logit_core` / `logit_core_reg` | L2 logistic regression on 29 standardised features, balanced class weights |
| `*_g` variants | Same models plus the IBM Granite similarity features |
| `final_blend` | Rank-average of the best boosting model and the best linear model, weight chosen on 2024 |

No random forest, no neural network, no stacking: with this many positives, additional capacity
buys variance, not signal. (LightGBM/XGBoost are not installed in this environment; scikit-learn's
histogram booster covers the same ground and was measured, not assumed.)

## 5. Validation protocol

1. **GroupKFold by snapshot month** (6 folds) over all 24 monthly cohorts — no row from a month is
   ever in both halves of a fold.
2. Model and blend selection read **only the 2024 out-of-fold columns**.
3. The chosen configuration is refit on 2024 alone and scored on the **Jan–Sep 2025 pool** — a real
   held-out year, never used for a decision.
4. Metrics: hits@500 (the official metric), precision@50/100/250/500, average precision, ROC-AUC,
   and a row-level bootstrap for hits@500.
5. Final submission model is refit on 2024–2025 and applied to 2026. **2026 labels are never used.**

Because the pool contains ~0.15% positives, absolute hit counts are noisy: we report bootstrap
intervals everywhere and do not claim significance where intervals overlap.

## 6. Reproduce

```bash
python -m pipeline.prepare_data     # raw CSV -> parquet
python -m pipeline.features         # cohorts + features
python -m models.granite_embed      # IBM Granite similarity features (slow, CPU)
python -m pipeline.discoveries      # discovery statistics
python -m models.train              # selection, held-out evaluation, final fit
python -m models.predict            # ranked_2026.csv, full_rankings.csv, top500.csv
python -m pipeline.audit            # feature availability audit
```
