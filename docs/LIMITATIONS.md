# Limitations and honest caveats

## On the score

- **We cannot report the official 2026 result.** The answer key (KEV additions to 4 November 2026) is
  not in the supplied data — the KEV file ends 2025-12-29. Every performance number in this project is
  a *historical* validation number on reconstructed cohorts, and is labelled as such.
- **The historical pools are easier than the 2026 pool.** The Jan–Sep 2025 pool has 35,280 candidates
  and 52 positives (0.147%); the 2026 pool has 72,670 candidates. A top-500 slice is therefore a
  larger fraction of the historical pool, which flatters every method, baselines included. Our
  baselines score differently from the official 7/6/8 for exactly this reason (5/8/18 on our pool).

## On the labels

- **Right-censoring.** Labels are observed only to 2025-12-29. A CVE published in late 2025 that is
  exploited in 2026 is recorded as a negative. This biases all cohorts toward under-counting
  positives, most strongly for the most recent months.
- **KEV is a lower bound on exploitation.** A CVE absent from KEV may still have been attacked. KEV
  reflects CISA's confirmation and federal relevance, not all exploitation.
- **Only ~122 positive labels** across 24 monthly cohorts. This is why the model is a regularised
  shallow booster blended with a regularised logistic regression rather than a deep ensemble, and why
  bootstrap intervals on hits@500 span roughly ±9 hits.
- **Class imbalance is severe** (0.14%). Accuracy is meaningless here; we report precision@k, AP and
  ROC-AUC, and never quote accuracy.

## On the features

- **No EPSS or exploit history for 2023**, so 2023 cohorts are excluded from training instead of being
  imputed. This costs roughly a third of the available positives.
- **EPSS changed models in March 2025.** We use EPSS as a snapshot level and a within-month rank, never
  as a cross-year trend.
- **CPE product fields are excluded** because their presence correlates with NVD attention. The model
  therefore cannot use product identity, only the assigner-derived vendor. Assigner is a proxy: some
  CNAs (github.com, mitre.org) carry no vendor information, and CISA-ADP enrichment is collapsed to a
  neutral key.
- **Descriptions can be edited after publication.** Text features are therefore a lower bound on what
  was knowable at snapshot time; this is a small but real leak-adjacent risk, documented rather than
  hidden.
- **`horizon_days` encodes the evaluation cutoff.** It is a published competition rule, but for the
  historical cohorts the cutoff is 2025-12-29 rather than 2026-11-04, so the feature's distribution
  shifts slightly between train and predict.

## On the model

- **Blend weights were selected on 2024 out-of-fold scores** with 67 positives. That is a thin basis
  for a weight; the selected 0.2 vs 0.8 is not meaningfully better than nearby values, and we say so.
- **The Granite preference is a judgement call.** The selected pair's best 2024 OOF score is 29
  hits@500 against 30 for the outright best pair, and we preferred it because IBM technology use is a
  competition requirement; the selected weight itself scores 26, so the preference is not a clean
  win. It then scored 22 vs 18 on held-out, but that held-out result was observable to us before the
  final choice, so treat the preference as a documented decision rather than a clean pre-registered
  one. Both configurations are reported in MODEL_EVALUATION.md.
- **The permutation importances** are computed on a subsample of the held-out pool and are unstable
  under resampling; treat the ordering as indicative.
- **Calibration is approximate.** The blend is a rank average, so its output is a percentile, not a
  probability. The UI therefore calls it a risk score with a percentile, not a probability of
  exploitation.
- **Granite embeddings are float32 on CPU**; last-bit differences across BLAS implementations can
  move a cosine similarity by a few thousandths, but the features are recomputed from scratch and the
  ranking is stable at that scale.

## On the product

- **Browser verification was limited to what the environment allows** (no Chrome binary was available).
  The Next.js frontend was type-checked, production-built, served independently on :3000 and checked
  over HTTP together with the FastAPI service; see FRONTEND_TEST_REPORT.md for exactly what was and
  was not visually verified.
- **Explanations remain deterministic**, while the analyst chat can generate with a local Granite 2B
  model through llama.cpp. The local model is slower and less capable than hosted Granite 8B; every
  answer is constrained to retrieved evidence and falls back to the deterministic response on failure.
- **The dashboard shows the 2026 benchmark only.** It is a decision-support view, not a monitoring
  system with live ingestion.
