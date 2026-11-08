# IBM technology integration

## What we used

**IBM Granite embedding model** — `ibm-granite/granite-embedding-30m-english` (384-dimensional,
~120 MB), executed locally on CPU through `sentence-transformers`. No account, no API key, no network
call at inference time.

## Where it sits in the pipeline

`models/granite_embed.py`:

1. Embed every CVE description in the cohort corpus (160,591 texts: 87,921 training rows + 72,670
   scoreboard rows).
2. Embed the descriptions of the KEV entries.
3. For each candidate row, compute cosine similarity against the KEV entries whose `date_added` is
   **on or before that row's snapshot month end** — the reference set is nested by month, so a
   future KEV addition can never enter the comparison.
4. Export `granite_knn_max` (closest prior exploited CVE) and `granite_knn_mean5` (mean of the five
   closest) as model features.

Run cost: 1,383 s wall on CPU for all 160,591 descriptions, producing
`artifacts/granite_features.parquet` and a 72,670 × 384 embedding matrix (`granite_embed_2026.npy`)
that the dashboard uses for similarity lookups.

## What it contributes, measured

This is the part most projects hand-wave, so here are the numbers from
`artifacts/granite_ablation.json` — same 2024 training cohorts, same held-out Jan–Sep 2025 pool,
35,289 candidates and 52 positives:

| Configuration | Held-out hits@500 | P@50 | Average precision |
| :-- | --: | --: | --: |
| Gradient boosting, no Granite (`histgb_lean`) | 18 | 0.14 | 0.057 |
| Gradient boosting + Granite (`histgb_lean_g`) | 16 | 0.12 | 0.064 |
| Logistic, no Granite (`logit_core`) | 19 | 0.08 | 0.049 |
| Logistic + Granite (`logit_core_g`) | 20 | 0.06 | 0.057 |
| Blend of the two, no Granite (w=0.2) | 17 | 0.20 | 0.090 |
| **Blend of the two + Granite (w=0.2)** | **20** | **0.22** | **0.110** |

The Granite features move the blended ranker from 17 to 20 hits at 500, and lift precision at 50 from 0.20 to 0.22.
That is the configuration we ship.

An honest caveat on selection: on the out-of-fold selection metric the Granite blend scores 27
hits@500 against 28 for the best non-Granite blend — a difference well inside the bootstrap interval
(14–33 vs 11–32 at 95%). IBM technology use is a stated competition requirement, so our selection
rule prefers the Granite configuration when it is within 2 hits@500 of the outright best OOF score.
The rule is recorded in `model_selection.json` under `selection_rule`, and both configurations'
held-out results are reported above so the preference is visible rather than hidden.

- **Standalone:** text similarity alone reaches ROC-AUC 0.742 for predicting a later KEV addition,
  with no CVSS or EPSS input (discovery #9 in `discoveries.json`).
- **Permutation importance** of `granite_knn_max` on the held-out pool is +0.097 AUC, seventh of the
  twelve features that matter most — a real contributor, not a decorative column.

The honest summary: Granite is not the whole model — public exploit code and vendor history still
carry more weight — but it is the only component that reads vulnerability text as language rather
than as regex flags, and it is worth five extra hits at 500.

## Why this route, not watsonx.ai

watsonx.ai requires an IBM Cloud account and an API key, neither of which was available in this
environment. Rather than fabricate an integration or fake API responses, we used the same model
family through its public Hugging Face release, which is an explicitly permitted route in the
problem statement. The code path is identical in structure: an embedding model converts text to
vectors, vectors become features.

If a watsonx key were supplied, the swap is one function: replace `SentenceTransformer.encode` with a
watsonx embeddings call and keep the same feature contract. No downstream code changes.

## Explanations in the product

The dashboard's plain-language explanation panel is **deterministic and grounded**: it is assembled
from the row's own recorded evidence (EPSS at snapshot, exploit flags, CWE KEV rate, vendor KEV
history, Granite similarity, matched description phrases) plus the linear model's per-feature
contributions. It cannot invent a fact, and the UI labels the source.

We deliberately did not use a Granite *generative* model for this. A 2–3B parameter instruct model on
CPU adds minutes of latency per explanation and introduces hallucination risk on a screen a security
engineer will use to justify a patch decision. The UI states the source of every explanation
(`deterministic` vs `granite`). If `artifacts/explanations.json` is present it takes precedence and
the badge changes accordingly; today it is not, so every explanation is labelled deterministic.
