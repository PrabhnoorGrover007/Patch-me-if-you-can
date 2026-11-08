# IBM technology integration

## What we used

**IBM Granite embedding model** — `ibm-granite/granite-embedding-30m-english` (384-dimensional,
~120 MB), executed locally on CPU through `sentence-transformers`. No account, no API key, no network
call at inference time.

## Where it sits in the pipeline

`models/granite_embed.py`:

1. Embed every CVE description in the cohort corpus (87,907 training candidates + 72,670 scoreboard
   rows after the 2026-11-08 candidate-cohort correction).
2. Embed the descriptions of the KEV entries.
3. For each candidate row, compute cosine similarity against the KEV entries whose `date_added` is
   **on or before that row's snapshot month end** — the reference set is nested by month, so a
   future KEV addition can never enter the comparison.
4. Export `granite_knn_max` (closest prior exploited CVE) and `granite_knn_mean5` (mean of the five
   closest) as model features, and keep the 2026 embedding matrix for the similarity endpoint.

Run cost: 1,383 s wall on CPU for the original 160,591 descriptions, producing
`artifacts/granite_features.parquet` and a 72,670 × 384 embedding matrix
(`granite_embed_2026.npy`). The 14 retired training rows were removed from the feature table without
re-embedding; their vectors are identical and they are no longer candidates.

## What it contributes, measured

This is the part most projects hand-wave, so here are the numbers from
`artifacts/granite_ablation.json` — same 2024 training cohorts, same held-out Jan–Sep 2025 pool,
35,280 candidates and 52 positives:

| Configuration | Held-out hits@500 | P@50 | Average precision |
| :-- | --: | --: | --: |
| Gradient boosting, no Granite (`histgb_lean`) | 17 | 0.14 | 0.060 |
| Gradient boosting + Granite (`histgb_lean_g`) | 18 | 0.12 | 0.068 |
| Logistic, no Granite (`logit_core`) | 19 | 0.08 | 0.050 |
| Logistic + Granite (`logit_core_g`) | 20 | 0.08 | 0.057 |
| Blend of the two, no Granite (w=0.2) | 16 | 0.22 | 0.098 |
| **Blend of the two + Granite (w=0.2)** | **20** | **0.20** | **0.124** |

The controlled ablation moves the blended ranker from 16 to 20 hits at 500. That is a real measured
association under this protocol, but it is not a clean causal estimate of "Granite alone": the
selected shipped pair is a mixed blend (`histgb_lean + logit_core_g`, `w_b=0.8`) and scores 22, while
the both-Granite blend scores 20. We report the mixed selection rather than presenting the best
Granite-only number as if it were the shipped model.

An honest caveat on selection: on the 2024 out-of-fold metric the selected pair's best score is 29
hits@500 against 30 for the outright best pair — inside the two-hit Granite preference tolerance — but
the selected weight itself is 26, chosen by a noisy hits@100 tie-break. IBM technology use is a stated
competition requirement, and the preference is recorded in `model_selection.json` under
`selection_rule`. The held-out 22 is confirmation, not an independent selection signal.

- **Standalone:** text similarity alone reaches ROC-AUC 0.742 for predicting a later KEV addition,
  with no CVSS or EPSS input (discovery #9 in `discoveries.json`).
- **Permutation importance:** Granite is not in the top twelve features on the held-out AP metric;
  EPSS × exploit code, CVSS, description length and vendor priors rank above it. Granite is a real
  secondary text signal, not the engine.

## Product surfaces that use Granite

- `GET /api/vulnerabilities/{cve_id}/similar` — cosine nearest neighbours from the 2026 Granite
  matrix. The endpoint labels similarity as similarity, never as exploitation probability.
- `POST /api/granite/analyze` — returns a deterministic, evidence-grounded DNA extraction plus
  Granite analog retrieval. It does **not** claim that Granite generated the extraction.
- `POST /api/granite/chat` — retrieval-grounded analyst answers from the ranked table, attribution and
  similarity index. It is explicitly labelled `generative_model: null`.
- `GET /api/granite/status` — model ID, dimensions, capability list and the no-generative-model
  limitation.

## Why this route, not watsonx.ai

watsonx.ai requires an IBM Cloud account and an API key, neither of which was available in this
environment. Rather than fabricate an integration or fake API responses, we used the same model
family through its public Hugging Face release, which is an explicitly permitted route in the
problem statement.

If a watsonx key were supplied, the swap is one function: replace `SentenceTransformer.encode` with a
watsonx embeddings call and keep the same feature contract. No downstream code changes.

## Explanations in the product

The dashboard's plain-language explanation panel is **deterministic and grounded**: it is assembled
from the row's own recorded evidence (EPSS at snapshot, exploit flags, vendor KEV history, Granite
similarity, matched description phrases) plus the linear model's per-feature contributions. It cannot
invent a fact, and the UI labels the source.

We deliberately did not use a Granite *generative* model for this. A multi-billion-parameter instruct
model on CPU adds latency and hallucination risk on a screen a security engineer will use to justify a
patch decision. The UI states the source of every explanation (`deterministic` vs `granite`). If
`artifacts/explanations.json` is present it takes precedence and the badge changes accordingly; today
it is not, so every explanation is labelled deterministic.

## What was not verified

- No live watsonx.ai call was made; no IBM Cloud credentials were available.
- No Granite instruct/generative model was run; the analyst endpoint is retrieval-grounded.
- The embedding model was run locally; its output is cached, not called live during a demo.
