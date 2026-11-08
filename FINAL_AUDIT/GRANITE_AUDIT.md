# IBM Granite audit

## What is genuinely IBM

- Model: **`ibm-granite/granite-embedding-30m-english`**, 384 dimensions.
- Runtime: `sentence-transformers` on CPU, public Hugging Face weights. No watsonx.ai call, no IBM
  Cloud credentials, no API key.
- Corpus: 87,907 training descriptions + 72,670 scoreboard descriptions after the cohort correction
  (160,577 rows). `artifacts/granite_meta.json` records 87,907 / 72,670 and 1,484 KEV reference rows.
- Feature: max and mean-of-top-5 cosine similarity to KEV descriptions added **before** each row's
  snapshot month end. The reference set is nested by month, so future KEV additions cannot enter.
- Product: `/api/vulnerabilities/{id}/similar` uses the 2026 384-d matrix; `/api/granite/analyze`
  returns analogs; `/api/granite/chat` cites the similarity source.

## Measured contribution

Controlled ablation, same 2024 training cohorts and Jan–Sep 2025 held-out pool:

| Configuration | hits@500 | P@50 | AP |
| :-- | --: | --: | --: |
| no-Granite blend (`w=0.2`) | 16 | 0.22 | 0.098 |
| both-Granite blend (`w=0.2`) | 20 | 0.20 | 0.124 |
| gradient boosting alone / + Granite | 17 / 18 | 0.14 / 0.12 | 0.060 / 0.068 |
| logistic alone / + Granite | 19 / 20 | 0.08 / 0.08 | 0.050 / 0.057 |
| shipped mixed blend (`histgb_lean + logit_core_g`, 0.8) | **22** | **0.24** | **0.119** |

The both-Granite blend gains four hits in the controlled comparison. The shipped model is a mixed
blend and is better still, but that is not evidence that Granite alone caused the gain. Permutation
importance does not put either Granite feature in the top twelve; EPSS × exploit code dominates.
Granite is a real secondary text signal, not the engine.

Standalone text similarity reaches ROC-AUC **0.742** for a future KEV addition with no CVSS or EPSS
input.

## What is not Granite

- **Structured DNA extraction is deterministic.** `/api/granite/analyze` uses conservative regex rules
  over the description, returns evidence sentences and leaves unknown properties unknown. It is
  labelled `source: deterministic_rules` and `generative_model: null`. The test suite asserts that
  label.
- **The analyst assistant is retrieval-grounded, not generative.** It assembles answers from the
  ranked row, attribution, CVSS/EPSS and similarity index. It does not invent KEV membership or
  exploit availability, and it says "prediction is not confirmation of exploitation".
- **No live watsonx.ai call has been made.** No IBM Cloud account was available. This is a documented
  limitation, not a hidden substitution.

## Failure behaviour

- The core ranking, Explorer, Patch Optimizer and Model Laboratory do not depend on a live Granite
  service; all features are cached artefacts.
- If `ranked_2026.parquet` is absent, the API returns 503 rather than fabricated data.
- `granite_analyze` catches a missing similarity artefact and returns an analysis with an empty
  analog list, rather than failing the whole request.
- The local embedding stage batches at 64, uses normalized float32 vectors and caches to parquet/npy.
  There is no retry/rate-limit layer because there is no remote API; adding one would be untested
  decoration.
- `test_granite_analysis_and_chat` exercises analyze and chat against the real app; it asserts
  `generative_model: null`, non-empty analogs and a grounded source.

## Honest limitation

The challenge asked for a Granite instruction model for extraction and a generative analyst
assistant. Only the embedding model is integrated. The product labels that boundary everywhere. If a
watsonx key is supplied, the embedding call can be swapped behind the same feature contract; the
generative assistant would need a separate, grounded prompt and validation layer before it could
replace the deterministic answer path.
