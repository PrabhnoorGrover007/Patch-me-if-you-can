# Test report

Executed in this repository on 2026-11-08 (Windows, Python 3.13.7, pytest 9.2.0, Node 22).
Commands are reproducible from the project root. Nothing below is inferred from a previous run; the
counts are from the final post-correction artefacts.

## Summary

| Command | Result |
| :-- | :-- |
| `.venv/Scripts/python.exe -m pytest -q` | **22 passed** |
| `python -m models.train` | exit 0, wrote `model.joblib`, `model_selection.json`, `attribution.json` |
| `python -m models.predict` | exit 0, wrote `top500.csv` (500 ids), `ranked_2026.parquet` (72,670 rows) |
| `python -m eval.backtest` | exit 0, baselines reproduced |
| `python -m eval.gap` | exit 0, blind-spot analysis written |
| `python -m eval.granite_ablation` | exit 0, Granite on/off table written |
| `python -m pipeline.discoveries` | exit 0, 9 discoveries with Wilson intervals |
| `bash -n start.sh` / `start.bat` review | syntax OK; startup exercised |
| HTTP smoke test | every exercised endpoint 200; invalid input 422; missing records 404 |
| `npm run build` (web) | exit 0, TypeScript clean, Vite bundle written |

## Pipeline tests (`tests/test_pipeline.py`, 11)

| Test | What it proves |
| :-- | :-- |
| `test_source_files_present` | all eight raw CSVs exist with the documented names |
| `test_scoreboard_size_and_filter` | the benchmark parquet has 72,670 rows, unique ids, publication dates inside 2026-01-01…2026-09-30 and correct month-end snapshots |
| `test_kev_never_used_as_feature` | no KEV, NVD-review, CPE-count or reference-count column reaches the model table |
| `test_labels_only_count_future_additions` | positives are only KEV additions strictly after each row's snapshot month end, and no already-exploited CVE remains in the candidate cohort |
| `test_top500_matches_model_order` | `top500.csv` is exactly the first 500 rows of the ranked table, in the same order |
| `test_train_predict_feature_parity` | train and predict expose the same feature names and dtypes |
| `test_granite_features_are_asof` | Granite similarity columns exist, are finite, and stay within cosine range |
| `test_top500_format` | one column named `cve_id`, exactly 500 unique ids, all inside `scoreboard_2026.csv` |
| `test_ranked_table_integrity` | 72,670 unique rows, unique ranks 1…N, finite risk scores in [0, 1] |
| `test_model_is_deterministic_and_loadable` | both models load from the bundle and produce identical probabilities on repeated calls |
| `test_discoveries_have_intervals` | every discovery carries a sample size; at least six carry confidence intervals |

## API tests (`tests/test_api.py`, 11)

| Test | What it proves |
| :-- | :-- |
| `test_health` | `/api/health` reports the product name, `ok`/`degraded`, 72,670 rows and Granite availability |
| `test_overview_shape` | headline model and baseline numbers are served from artefacts, not hard-coded in the frontend |
| `test_vulnerabilities_pagination_and_filters` | paging, sorting and severity/EPSS filters return consistent counts |
| `test_invalid_query_parameters_rejected` | page 0, oversized pages and unknown sorts return 422 |
| `test_vulnerability_detail_and_missing_id` | detail carries description, remediation priority and technical fields; unknown ids return 404 |
| `test_model_performance_and_discoveries` | performance JSON exposes the held-out rows and selection table; discoveries are served |
| `test_explanations_fallback_is_grounded` | with no generated explanations file, the endpoint returns a deterministic explanation and labels its source |
| `test_export_and_top500` | `/api/export` returns CSV of the requested length; `/api/top500` returns exactly 500 ids |
| `test_similar_timeline_and_products` | similarity excludes the query CVE and stays in cosine range; timeline returns the CVE; product pagination works |
| `test_patch_optimizer` | all four strategies return exactly the requested budget and an overlap matrix |
| `test_granite_analysis_and_chat` | analysis labels `generative_model: null`, returns grounded extraction and analogs; chat is retrieval-grounded and cites the CVE |

## HTTP smoke test

A real uvicorn process was started on a free port and queried over TCP after the corrected rebuild:

```
200  /api/health                  rows=72670, granite=true
200  /api/overview                analyzed=72670, severity_mix, risk_distribution
200  /api/vulnerabilities         total=72670, pagination
200  /api/vulnerabilities/{id}    detail + contributions + technical evidence
200  /api/vulnerabilities/{id}/similar      Granite nearest neighbours
200  /api/vulnerabilities/{id}/timeline     monthly EPSS / exploit / KEV points
200  /api/products                vendor aggregate
200  /api/products/{vendor}/vulnerabilities
200  /api/patch-optimizer         four 20-item queues + overlap
200  /api/granite/analyze         deterministic DNA + Granite analogs
200  /api/granite/chat            grounded answer, generative_model=null
200  /api/model/performance       held-out rows + selection + permutation importance
200  /api/discoveries             9 findings
200  /api/rankings                ranked slice
200  /api/export                  CSV
200  /api/top500                  CSV, 500 unique ids
200  /                           built dashboard
200  /docs                       OpenAPI UI
422  /api/vulnerabilities?page=0
404  /api/vulnerabilities/CVE-1999-9999
404  /api/products/not-a-real-vendor/vulnerabilities
```

The earlier smoke run reported `/api/top500` as a parse failure because the harness expected JSON from
an endpoint that serves CSV by design. The endpoint was correct; the harness was fixed and re-run.

## What these tests do not prove

- **They do not prove the 2026 ranking is good.** No 2026 answer key exists in the release (KEV ends
  2025-12-29), so no test can assert 2026 accuracy. Only judges can score the submission.
- **They do not prove generalisation.** Held-out performance is measured in `MODEL_EVALUATION.md` with
  bootstrap intervals; the unit tests check mechanics, not predictive quality.
- **They do not check rendering.** No Chrome binary was available. The dashboard is verified by a
  successful TypeScript build, Vite output and HTTP responses from the served bundle. Nobody clicked
  through every control in a real browser; that remains a manual pre-recording step.
- **They do not benchmark latency.** The API answers in well under a second on this machine for the
  endpoints exercised, but no load or concurrency test was run.

## Reproduction notes

- The Granite stage takes ~23 minutes on CPU. `test_granite_features_are_asof` skips cleanly if the
  artefact is absent, so the suite is runnable before the embedding step.
- All artefact-dependent tests read from `artifacts/`. Run `python run_all.py` (or the individual
  stages) before the suite on a clean checkout.
- Frontend verification is `npm ci && npm run build`; there is no separate frontend unit-test harness
  in this submission.
