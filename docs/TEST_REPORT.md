# Test report

Everything below was executed in this repository on 2026-11-07 (Windows, Python 3.13.7, pytest 9.2.0).
Commands are reproducible from the project root; no test is skipped or xfailed in the shipped state.

## Summary

| Command | Result |
| :-- | :-- |
| `.venv/Scripts/python.exe -m pytest -q` | **18 passed in 3.46 s** |
| `python -m models.train` | exit 0, wrote `model.joblib`, `model_selection.json`, `attribution.json` |
| `python -m models.predict` | exit 0, wrote `top500.csv` (500 ids), `ranked_2026.parquet` (72,670 rows) |
| `python -m eval.backtest` | exit 0, baselines reproduced |
| `python -m eval.gap` | exit 0, blind-spot analysis written |
| `python -m eval.granite_ablation` | exit 0, Granite on/off table written |
| `python -m pipeline.discoveries` | exit 0, 9 discoveries with Wilson intervals |
| HTTP smoke test (12 endpoints) | all 200 |
| `bash -n start.sh` | syntax OK |
| `npm run build` (web) | exit 0, TypeScript clean |

## Pipeline tests (`tests/test_pipeline.py`, 10)

| Test | What it proves |
| :-- | :-- |
| `test_source_files_present` | all five raw CSVs exist with the documented names |
| `test_scoreboard_size_and_filter` | the benchmark parquet has 72,670 rows across 8 snapshot months, and every row is unique |
| `test_kev_never_used_as_feature` | no KEV column appears in the 114-feature matrix — the label cannot leak in through a column |
| `test_labels_only_count_future_additions` | positives are only KEV additions strictly after each row's snapshot month end; the 62 pre-publication KEV records are excluded |
| `test_train_predict_feature_parity` | train and predict matrices expose the same feature set, so the model cannot silently drop a column at scoring time |
| `test_granite_features_are_asof` | Granite similarity columns exist for both splits, are finite, and stay within cosine range (float32 drift ≤ 0.02 tolerated) |
| `test_top500_format` | `top500.csv` has one column named `cve_id`, exactly 500 rows, 500 unique ids, all inside `scoreboard_2026.csv` |
| `test_ranked_table_integrity` | the ranked table has 72,670 rows, unique `cve_id` and `rank`, ranks 1…N, and every `risk_score` is finite in [0, 1] |
| `test_model_is_deterministic_and_loadable` | both models load from the bundle and produce identical probabilities on two consecutive calls |
| `test_discoveries_have_intervals` | every discovery carries a sample size and a confidence interval |

## API tests (`tests/test_api.py`, 8)

| Test | What it proves |
| :-- | :-- |
| `test_health` | `/api/health` reports `ok` with 72,670 rows and Granite availability |
| `test_overview_shape` | headline model and baseline numbers are served, not hard-coded in the frontend |
| `test_vulnerabilities_pagination_and_filters` | paging, sorting and severity/vendor/EPSS filters return consistent counts |
| `test_invalid_query_parameters_rejected` | bad paging and sort values return 422 instead of silently degrading |
| `test_vulnerability_detail_and_missing_id` | detail payload carries contributions and evidence; unknown ids return 404 |
| `test_model_performance_and_discoveries` | performance JSON exposes the held-out rows and selection table |
| `test_explanations_fallback_is_grounded` | with no generated explanations file, the endpoint returns a deterministic explanation and labels its source |
| `test_export_and_top500` | `/api/export` returns CSV of the requested length and `/api/top500` returns exactly 500 ids |

## HTTP smoke test

A real uvicorn process was started on a free port and queried over TCP:

```
200  health                       {'status': 'ok', 'rows': 72670, 'columns': 14, 'granite': True}
200  top500                       500 ids, header='cve_id', unique=500
200  export                       500 rows
200  rankings                     10 items
200  vulnerabilities              total=72670
200  model/performance            heldout rows=6
200  discoveries                  9 items
200  overview                     ['analyzed', 'discoveries', 'epss_coverage', 'exploit_code_share']
200  cve/CVE-2025-40554           ['contributions', 'cve_id', 'cvss3_score', 'cvss3_severity', 'cwe_name', 'cwe_top']
200  explanation/CVE-2025-40554   deterministic
200  frontend /                   len=571 has_root=True
200  swagger /docs                1016
```

The first smoke run reported `/api/top500` as a parse failure — that was the test harness assuming
JSON from an endpoint that serves CSV by design. The endpoint was already correct; the harness was
fixed and re-run, and the table above is the re-run.

## What these tests do not prove

- **They do not prove the 2026 ranking is good.** No 2026 answer key exists in the release, so no test
  can assert 2026 accuracy. Only judges can score the submission.
- **They do not prove generalisation.** Held-out performance is measured in `MODEL_EVALUATION.md` with
  bootstrap intervals; the unit tests check mechanics, not predictive quality.
- **They do not check rendering.** No browser was available in this environment, so the dashboard is
  verified by a successful TypeScript build and by HTTP responses from the served bundle. Nobody has
  clicked through it in a real browser.
- **They do not benchmark latency.** The API answers in well under a second on this machine for the
  endpoints exercised, but no load or concurrency test was run.

## Reproduction notes

- The Granite stage takes ~23 minutes on CPU; tests that depend on its output skip cleanly if the
  artefact is absent, so the suite is runnable on a fresh clone before the embedding step.
- All artefact-dependent tests read from `artifacts/`; run the pipeline before the suite on a clean
  checkout, otherwise those tests skip rather than fail.
