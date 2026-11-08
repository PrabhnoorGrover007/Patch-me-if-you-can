# Completion report

Final audit state, 2026-11-08. This supersedes the build-phase report. Every command cited here was
executed against the current tree; the detailed evidence is in [`../FINAL_AUDIT/`](../FINAL_AUDIT/).

## Deliverables

| Requirement | Status | Evidence |
| :-- | :-- | :-- |
| `top500.csv` — one column `cve_id`, 500 unique ids from the scoreboard | **Done** | `(500, 1)`, unique, subset of `scoreboard_2026.csv`, order identical to the ranked table; `test_top500_format` and `test_top500_matches_model_order` |
| Working product | **Done** | FastAPI + React dashboard; all major endpoints 200 over real TCP; `web/dist` built |
| Model | **Done** | `artifacts/model.joblib`; selection + refit in `models/train.py`; inference in `models/predict.py` |
| Code repository | **Done** | working tree contains the audit changes; no commit/push was requested or made during the audit |
| 8 named docs | **Done** | README, METHODOLOGY, DATA_AUDIT, DISCOVERIES, MODEL_EVALUATION, IBM_INTEGRATION, TEST_REPORT, LIMITATIONS |
| Demo script | **Done** | `docs/DEMO_SCRIPT.md`, 2:50 shot list, cuts, fallback and Q&A |
| Devpost draft | **Done** | `docs/DEVPOST.md` |
| One-command startup | **Done** | `start.sh` / `start.bat`; health checked through the served process |
| Executed tests | **Done** | `pytest -q` → **22 passed**; report in `docs/TEST_REPORT.md` |
| Final audit evidence | **Done** | `FINAL_AUDIT/` inventory, traceability, data/ML, top500, Granite, backend, frontend, journeys, security, performance, cleanup, tests, judge perspective |

## Judging criteria

| Criterion | Where it is addressed |
| :-- | :-- |
| Discovery (35%) | `DISCOVERIES.md` — nine findings, each with n, rate and Wilson 95% interval; the blind-spot result (33 of 52 exploited CVEs missed by every baseline) is the headline |
| Data use (25%) | `DATA_AUDIT.md` + `FEATURE_AUDIT.md` — 401,082 records, 6.46 M signals, every feature with source, fill rate and leak assessment; excluded columns justified |
| Communication (25%) | README, dashboard, `DEMO_SCRIPT.md`, `DEVPOST.md`; performance claims carry intervals and a plain statement of what they do not prove |
| Impact (15%) | The product answers "what do we fix first, and why", with per-CVE evidence a patch decision can cite |
| IBM technology (mandatory) | IBM Granite embeddings run locally; controlled ablation 16 → 20 hits@500 for the both-Granite blend, shipped mixed blend 22; `IBM_INTEGRATION.md` |

## Integrity requirements

| Rule | Status |
| :-- | :-- |
| No `nvd_status`, `n_affected_cpes`, `n_references`, blank-severity signal, CWE missingness, reference links/tags | Excluded; severity is median-imputed and all CWE-derived columns were dropped after review; `FEATURE_AUDIT.md` lists them with reasons, `test_kev_never_used_as_feature` guards the KEV columns |
| No random splits | Month-grouped `GroupKFold`; held-out is a nine-month block |
| No 2026 leakage | 2026 rows appear only in `models/predict.py`; nothing is fitted on them |
| No fabricated results | Every number in every doc comes from a JSON artefact in `artifacts/`; baselines are reproduced by our own code, not quoted |
| Baselines beaten | Held-out hits@500: **22 vs 18** (exploit-first), 8 (EPSS), 5 (CVSS); P@50 **0.24 vs 0.08**; AP **0.119 vs 0.047** |
| Cohort correction | 14 already-on-KEV rows removed; training table 87,907 / 122 positives; asserted by `test_labels_only_count_future_additions` |

## Verification actually run

| Command | Result |
| :-- | :-- |
| `.venv/Scripts/python.exe -m pytest -q` | **22 passed** |
| `python -m models.train` / `models.predict` | exit 0, artefacts + `top500.csv` written |
| `python -m eval.gap` | exit 0, 22 hits, 7 of 33 blind-spot recoveries |
| `python -m eval.granite_ablation` | exit 0, Granite on/off table |
| `python -m pipeline.discoveries` | exit 0, 9 findings |
| HTTP smoke test, live uvicorn | all exercised endpoints 200; 422/404 cases correct |
| `bash start.sh` | served `/api/health` 200 on the documented port |
| `bash -n start.sh` | syntax OK |
| `cd web && npm run build` | exit 0, TypeScript clean |
| `top500.csv` independent checks | 500 unique, one column, subset, ordered; md5 `4677d079b77a6262a70e265cb3136d4e` |

## Known gaps

1. **No 2026 answer key exists in the release** (KEV ends 2025-12-29), so the official score cannot be
   computed or claimed. All performance numbers are historical validation on 2024–2025 and are labelled
   as such throughout.
2. **No browser automation was possible** (no Chrome binary). The dashboard is verified by TypeScript
   build and HTTP responses from the served bundle; a human click-through is still required before
   recording.
3. **Demo video not recorded** — the script is delivered; recording needs a human and screen capture.
4. **watsonx.ai not used** — no IBM Cloud account was available. Granite runs locally from public
   weights, an explicitly permitted route; the swap path is documented in `IBM_INTEGRATION.md`.
5. **No Granite instruct model** — extraction and analyst answers are deterministic/retrieval-grounded,
   labelled as such in the UI and API. This is a limitation, not a hidden substitution.
6. **Small held-out positive count** (52), so the 22-vs-18 lead has overlapping bootstrap intervals.
   The defensible claims are precision at 50 and average precision, both materially above the baseline.
7. **Residual review-status tilt** — 0.2% blank severity, 0.4% blank CWE, 56.2% NIST-Analyzed in the
   top 500. Reduced from 62.4%, not eliminated.

## Reproduce from scratch

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/pip install -r requirements-granite.txt
python run_all.py            # ~30 min incl. the 23-minute embedding stage
.venv/Scripts/python.exe -m pytest -q
bash start.sh
```
