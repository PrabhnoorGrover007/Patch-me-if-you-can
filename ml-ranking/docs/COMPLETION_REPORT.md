# Completion report

Status of every requirement in the brief, with the evidence that backs each line. Produced at the end
of the build, not reconstructed from memory: every command below was executed in this repository.

## Deliverables

| Requirement | Status | Evidence |
| :-- | :-- | :-- |
| `top500.csv` — one column `cve_id`, 500 unique IDs from the scoreboard | **Done** | `top500.csv`: 501 lines including header, `(500, 1)` shape, unique, subset of `scoreboard_2026.csv`; asserted again by `test_top500_format` |
| Working product | **Done** | FastAPI + React dashboard, 10 endpoints, all 200 over real TCP; `web/dist` built |
| Model | **Done** | `artifacts/model.joblib` (bundle), `models/train.py` selection + refit, `models/predict.py` scoring |
| Code repository | **Done** | git repo initialised, commit `53ba86a`, 64 tracked files, clean tree, heavy artefacts ignored |
| 8 named docs | **Done** | README, METHODOLOGY, DATA_AUDIT, DISCOVERIES, MODEL_EVALUATION, IBM_INTEGRATION, TEST_REPORT, LIMITATIONS — all present, 650–1,150 words each |
| Demo script | **Done** | `docs/DEMO_SCRIPT.md`, timed shot list, cuts, fallback, Q&A prep |
| Devpost draft | **Done** | `docs/DEVPOST.md` |
| One-command startup | **Done** | `start.sh` / `start.bat`; `bash start.sh` exercised and served `/api/health` → 200 |
| Executed tests | **Done** | `pytest -q` → 18 passed; report in `docs/TEST_REPORT.md` |
| Final completion report | **Done** | this file |

## Judging criteria

| Criterion | Where it is addressed |
| :-- | :-- |
| Discovery (35%) | `DISCOVERIES.md` — nine findings, each with n, rate and Wilson 95% interval; the blind-spot result (33 of 52 exploited CVEs missed by every baseline) is the headline |
| Data use (25%) | `DATA_AUDIT.md` and `FEATURE_AUDIT.md` — 401,082 records, 6.46 M signals, every one of the 73 features with source, fill rate and leak assessment; excluded columns justified |
| Communication (25%) | README, dashboard, `DEMO_SCRIPT.md`, `DEVPOST.md`; every performance claim carries an interval and a plain statement of what it does not prove |
| Impact (15%) | The product answers "what do we fix first, and why", with per-CVE evidence a patch decision can cite |
| IBM technology (mandatory) | IBM Granite embeddings, run locally; measured ablation 17 → 20 hits@500; `IBM_INTEGRATION.md` |

## Integrity requirements

| Rule | Status |
| :-- | :-- |
| No `nvd_status`, `n_affected_cpes`, `n_references`, blank-severity signal, CWE missingness, reference links/tags | Excluded; severity is median-imputed and
all CWE-derived columns were dropped after review; `FEATURE_AUDIT.md` lists them with reasons, `test_kev_never_used_as_feature` guards the KEV columns |
| No random splits | Month-grouped `GroupKFold`; held-out is a nine-month block |
| No 2026 leakage | 2026 rows appear only in `models/predict.py`; nothing is fitted on them |
| No fabricated results | Every number in every doc comes from a JSON artefact in `artifacts/`; baselines are reproduced by our own code, not quoted |
| Baselines beaten | Held-out hits@500: 20 vs 18 (exploit-first), 8 (EPSS), 5 (CVSS); P@50 0.22 vs 0.08; AP 0.110 vs 0.047 |

## Verification actually run

| Command | Result |
| :-- | :-- |
| `.venv/Scripts/python.exe -m pytest -q` | 18 passed |
| `python -m models.train` / `models.predict` | exit 0, artefacts + `top500.csv` written |
| `python -m eval.gap` | exit 0, 20 hits, 5 of 33 blind-spot recoveries |
| `python -m eval.granite_ablation` | exit 0, Granite on/off table |
| `python -m pipeline.discoveries` | exit 0, 9 findings |
| HTTP smoke test, live uvicorn | 10 endpoints, all 200 |
| `bash start.sh` | served `/api/health` 200 on the documented port |
| `bash -n start.sh` | syntax OK |
| `cd web && npm run build` | exit 0, TypeScript clean |
| Markdown link check across README + docs | 0 broken relative links |

## Known gaps

1. **No 2026 answer key exists in the release** (KEV ends 2025-12-29), so the official score cannot be
   computed or claimed. All performance numbers are historical validation on 2024–2025 and are labelled
   as such throughout.
2. **No browser automation was possible** (no Chrome binary in this environment). The dashboard is
   verified by TypeScript build and by HTTP responses from the served bundle; nobody has clicked
   through it in a real browser. Do one manual pass before recording.
3. **Demo video not recorded** — the brief asked for a demo script, which is delivered; recording needs
   a human and screen capture.
4. **watsonx.ai not used** — no IBM Cloud account was available. Granite runs locally from public
   weights, an explicitly permitted route; the swap path is documented in `IBM_INTEGRATION.md`.
5. **Small held-out positive count** (52), so the 20-vs-18 lead has overlapping bootstrap intervals.
   The defensible claims are precision at 50 and average precision, both ~2.5× the baseline.

## Reproduce from scratch

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/pip install -r requirements-granite.txt
python run_all.py            # ~30 min incl. the 23-minute embedding stage
.venv/Scripts/python.exe -m pytest -q
bash start.sh
```
