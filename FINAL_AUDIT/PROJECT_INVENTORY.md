# Project inventory

Audited 2026-11-08. The product name is **PATCH ME IF YOU CAN**; the only surviving "Before the
Breach" references correctly name the official IBM track.

## Shape

| Area | Count / location | Notes |
| :-- | :-- | :-- |
| Python source | `pipeline/`, `models/`, `eval/`, `api/`, `tests/` | 30 front/back source files in the audited tree |
| API routes | 18 under `/api` | listed in `BACKEND_AUDIT.md` |
| Frontend pages | 9 | Command Center, Explorer, investigation, Patch Optimizer, Granite Intelligence, Discovery Lab, Model Laboratory, Product Exposure, Workflow |
| Frontend build | `web/dist` | 438 modules, 732.26 kB JS / 11.49 kB CSS, Vite 7.3.7 |
| Docs | 12 Markdown files in `docs/` | all required submission docs present |
| Data | `data/` and `data.zip` | supplied raw files; `.gitignore` excludes them, never modified |
| Artefacts | `artifacts/` | parquet/CSV/JSON; large binaries ignored, small evidence files retained |
| Tests | `tests/test_pipeline.py`, `tests/test_api.py` | 22 tests |
| Startup | `start.sh`, `start.bat`, `run_all.py` | one command, single uvicorn process serving API + UI |

## Findings resolved in this audit

- **Stale working title** was still present in a few docs and the UI copy. Replaced with PATCH ME IF
  YOU CAN; official track references retained.
- **Dashboard said "nine" snapshot months**; the scoreboard has eight distinct `snapshot_month` values
  (June folds into July). Corrected.
- **`shap` was declared but unused**; removed from `requirements.txt`.
- **Granite feature table held 14 rows** that the corrected cohort no longer uses. Filtered to 87,907
  train + 72,670 predict rows; `granite_meta.json` updated.
- **`pipeline/audit.py` wrote Markdown with the Windows default encoding**, producing replacement
  characters for em dashes. Both the JSON and Markdown writes now use UTF-8 and the document was
  regenerated.
- **Stale listener on port 8000** was found during the first startup test. It was an old server from a
  previous development run, not a defect in `start.sh`; it was terminated and the current process was
  re-tested. The final startup log shows the current server binding and serving 21/21 checks.

## Files deliberately retained

- `artifacts/full_rankings.csv`, `ranked_2026.csv`, `submission_summary.json` — reproducibility and
  the judge-facing evidence trail.
- `data.zip` — supplied challenge input; excluded from git but kept locally so a clean rerun is
  possible.
- `web/dist` — built output, ignored by git but present for the one-command demo.
- `docs/OFFICIAL_CHALLENGE.md` — the original track statement, not product copy.

## Duplicate / dead material

No duplicate API route or unused page was found. `Workflow` is a static explanatory page and is linked
from navigation; it does not claim live data. No placeholder component remains. The unused dependency
and the 14 retired Granite rows were the only material removals.
