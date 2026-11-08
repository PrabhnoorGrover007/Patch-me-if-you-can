# Cleanup report

## Removed or corrected

- Removed unused `shap==0.49.1` from `requirements.txt`. It was not imported anywhere.
- Filtered `artifacts/granite_features.parquet` from 160,591 to **160,577** rows, dropping the 14
  records excluded by the corrected candidate cohort. `granite_meta.json` now records
  `train_rows: 87907`, `predict_rows: 72670`, and the updated mean similarity.
- Regenerated `docs/FEATURE_AUDIT.md` and `artifacts/feature_audit.json` with UTF-8 output; the old
  file contained replacement characters for em dashes.
- Corrected "nine 2026 snapshot months" to eight in the sidebar.
- Removed stale working-title and metric text from README and submission docs.
- Removed no working feature. No raw data file was touched.

## Repository state

- Working tree is intentionally dirty: the audit did not commit or push. `git status --short` shows
  the source/doc/artefact changes and three new frontend pages.
- `data/` and `data.zip` are present locally but ignored; the submission does not redistribute raw
  challenge data.
- `.venv`, `web/node_modules`, `web/dist`, `.pytest_cache`, and large binary artefacts are ignored.
- `requirements.txt` is pinned; `web/package-lock.json` is present.
- No `.env` file is tracked. No API key or password appears in the tree.

## Validation of the clean state

- `pytest -q` → 22 passed after cleanup.
- `npm run build` → exit 0 after the UI copy change.
- `bash -n start.sh` → exit 0.
- Live `start.sh` → health 200 and 21/21 endpoint checks after killing the unrelated stale listener.

## Remaining generated files

`artifacts/full_rankings.csv`, `ranked_2026.csv`, `submission_summary.json` and the small JSON tables
are retained because they are evidence and are used by the API. They are not duplicates of the raw
data and are intentionally part of the reproducibility trail.
