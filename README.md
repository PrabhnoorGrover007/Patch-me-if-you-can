# Patch Me If You Can

Sheridan Datathon 2026 · IBM track. Rank the 2026 vulnerability scoreboard by the chance an attacker
actually exploits it, then show engineers what to fix first.

| Path | What it is |
| --- | --- |
| `prepare_data.py`, `model.py`, `validate_outputs.py` | The ML pipeline (raw CSVs → features → ranking → `outputs/top500.csv`) |
| `src/` | Pipeline helpers: data audit, feature building, exploration |
| `tests/` | Pipeline unit tests (no data needed) |
| `outputs/` | `top500.csv` submission and the validation report |
| `IBM_dataset/` | Raw challenge data (~850 MB, not committed) |
| `app/` | The web application: dashboard, analytics, remediation board, CSV inspector, Granite chat |
| `docs/` | Pipeline documentation and the data dictionary |

Pipeline: see `docs/PIPELINE.md`. App: see `app/README.md` (`cd app && npm install && npm run dev`).
