# PATCH ME IF YOU CAN — exploit-aware vulnerability prioritisation

IBM **Before the Breach** track, Sheridan Datathon 2026.

Security teams cannot patch everything. In our corpus **fewer than 1 in 250 published
vulnerabilities is ever confirmed exploited**, yet severity scores remain the default sort order.
This project ranks 72,670 candidate CVEs from the 2026 benchmark so that the ones attackers actually
use land at the top, and explains each ranking in language an engineer can act on.

**Result:** on a held-out nine-month pool that mirrors the benchmark, the model puts **22 of 52**
later-exploited CVEs in its top 500. The best publication-style baseline (public exploit code, then
EPSS) puts 18 there. It also recovers **7 of the 33** exploited CVEs that *no* baseline ranks in its
top 500.

Submission: [`top500.csv`](top500.csv) — 500 unique `cve_id` values, one column, all drawn from
`scoreboard_2026.csv`.

---

## Quickstart

One command, from this directory:

```bash
bash start.sh          # macOS / Linux / Git Bash
start.bat              # Windows cmd / PowerShell
```

It checks that the model artefacts exist, builds the dashboard if `web/dist` is missing, then serves
the API and UI from one process at <http://127.0.0.1:8000>. If artefacts are missing it tells you to
run the pipeline first: `python run_all.py` reproduces every artefact from the raw CSVs (add
`--skip-granite` to skip the ~23-minute embedding stage).

Manual equivalent:

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # or .venv/bin/pip on unix
python -m pipeline.prepare_data     # raw CSVs  -> parquet artefacts
python -m pipeline.features         # cohorts   -> 73 features, as-of monthly priors
python -m models.train              # selection -> artifacts/model.joblib
python -m models.predict            # score 2026 -> top500.csv
python -m uvicorn api.main:app --port 8000
```

Stages run as modules (`-m`) because they import one another: the script form fails with
`ModuleNotFoundError: No module named 'eval'`, the `-m` form works.

The Granite embedding stage is optional for the API but required to reproduce the shipped model:

```bash
pip install -r requirements-granite.txt
python -m models.granite_embed      # ~23 min on CPU, no account or API key needed
```

## What you get

- **`top500.csv`** — the deliverable.
- **Dashboard** (`/`) — overview, searchable ranked table, per-CVE evidence panel, model performance
  page, discovery cards, and a walkthrough of the monitoring workflow.
- **REST API** (`/docs`) — every page is a thin client of it: `/api/vulnerabilities`,
  `/api/vulnerabilities/{cve}`, `/api/rankings`, `/api/top500`, `/api/export`,
  `/api/model/performance`, `/api/discoveries`, `/api/explanations/{cve}`, `/api/overview`,
  `/api/vulnerabilities/{cve}/similar`, `/api/vulnerabilities/{cve}/timeline`, `/api/products`,
  `/api/patch-optimizer`, `/api/granite/analyze`, `/api/granite/chat` and `/api/granite/status`.
- **Artefacts** — `artifacts/ranked_2026.parquet` (all 72,670 rows with score, rank and reasons),
  `full_rankings.csv`, `submission_summary.json`, plus every evaluation table quoted below.

## Results

Held-out **Jan-Sep 2025**, 35,280 candidates, 52 positives; every ranker trained on 2024 only.

| Ranker | hits@500 | P@50 | AP | ROC-AUC |
| :-- | --: | --: | --: | --: |
| CVSS 3.1 descending | 5 | 0.06 | 0.006 | 0.732 |
| EPSS descending | 8 | 0.06 | 0.031 | 0.707 |
| Exploit-first, then EPSS | 18 | 0.08 | 0.047 | 0.768 |
| **This model** | **22** | **0.24** | **0.119** | **0.848** |

Bootstrap 95% interval on our hits@500 is 13-31, so the four-hit lead over the baseline is a direction,
not a guaranteed margin. What is more solid: precision at 50 is 3.0x the baseline and the full ordering
(AP) is 2.5x better, which means the top of the list is genuinely better, not just longer.

These numbers differ from the first version of this writeup, which claimed 24/500. An independent
review found the model was exploiting NIST-review metadata: blank severity and blank CWE are recorded
only for vulnerabilities NIST has not analysed yet, and NIST analyses attacked CVEs first. Those
features are gone, the selection folds are corrected, and a follow-up audit removed 14 already-KEV
rows that a missing monthly signal row had quietly admitted. The current held-out result is 22; the
earlier 24 was not a clean comparison because the candidate population contained those rows. The
correction, its evidence and the residual tilt are documented in
[`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md).

We also tested four extra features adapted from a second, independently written implementation, and
rejected them. That gate was run on the earlier 112-feature matrix and has not been re-run on the
corrected matrix, so those figures are historical; the decision to keep the features out stands.

Profile of the shipped top 500 versus the whole pool: mean EPSS 0.0233 vs 0.0027 (8.7x), public exploit
code in 69.2% of rows, mean CVSS 9.13 vs 7.05. The top 500 is 0.2% blank-severity and 0.4% blank-CWE,
against 8.7% and 6.8% in the pool; the residual review-status tilt is 56.2% NIST-Analyzed, down from
62.4% before the cohort fix.

## How it works

1. **Data** — 401,082 vulnerability records, 324,005 affected products, 6.46 M monitoring signals,
   1,484 KEV entries, 72,670 benchmark rows across eight snapshot months.
2. **Label** — a CVE is positive if KEV added it *strictly after* its snapshot month ended. Nobody
   can see the future in this label, by construction.
3. **Features (73)** — severity and vector components (missing values imputed, never flagged), EPSS level and rank, exploit-code availability
   (PoC, Nuclei, Metasploit), description keyword families,
   age, vendor KEV history as-of the snapshot month, and IBM Granite embedding
   similarity to previously exploited CVEs.
4. **Model** — gradient boosting plus a Granite-augmented L2 logistic model, blended 0.2/0.8 on rank-averaged scores. The selected pair is `histgb_lean + logit_core_g`.
5. **Validation** — GroupKFold by month on 2024 for all choices, 2025 held out for confirmation, final
   refit on 2024–2025, 2026 never touched. Details in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

Leakage controls that mattered: `nvd_status`, `n_affected_cpes`, `n_references`, CWE missingness and reference
links/tags are excluded (they encode whether NVD was paying attention, which is itself a KEV
precursor); CPE product strings are excluded for the same reason (49.6% blank in 2026); every prior
is computed as-of the row's own month; splits are never random.

## IBM technology

`ibm-granite/granite-embedding-30m-english` runs locally on CPU and turns each description into a
384-dimensional vector. Cosine similarity to KEV entries that were already listed at snapshot time is
a model feature, and similarity lookup powers the dashboard.

Measured, not asserted: in the controlled ablation, the no-Granite blend reaches 16 held-out hits@500
and P@50 0.22, while the both-Granite blend reaches 20. The shipped mixed blend reaches 22 and P@50
0.24. Text similarity alone reaches ROC-AUC 0.742 for a future KEV addition. The permutation importance
is dominated by EPSS × exploit code, so Granite is a real but secondary contributor. Full ablation in
[`docs/IBM_INTEGRATION.md`](docs/IBM_INTEGRATION.md).

## Repository layout

```
data/                 raw CSVs (not committed)
pipeline/             prepare_data, features, discoveries, audit
models/               train, predict, granite_embed
eval/                 backtest (baselines), gap (blind spot), granite_ablation
api/                  FastAPI service + static mount for the built dashboard
web/                  Vite + React + TypeScript + Recharts dashboard
tests/                pytest suite (pipeline invariants, API contract, submission format)
artifacts/            generated tables, model bundle, ranked output
docs/                 methodology, audit, discoveries, evaluation, IBM, limitations, test report
```

## Tests

```bash
.venv/Scripts/python.exe -m pytest -q      # 22 passed
```

Covers label construction (no future leakage), feature as-of integrity, the Granite temporal
reference set, submission format (500 unique ids, all in the scoreboard, one column), ranked-table
integrity, model determinism, discovery confidence intervals, and the API contract.
See [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md).

## Verify it yourself

```bash
.venv/Scripts/python.exe -m pytest -q        # 22 passed: label, as-of integrity, submission format, API, new product surfaces
bash start.sh                                # API + dashboard on http://127.0.0.1:8000
curl -s http://127.0.0.1:8000/api/health     # {"status":"ok","rows":72670,"granite":true}
```

`top500.csv` is the file that gets scored. Its invariants are executable: 500 unique ids, one column,
every id present in `scoreboard_2026.csv`. The submitted file's md5 is
`4677d079b77a6262a70e265cb3136d4e`, reproducible with `python -m models.predict`.

## Honest limitations

- The 2026 answer key does not exist in the release — KEV entries end 2025-12-29 — so **our 2026
  score is unknown** until judges run it. All numbers above are historical validation.
- 52 positives is a small held-out pool; bootstrap intervals are wide and we report them everywhere.
- KEV is US-centric and lagging; a CVE exploited only in the wild without CISA confirmation is
  invisible to this model.
- The dashboard is verified by build and HTTP responses, not by browser automation (no browser was
  available in this environment).

Full list in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Docs

| Document | Contents |
| :-- | :-- |
| [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) | data, label, features, model, validation protocol |
| [`docs/DATA_AUDIT.md`](docs/DATA_AUDIT.md) | corpus shape, coverage, anomalies, leakage exclusions |
| [`docs/FEATURE_AUDIT.md`](docs/FEATURE_AUDIT.md) | all 73 features, source, fill rate, leak status |
| [`docs/DISCOVERIES.md`](docs/DISCOVERIES.md) | nine findings with confidence intervals |
| [`docs/MODEL_EVALUATION.md`](docs/MODEL_EVALUATION.md) | selection table, held-out results, blind spot |
| [`docs/IBM_INTEGRATION.md`](docs/IBM_INTEGRATION.md) | Granite usage and measured contribution |
| [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md) | what was executed and what it proves |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | threats to validity |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | timed 3-minute demo shot list, cuts and Q&A prep |
| [`docs/COMPLETION_REPORT.md`](docs/COMPLETION_REPORT.md) | requirement-by-requirement status with evidence and known gaps |
| [`FINAL_AUDIT/`](FINAL_AUDIT/) | independent audit evidence: inventory, traceability, data/ML, top500, Granite, backend, frontend, security, performance |
| [`docs/OFFICIAL_CHALLENGE.md`](docs/OFFICIAL_CHALLENGE.md) | the problem statement as issued |

## Team

Built by the Sheridan Datathon 2026 IBM team. Member 2 owns the ML and ranking layer: label design,
feature engineering, model selection, validation, evaluation and the scoring pipeline.

_Implementation developed with Codebuff, an AI coding agent._
