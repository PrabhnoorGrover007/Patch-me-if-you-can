# Frontend feature parity — Patch Me If You Can

Legend: **Full** = implemented and backed by real data; **Partial** = implemented where the data
supports it, with the unavailable part stated in the UI; **Unavailable** = no honest source exists.

| # | Capability | State | What now exists | Data / evidence | Limitation shown |
| --- | --- | --- | --- | --- | --- |
| 1 | Command Center | **Full** | `/` dashboard: universe/cohort counts, held-out hits@500 and ROC-AUC, quick-wins matrix, severity donut, ranked table, per-CVE panel, grounded insight, queue action, links to every deeper page | `GET /api/dashboard`; `ranked_2026.parquet`, `full_rankings.csv`, `vulnerabilities.parquet`, `model_selection.json` | Priority is rank-normalised; model p is not a calibrated probability |
| 2 | Vulnerability Explorer | **Full** | `/explorer`: server-paginated search across all 72,670 rows, severity/EPSS/PoC filters, sort, CVSS/EPSS/model score/vendor/CWE columns, CVE links, official top500 and ranked CSV downloads | `GET /api/vulnerabilities` with pagination and filters; `GET /api/top500`; `GET /api/export` | 25 rows/page; the full table is never shipped to the browser |
| 3 | Vulnerability Intelligence | **Full for available data** | `/intelligence` and `/intelligence/[cve]`: record, why-ranked, CVSS/EPSS/model rank, CNA, CWE, products, technical fields, linear attribution, remediation priority, similar CVEs, timeline and analyst chat | `GET /api/vulnerabilities/{cve}`, `/similar`, `/timeline`; `POST /api/granite/analyze`, `/chat` | No claimed causality from attribution; no invented missing fields |
| 4 | IBM Granite Intelligence | **Full for available data** | Deterministic attack-characteristic extraction with source sentences, Granite embedding analog retrieval, grounded generative answers from local Granite 2B or watsonx.ai, uncertainty list, loading/error states | `ibm-granite/granite-embedding-30m-english` local index; local `granite-3.3-2b-instruct` through llama.cpp; optional watsonx 8B; `granite_analyze`, `granite_chat`, `granite_status` | Local 2B model runs on CPU and is grounded in retrieved evidence; it is not presented as a hosted 8B model |
| 5 | Discovery Lab | **Full** | `/discoveries`: all nine measured findings, headline statistic, n, chart, Wilson intervals, underlying value table, limitations | `GET /api/discoveries` from `discoveries.json` | Correlation, not causation; 2026 outcomes unknown |
| 6 | Patch Optimizer — 20-Patch Challenge | **Full** | `/patch`: budgets 10/20/50/100; four strategies (CVSS, EPSS, exploit→EPSS, model); selected queue, overlap, unique picks; historical held-out evidence | `POST /api/patch-optimizer`; `gap_analysis.json` | Historical validation only; no 2026 answer key and no enterprise-outcome guarantee |
| 7 | Historical Timeline | **Partial** | Per-CVE EPSS and exploit-source monthly path where 2024–2025 signals exist; KEV addition and publication dates; snapshot month | `GET /api/vulnerabilities/{cve}/timeline`; `signals.parquet`, `kev.parquet` | 2026 has one snapshot per CVE; no synthetic monthly path is drawn |
| 8 | Product Exposure Explorer | **Partial** | `/products`: searchable CPE-vendor directory, vendor CVE counts, vendor detail with ranked CVEs, filters through API pagination | `GET /api/products`, `/api/products/{vendor}/vulnerabilities`; `affected_products.csv` | It is the supplied CPE dataset, **not** an organisation's asset inventory; CPE absence is not safety |
| 9 | Model Laboratory | **Full** | `/model`: held-out ranker table, P@50/P@100/AP/ROC-AUC, bootstrap intervals, baseline reproduction, permutation importance, Granite ablation, selection protocol | `GET /api/model/performance`; `model_selection.json`, `backtest_baselines.json`, `granite_ablation.json` | 52 held-out positives is small; calibration not claimed |
| 10 | Export and Reporting | **Full** | `/api/top500` exact submission; `/api/export?limit=500` ranked working CSV; explorer/dashboard download links; upload validator checks the `cve_id` contract | `top500.csv` direct; ranked table; upload inspector | Working export has more columns by design; official submission remains one column |
| + | Remediation queue | **Full** | `/queue`: drag/arrow Kanban, add from dashboard, server persistence, MTTR feed to risk trends | `app/src/lib/queue-store.ts`, server actions | Single-host JSON store; no multi-user auth |
| + | Risk trends | **Full** | `/analytics`: open priority in queue, completion counts, MTTR, cumulative exposure, monthly severity mix | Derived from `/api/dashboard` + queue store | MTTR only exists after cards are completed |
| + | Submission inspector | **Full** | `/upload`: browser-side CSV validation for header, malformed IDs, duplicates, outside-cohort rows; links to CVE detail | Cohort briefs from `/api/dashboard` | File is parsed locally, not uploaded |
| + | Grounded chat | **Full** | `/chat` and slide-over: CVE selection, context injection server-side, suggestions, generated or grounded source badge, error state | `POST /api/granite/chat`; local Granite 2B or watsonx.ai; ranked table, attribution, Granite index | Answers are constrained to retrieved evidence; generation falls back to the deterministic answer if the model is unavailable |

## Deliberately unavailable / not fabricated

- **2026 KEV outcome** — the release ends KEV in 2025; no 2026 hits@500 is displayed.
- **Calibrated probability** — the fitted score is a ranking signal; the UI says so and shows model p
  separately.
- **Hosted 8B Granite without credentials** — watsonx.ai needs an IBM Cloud key and project id.
  Without them the app uses the local 2B Granite model; the extraction panel itself remains
  deterministic and labels that distinction.
- **2026 monthly EPSS path** — the benchmark has one snapshot per CVE; the timeline shows historical
  monthly signals only and says why.
- **Organisation asset inventory** — product exposure uses the supplied CPE-affected-product table
  and states that it is not an asset inventory.
- **Baseline reproduction in 2026** — baselines are historical held-out results, not a claimed 2026
  score.

## Navigation

The teammate tab bar was extended consistently: Dashboard · Explorer · 20-Patch challenge ·
Discoveries · Model lab · Products · Investigation · Risk trends · Remediation · Upload · Chat.
Every route shares the same header, footer, page-header, panel, chip, table and chart styling.
