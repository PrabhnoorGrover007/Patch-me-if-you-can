# Requirements traceability

Status values: **Met**, **Partial**, **Not verifiable here**. A page existing is not evidence; the
second column names the code path or artefact that was actually exercised.

| Requirement | Implementation | Evidence | Result |
| :-- | :-- | :-- | :-- |
| Use the official 2026 benchmark | `pipeline/prepare_data.py`, `scoreboard.parquet` | 72,670 rows, unique ids, publication dates 2026-01-01…2026-09-30; `test_scoreboard_size_and_filter` | Met |
| `top500.csv`: one column, 500 unique benchmark ids | `models/predict.py`, `top500.csv` | 501 lines, one header, 500 unique, subset, same order as ranked table; md5 `4677d079b77a6262a70e265cb3136d4e` | Met |
| Correct future-KEV target | `pipeline/features.py` `build_train` | `days_to_kev > 0` for positives; no already-KEV row remains; 87,907 rows / 122 positives; `test_labels_only_count_future_additions` | Met |
| Snapshot-time features | `pipeline/features.py`, `models/granite_embed.py` | monthly joins, as-of vendor priors, nested KEV reference set; feature audit 73 rows | Met |
| Temporal leakage prevention | `docs/FEATURE_AUDIT.md`, `FEATURE_AUDIT.md` | `nvd_status`, CPE/reference counts, reference links, blank-severity signal and all CWE-derived columns excluded; severity imputed | Met |
| Meaningful IBM technology | `models/granite_embed.py`, `docs/IBM_INTEGRATION.md` | `ibm-granite/granite-embedding-30m-english`, 384-d, 160,577 descriptions, local CPU; measured ablation 16 → 20 for both-Granite blend | Met (embeddings only) |
| Granite semantic similarity in product | `/api/vulnerabilities/{id}/similar`, Granite Intelligence page | 21/21 live HTTP checks; similarity excludes self, cosine range, no probability claim | Met |
| Granite structured extraction | `/api/granite/analyze` | deterministic description rules, schema fields, unknown preserved, evidence text; `generative_model: null` | Partial — not a Granite instruct model |
| Granite analyst assistant | `/api/granite/chat`, Granite Intelligence page | retrieval-grounded responses from ranked table, drivers, CVSS/EPSS, similarity; sources cited; no fabricated KEV claim | Partial — no generative Granite |
| Baselines reproduced | `eval/backtest.py`, `eval/gap.py` | CVSS 5, EPSS 8, PoC-then-EPSS 18 held-out; union 19; final 22 | Met on our historical pool |
| Chronological validation | `models/train.py`, `eval/backtest.py` | 2024 month-grouped OOF; Jan–Sep 2025 held out; 2026 never fitted | Met |
| Granite ablation | `eval/granite_ablation.py`, `artifacts/granite_ablation.json` | no-Granite blend 16, both-Granite 20; single models 17/18/19/20 | Met |
| Command Center | `web/src/pages/Overview.tsx` | `/api/overview` 200; distribution, top vendors/CWEs, headline model/baseline | Met (HTTP/build, not browser-clicked) |
| Vulnerability Explorer | `web/src/pages/Explorer.tsx` | pagination/filter/sort API tests; description/vendor/CWE controls in code | Met at API level |
| CVSS Blind Spot detector | Overview/Discoveries, `eval/gap.py` | 33/52 missed by all baselines; 7 recovered; chart data from JSON | Met |
| Vulnerability DNA | Granite Intelligence, `_dna` | deterministic fields + evidence + uncertainty; test asserts method and verified block | Partial — not Granite-extracted |
| Historical timeline | `/timeline`, `CveDetail` | 200 on live CVE; monthly EPSS/exploit/KEV points; note on 2026 one-snapshot limitation | Met |
| Exploit Pattern Discovery | `pipeline/discoveries.py`, Discovery Lab | 9 findings, Wilson intervals; `/api/discoveries` 200 | Met |
| Risk Trajectory | Timeline page | historical EPSS/exploit path for 2024–2025; no fake live monitoring | Met for historical data |
| Similarity Network | Granite Intelligence | nearest-neighbour table with similarity/rank/CWE; not a dense graph | Partial — functional list, not graph visualization |
| Model uncertainty | CVE detail / Granite chat | missing technical fields surfaced; rank described as score/percentile, not calibrated probability | Partial |
| Patch Budget Optimizer | `/api/patch-optimizer`, Patch Optimizer page | four strategies × 20 items, overlap matrix; 5 requests averaged 272 ms; historical validation separate | Met |
| Product Exposure Explorer | `/api/products`, `Products.tsx` | vendor search 200, vendor→vulns 200, 404 unknown; CPE vendor only, no asset inventory | Partial — vendor-level |
| Evidence-backed investigation | `CveDetail.tsx` | detail 200 with description, rank, technical fields, contributions, remediation priority, Granite link | Met |
| 18 API routes with validation | `api/main.py` | 21/21 checks; 422 page 0; 404 unknown CVE/vendor | Met |
| One-command startup | `start.sh` / `start.bat` | live bind + health 200; 21/21 checks; syntax OK | Met after killing stale listener |
| Reproducibility | `run_all.py`, requirements, lockfile | pipeline stages, model, predictions, tests; Granite ~23 min CPU | Met with local artefacts |
| Required docs | `docs/` + `README.md` | 12 docs; links present | Met |
| Demo script / Devpost | `docs/DEMO_SCRIPT.md`, `docs/DEVPOST.md` | 2:50 shot list, Q&A, fallback; draft | Met |
| Browser click-through | not available | no Chrome binary; HTTP/build verification only | Not verifiable here |
| Official 2026 score | no answer key in release | KEV ends 2025-12-29; 2026 labels unavailable | Not verifiable here |
| Frontend unit tests | none | build and API integration only | Partial |
