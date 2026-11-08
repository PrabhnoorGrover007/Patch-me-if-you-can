# Frontend test report — integrated application

Date: 2026-11-08  
Environment: Windows, Git Bash; Python 3.13.7; Node 24.21.0; npm 11.19.0; llama.cpp b12208 with
local Granite 2B Q3_K_M; no Chrome/Chromium binary available.

## Executed checks

| Check | Command | Result |
| --- | --- | --- |
| Backend suite | `.venv/Scripts/python.exe -m pytest -q` | **23 passed** |
| Frontend type check | `cd app && npm run typecheck` | **pass**, exit 0 |
| Frontend production build | `cd app && npm run build` | **pass**, exit 0; 13 routes compiled |
| Next + FastAPI live | `uvicorn api.main:app --port 8000` and `API_BASE=http://127.0.0.1:8000 npm start` | both ready; no startup exception |
| API rewrite through Next | `curl http://127.0.0.1:3000/api/...` | 200 for dashboard, top500, export, vulnerabilities, products, model, discoveries, patch, detail, Granite analyze/chat |
| Dashboard payload | `GET /api/dashboard` | 500 records, universe 72,670, validation hits@500 22 |
| Official export | `GET /api/top500` | 501 lines; header exactly `cve_id`; 500 unique ids; byte-identical MD5 `4677d079b77a6262a70e265cb3136d4e` (raw bytes, CRLF preserved) |
| Working export | `GET /api/export?limit=500` | 500 rows; `cve_id,rank,risk_score,cvss3_score,epss_score,vendor,cwe_top,reason` |
| Patch optimizer | `POST /api/patch-optimizer {"budget":50}` | four strategies, each exactly 50 items |
| Granite analysis | `POST /api/granite/analyze` for `CVE-2026-2699` | 200; deterministic extraction + 5 analogs; `generative_model: null` |
| Local Granite service | `local_ai/runtime/llama-server.exe` + `GET /health` | 200; model loaded; no account required |
| Granite chat | `POST /api/granite/chat` for `CVE-2026-2699` | 200; `source: granite-generative`; `provider: local llama.cpp`; generated answer in about 26s; also 200 through the Next proxy |
| Build route list | `npm run build` output | `/`, `/explorer`, `/patch`, `/discoveries`, `/model`, `/products`, `/intelligence`, `/intelligence/[cve]`, `/analytics`, `/queue`, `/upload`, `/chat`, `/_not-found` |

## Live SSR route checks

Each response was fetched from the running Next server, not from the build log:

| Route | Status | Notes |
| --- | --- | --- |
| `/` | 200 | dashboard payload rendered server-side |
| `/explorer` | 200 | client table shell renders; data arrives from `/api/vulnerabilities` |
| `/patch` | 200 | optimizer shell renders; budget request is API-backed |
| `/discoveries` | 200 | all nine findings render; a runtime cohort-object rendering bug found here was fixed and re-checked |
| `/model` | 200 | held-out table, Granite ablation and importance render |
| `/products` | 200 | product shell renders; directory and vendor CVEs are API-backed |
| `/intelligence` | 200 | search/start page |
| `/intelligence/CVE-2026-2699` | 200 | CVE detail route |
| `/analytics` | 200 | risk trends |
| `/queue` | 200 | remediation board |
| `/upload` | 200 | submission inspector |
| `/chat` | 200 | grounded analyst workspace |
| `/not-a-route` | 404 | branded not-found page |

## User journeys exercised

1. **Command Center** — SSR page loaded with 500 hydrated records; first record is
   `CVE-2026-2699`, rank 1, priority 100, model p 0.999915; product list is present.
2. **Vulnerability investigation** — `CVE-2026-2699` detail, similar-CVE and timeline endpoints
   returned 200; Granite analysis stayed deterministic, and chat returned a grounded generative answer
   from the local Granite 2B model.
3. **Patch Optimizer** — budget 50 returned four strategies with 50 items each; the UI exposes
   overlap and historical held-out evidence.
4. **Discovery Lab** — all nine discoveries returned, each with an n and a finding; charts include
   confidence intervals where the pipeline computed them.
5. **Product Explorer** — `/api/products` returned 35,506 CPE vendors; a vendor's CVEs returned
   200. This is the supplied CPE table, not an asset inventory.
6. **Model Laboratory** — held-out table, baseline reproduction and measured Granite ablation were
   returned from the real artefacts.
7. **Export** — official `top500.csv` is 500 unique CVEs in one column; working export has 500 rows.

## Fixes made during verification

- `/discoveries` initially returned HTTP 500 because the API's `cohort` object was rendered as a
  React child. The page now uses a readable cohort label; the route was rebuilt and returned 200.
- The explorer API response did not include descriptions; descriptions were added server-side so
  the table and search results are useful.
- The teammate's Gemini client was removed after TypeScript caught its provider types conflicting
  with the Granite-only contract. The shared `SourceBadge` now reports **IBM Granite · generated**,
  **IBM Granite · grounded** or **Backend unavailable**.
- The assistant gained a local llama.cpp provider. `start.sh` launches it when `local_ai/` exists,
  and the backend falls back to grounded retrieval if the local model is unavailable.

## Not run / limitations

- **No browser automation or screenshots.** Chrome was not installed; Playwright was not added.
  Therefore hover/focus/drag interactions were code-reviewed but not click-tested in a real
  browser. The routes, SSR output, API calls, build and contract assertions were tested.
- **No hosted Granite 8B call.** No IBM Cloud/watsonx credentials were available. The local Granite
  2B model was called live and returned generated answers; the hosted 8B path is implemented but not
  exercised with real credentials.
- **No 2026 answer key** exists, so no 2026 scoring claim is made.
- **No visual regression baseline.** The teammate's Alabaster tokens and component classes were
  preserved, but pixel comparison was not possible without a browser.
