# Frontend integration — Patch Me If You Can

## Result

The teammate's Next.js application is now the primary frontend. It keeps the teammate's
**Royal SecOps Alabaster** design system and route vocabulary, while its data and analyst
surfaces are connected to the existing FastAPI/ML backend. The old Vite frontend was retired
from the working tree; it remains recoverable from the pre-integration backup branch.

- Primary UI: `app/` (Next.js 15, React 19, Tailwind 4, Recharts)
- API: `api/main.py` (FastAPI), served separately on port 8000
- Startup: `start.sh` / `start.bat` launch both processes; UI at `http://127.0.0.1:3000`

## Git state and recovery point

| Item | Value |
| --- | --- |
| Repository | `https://github.com/PrabhnoorGrover007/Patch-me-if-you-can.git` |
| Current branch | `wip/audit-frontend-integration` |
| HEAD before integration | `000b9ec` — preserves the audited backend/ML tree |
| Pre-integration backup | `backup/pre-frontend-integration` at `37ba440` |
| Remote frontend commit | `7d1e177` — `Add the top-500 CVE web app with Gemini-backed analysis` |
| Remote branches | `origin/master` and `origin/main` both at `7d1e177`; `origin/front-end` at `60d0893` |
| Merge base | **none** — `git merge-base HEAD origin/master` is empty |

The remote `master` history was force-rewritten to a separate root history. A normal
`git merge origin/master` therefore cannot be used without an unrelated-history merge, which
would be a destructive and misleading history operation. Integration was performed as a
**manual tree integration**:

1. Committed the audited local changes on `wip/audit-frontend-integration` (`000b9ec`).
2. Created/verified `backup/pre-frontend-integration` at `37ba440`.
3. Fetched `origin` with prune and identified `7d1e177` as the teammate frontend commit.
4. Extracted only the teammate's `app/` tree from that commit into the working tree.
5. Adapted its data and AI layer to the existing FastAPI API rather than importing the
   teammate's separate root `model.py` / `prepare_data.py` pipeline.
6. Kept our audited `pipeline/`, `models/`, `eval/`, `artifacts/`, `api/`, `tests/` and docs.
7. Removed the superseded `web/` Vite tree from the delivered working tree.

No push was performed. No `git reset --hard`, force-push, or discard of uncommitted work was
used.

## What was imported from `7d1e177`

The teammate application tree and its design documentation:

- `app/src/app/` — dashboard, analytics, queue, upload and chat routes
- `app/src/components/` — `AppShell`, `DashboardView`, `CveTable`, `CveDetail`, `QuickWinsMatrix`,
  `SeverityDonut`, `AnalyticsView`, `KanbanBoard`, `UploadInspector`, `ChatPanel`,
  `ChatProvider`, `ChatWorkspace` and the shared `ui.tsx`
- `app/src/lib/` — types, formatting and the server-side remediation store/actions
- `app/src/app/globals.css` and the Alabaster Tailwind token definitions
- `app/docs/DESIGN.md` and `app/docs/PRD.md`
- Next.js/Tailwind/TypeScript/Recharts configuration

The extraction was used as the visual source of truth, not as a blind replacement of the
backend or ML pipeline.

## Semantic conflicts resolved

There were no textual Git conflicts because no merge was possible. The real conflicts were
architectural:

| Conflict | Resolution |
| --- | --- |
| Teammate read generated `src/data/cves.json` and `meta.json` | Replaced with server-side `getDashboard()` calling `GET /api/dashboard`, built from `ranked_2026.parquet`, `full_rankings.csv`, `vulnerabilities.parquet`, `affected_products.csv` and the validation artefact |
| Teammate defaulted to Google Gemini and optionally watsonx | Removed the Gemini client. Analyst text comes from FastAPI grounded retrieval, then local Granite 2B through llama.cpp or watsonx.ai when available; the UI labels **IBM Granite · generated** vs **IBM Granite · grounded** and never fabricates a fallback |
| Teammate composite risk was a hand-built EPSS/exploit formula | Added `priorityScore` (model rank normalised across the submitted 500) and `riskProbability` (the actual fitted score). The UI labels both; neither is called a calibrated probability |
| Teammate's top-500 data was generated from its own `outputs/top500.csv` | `/api/dashboard` uses our authoritative `ranked_2026.parquet` and reproduces exactly the submitted `top500.csv` order |
| Teammate had a 500-row static dataset; our project has 72,670 scored rows | Dashboard receives only the 500 hydrated records; the Explorer pages through FastAPI, 25 rows at a time |
| Old Vite app still sat in `web/` | Retired it from the working tree so there is one UI system. It is in `backup/pre-frontend-integration` |
| Teammate's AI badged "Offline heuristic" when no key existed | Offline means the FastAPI evidence service is unreachable. The UI says **Backend unavailable** and never generates substitute findings |
| Teammate's queue was local server JSON | Kept it. The board persists to `app/.data/remediation.json` and is real server-side state |

## Backend changes

- `GET /api/dashboard` — one hydrated payload for the submitted 500: rank, model probability,
  priority, CVSS/vector, EPSS/percentile, exploit flags, CWE names, affected products, CNA,
  reasons, effort heuristic and quadrant, plus cohort meta and held-out validation.
- `GET /api/model/performance` — now also returns the measured `granite_ablation.json` table.
- `GET /api/vulnerabilities` — includes the description needed by the explorer and the
  intelligence search.
- `GET /` — explicit API-root metadata; the old static `web/dist` mount was removed.
- `tests/test_api.py` — added dashboard contract coverage and a Granite ablation assertion.

No existing ML endpoint, pipeline module, model artefact or data-processing rule was deleted or
rewritten. Queue persistence stays in the Next server because it is a UI workflow store, not a
model result.

## Design system preserved

The integration did not introduce a second visual system. The existing tokens are still used:

- Canvas `#f4efe4`, parchment `#fdf8ee`, alabaster `#fffdfa`, hairline `#ded3bf`
- Navy ink `#0b192c`, gold `#d4af37`, crimson `#9b111e`, jade `#1b4d3e`
- EB Garamond headings, Source Sans 3 body, JetBrains Mono labels
- `card`, `card-inset`, `eyebrow`, `mono`, `btn`, `btn-primary`, `btn-ghost`, `chip`, `input`
  component classes
- 4/8/10/12 px radii, gold-tinted borders, parchment surfaces, tab underline navigation
- Reusable `Panel`, `StatCard`, `SeverityChip`, `QuadrantChip`, `SourceBadge`, `Empty`,
  `PageHeader`

New routes use those same elements rather than a new component library.

## Running the integrated app

```bash
cd IBM
bash start.sh          # Git Bash / macOS / Linux
# or: start.bat        # Windows cmd
```

- UI: <http://127.0.0.1:3000>
- API docs: <http://127.0.0.1:8000/docs>
- Health: <http://127.0.0.1:8000/api/health>

Manual:

```bash
.venv/Scripts/python.exe -m uvicorn api.main:app --port 8000
cd app && API_BASE=http://127.0.0.1:8000 npm run dev
```

## Remaining integration limitations

- No Chrome/Chromium binary was available; click-level browser automation and screenshots were
  not run. HTTP/SSR checks and the production build are in `FRONTEND_TEST_REPORT.md`.
- The 2026 benchmark has no answer key, so no 2026 hit rate is shown.
- The Granite artefact is an embedding model. There is no hosted generative instruct model, so
  "Granite analysis" is deterministic extraction plus embedding retrieval, clearly labelled.
- Product exposure is CPE-vendor coverage from `affected_products.csv`, not an organisation's
  asset inventory.
