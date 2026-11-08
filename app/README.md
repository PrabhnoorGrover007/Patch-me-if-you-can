# Patch Me If You Can — integrated Next.js app

Next.js (App Router) + TypeScript + Tailwind 4 + Recharts front end for the 72,670-row
2026 benchmark, the submitted top 500, the model laboratory and the remediation board.

This is the **primary frontend** of the project. It has no generated `src/data/*.json`. Every
screen calls the FastAPI service in `../api/main.py`; generative Granite can use a local 2B model
or watsonx.ai and is configured on that backend.

## Run it

From the project root:

```bash
bash start.sh          # API :8000 + Next :3000 (macOS/Linux/Git Bash)
start.bat              # Windows cmd
```

Or manually:

```bash
npm install
API_BASE=http://127.0.0.1:8000 npm run dev    # http://localhost:3000
```

Production check: `npm run typecheck && npm run build && API_BASE=http://127.0.0.1:8000 npm start`.

## Data and AI

| Source | Used for |
| --- | --- |
| `GET /api/dashboard` | Hydrated top 500: rank, probability, priority, CVSS, EPSS, exploit flags, products, CWE, reasons |
| `GET /api/vulnerabilities` | Paginated explorer over all 72,670 scored rows |
| `GET /api/vulnerabilities/{cve}` | Investigation record, attribution and remediation priority |
| `GET /api/vulnerabilities/{cve}/similar` | Granite embedding analog retrieval |
| `GET /api/vulnerabilities/{cve}/timeline` | Monthly EPSS and exploit-source history where available |
| `POST /api/patch-optimizer` | Four strategies under the selected budget |
| `GET /api/model/performance` | Held-out metrics, baseline reproduction, Granite ablation |
| `GET /api/discoveries` | Nine measured findings with intervals |
| `GET /api/products` | CPE-vendor exposure from `affected_products.csv` |
| `GET /api/top500` | Exact submission file, one `cve_id` column |
| `GET /api/export` | Ranked working CSV |

`API_BASE` is server-only. Browser requests use relative `/api` paths and the rewrite in
`next.config.ts`; no key or internal host name is shipped to the client.

Analyst text is grounded retrieval assembled by FastAPI from the ranked table,
`attribution.json`, the Granite similarity index and the deterministic description rules.
The shipped embedding artefact is separate from generation. If a local Granite server is running
or watsonx.ai credentials are set, the same evidence is handed to a Granite instruct model and the
badge changes to **IBM Granite · generated**; otherwise the badge says **grounded** and no answer
is invented. See `../.env.example` and `../setup_local_ai.py`.

## Structure

```text
src/app/              routes: dashboard, explorer, intelligence, patch, discoveries,
                      model, products, analytics, queue, upload, chat
src/components/       one module per surface, plus the shared Panel/StatCard/ui kit
src/lib/api.ts        server/base-aware fetch wrapper
src/lib/data.ts       server-only dashboard accessors
src/lib/ai-actions.ts server actions calling the grounded FastAPI endpoints
src/lib/queue-*       server-side remediation store and actions
docs/DESIGN.md        the teammate's original Alabaster design system
```

The remediation board persists to `.data/remediation.json` on the Next server. It is real
server-side state, not seeded demo cards. Replace the four functions in `queue-store.ts` with a
database when multiple hosts need to share it.
