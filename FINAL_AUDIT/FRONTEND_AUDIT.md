# Frontend audit

## Product and branding

- Browser title: `PATCH ME IF YOU CAN` (checked in `web/index.html`).
- Package name: `patch-me-if-you-can`.
- Sidebar brand and subtitle: `PATCH ME IF YOU CAN` / `Vulnerability Intelligence`.
- Official track references in the Command Center eyebrow and API description still say
  `IBM · Before the Breach track · Sheridan Datathon 2026`; that is the challenge, not the product
  name.
- Export filename: `prioritized.csv`.
- No old working title remains as a product name.

## Pages (9)

| Page | Route | Data source |
| :-- | :-- | :-- |
| Command Center | `/` | `/api/overview` |
| Vulnerability Explorer | `/explorer` | `/api/vulnerabilities` |
| CVE Investigation | `/cve/:id` | `/api/vulnerabilities/{id}`, `/explanations`, `/similar`, `/timeline` |
| 20-Patch Challenge | `/patch` | `POST /api/patch-optimizer` |
| Granite Intelligence | `/granite` | `POST /api/granite/analyze`, `/chat`, `/similar` |
| Discovery Lab | `/discoveries` | `/api/discoveries` |
| Model Laboratory | `/model` | `/api/model/performance` |
| Product Exposure | `/products` | `/api/products`, `/api/products/{id}/vulnerabilities` |
| Prioritization Workflow | `/workflow` | static explanatory content, no analytical claims |

`HashRouter` is used because FastAPI serves the static build from `/`; deep links work under the hash.
All navigation targets are registered. The export button is an `<a>` to `/api/export?limit=500`; the
patch page reads the budget control and posts it; the CVE rows link to the investigation route.

## Data-integrity review

- No hardcoded model metric, discovery number, risk score or ranking was found in the page components.
  Values come from `api.ts` typed responses.
- `Workflow` is intentionally static and does not present numbers as model output.
- The Command Center gain and headline hit counts come from `/api/overview` (`headline_model`,
  `headline_baseline`), not constants.
- The `Granite Intelligence` page labels extraction as deterministic and the assistant as
  retrieval-grounded; it does not claim a generative Granite answer.
- Chart series derive from API arrays; empty arrays render as empty states, not fake data.

## Build evidence

```
npm run build
tsc --noEmit && vite build
438 modules transformed
dist/index.html 0.63 kB
dist/assets/index-BepINlHj.css 11.49 kB (gzip 3.31 kB)
dist/assets/index-BH7NRizC.js 732.26 kB (gzip 216.64 kB)
built in 2.95s
exit 0
```

Only warning: chunk larger than 500 kB. No TypeScript error. The bundle is single-chunk because the
whole app is a demo, not a route-split production site.

## What was not verified

No Chrome binary was available, so this audit could not visually inspect layout, contrast, responsive
breakpoints, console errors or click every control. Verification is limited to TypeScript build, the
served `index.html`, and HTTP responses from the API the UI calls. A human should do one browser pass
before recording; this is a real gap, not a passed check.

## Fixed during audit

- Sidebar said "nine 2026 snapshot months"; corrected to eight.
- New pages and navigation were wired; no dead menu entries found.
- The earlier stale-worktree UI copy was checked for the old product name and cleaned.
