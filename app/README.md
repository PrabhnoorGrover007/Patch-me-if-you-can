# Patch Me If You Can — web app

Next.js (App Router) + TypeScript + Tailwind + Recharts front end for the top-500 ranked
vulnerability list, with AI insights and a remediation board.

## Run it

```bash
npm install
npm run data     # regenerate src/data/*.json from ../outputs/top500.csv + ../IBM_dataset
npm run dev      # http://localhost:3000
```

Production check: `npm run build && npm start`.

## AI provider

The app calls **Google Gemini** when `GEMINI_API_KEY` is set, and **IBM watsonx / Granite** when
only the watsonx keys are set. Copy `.env.example` to `.env.local` and fill in one of them:

| Variable | Purpose |
| --- | --- |
| `GEMINI_API_KEY` | Google AI Studio key — the default path |
| `GEMINI_MODEL_ID` | default `gemini-3.6-flash` |
| `GEMINI_API_URL` | optional REST base override |
| `WATSONX_API_KEY` | IBM Cloud API key with watsonx.ai access (alternate) |
| `WATSONX_PROJECT_ID` | watsonx.ai project id (alternate) |
| `WATSONX_URL` | region endpoint, default `https://us-south.ml.cloud.ibm.com` |
| `GRANITE_MODEL_ID` | default `ibm/granite-4-h-small` |

Gemini takes precedence when both are configured. With no credentials the app still runs: insights
and chat answers come from a local explainer built from the CVE record, badged **Offline heuristic**
instead of **Google Gemini**.

If a call fails (bad key, retired model, rate limit) that single answer falls back to the local
explainer and the detail panel or chat bubble prints a crimson *"Model call failed"* line with the
provider's error, so a misconfiguration is visible rather than silent.

Model ids move: `gemini-3.5-flash` is already deprecated (Google routes it to 3.6). If you get a
404, list what your key can reach and set `GEMINI_MODEL_ID` accordingly:

```bash
curl -s "https://generativelanguage.googleapis.com/v1beta/models" -H "x-goog-api-key: $GEMINI_API_KEY"
```

## Where the data comes from

`scripts/build-dataset.mjs` streams the raw challenge CSVs once and writes two files the app
imports:

- `src/data/cves.json` — 500 records hydrated from `outputs/top500.csv` (rank order), joining
  `vulnerabilities.csv` (description, CVSS, CWE), `scoreboard_2026.csv` (EPSS and exploit flags at
  the cutoff), `weakness_types.csv` (CWE names) and `affected_products.csv` (product context).
- `src/data/meta.json` — cohort aggregates, the validation numbers from
  `outputs/validation_results.json`, and the monthly exposure series.

Composite risk shown in the UI is `100 × (0.50·EPSS percentile + 0.25·Metasploit + 0.15·Exploit-DB
+ 0.07·Nuclei + 0.03·GitHub PoC)`, evaluated only on signals available at the snapshot month.
Remediation effort is a documented heuristic (product class + description wording), not a measured
value.

## Structure

```
src/app/            routes: / (dashboard), /analytics, /queue, /upload, /chat
src/components/     UI modules, one per surface
src/lib/data.ts     typed accessors over the generated JSON
src/lib/llm.ts      Gemini + watsonx clients, prompts, offline explanation fallbacks
src/lib/ai-actions.ts  server actions: insight + chat
src/lib/queue-*     server-side remediation store and actions
docs/               original design system (DESIGN.md) and PRD
```

The remediation board is persisted to `.data/remediation.json` on the server. Replace the four
functions in `src/lib/queue-store.ts` with Supabase queries to move it to Postgres.
