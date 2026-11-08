# Security audit

## Secrets and repository hygiene

- No API keys, passwords or IBM Cloud credentials in source, docs or tracked artefacts.
- `.env.example` contains only optional non-secret bind/model/cache settings.
- `.env`, `.env.local`, `.venv`, `data/`, `data.zip`, `web/node_modules`, `web/dist` and large binary
  artefacts are ignored.
- `top500.csv`, `full_rankings.csv` and the small JSON evidence files are intentionally retained.
- No raw supplied data was modified. No personal data is present.
- `shap` was removed because it was declared but unused, reducing the dependency surface.

## Input handling

- Pydantic validates budget (1–500), page/size bounds, sort whitelist, CVE string length and chat
  question length.
- All data access is through fixed paths under the project root; no user string is used as a path.
- Comparisons use pandas string equality/contains, not SQL; there is no SQL injection surface.
- JSON parsing is limited to project-owned artefact files, not request bodies beyond Pydantic.
- Error responses do not include stack traces or secrets; missing artefacts return a 503 message.
- `CVE_RE` only extracts an id-shaped token for grounded chat; it does not evaluate arbitrary input.

## Exposure and accepted risks

- **CORS is `*`** and there is **no authentication**. This is a local hackathon demo; the server binds
  to `127.0.0.1` through `start.sh` and should not be exposed publicly. This is a documented demo
  trade-off, not a production security posture.
- OpenAPI docs are exposed at `/docs`; acceptable for judging.
- No rate limiting. A local user can issue many patch-optimizer or export requests; the page size is
  capped at 500 and export at 5,000.
- `granite` is local; there is no remote prompt-injection path because there is no generative model.
  The deterministic rules read CVE descriptions as text, not instructions.
- The frontend has no authentication state to leak.

## Dependency checks

`pip check` was run in the audited environment; no broken requirement was reported. No automated
Python CVE scanner or `npm audit` was run (offline/registry access was not assumed). The lockfile is
present for the frontend; versions are pinned in `requirements.txt`. This is a limitation, not a claim
of a clean vulnerability scan.

## Verdict

No critical or high-severity code-level vulnerability was found in the parts inspected. The main
residual risks are architectural and intentional for a demo: unauthenticated local API, permissive
CORS and no rate limiting. Do not deploy this server on a public interface without adding auth,
origin restrictions and request throttling.
