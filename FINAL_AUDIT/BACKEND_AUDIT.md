# Backend audit

## Routes (18)

| Method | Path | Purpose |
| :-- | :-- | :-- |
| GET | `/api/health` | product, row count, Granite availability |
| GET | `/api/overview` | Command Center aggregates from `ranked_2026.parquet` |
| GET | `/api/vulnerabilities` | pagination, severity/vendor/CWE/EPSS/exploit/search filters |
| GET | `/api/vulnerabilities/{cve_id}` | full investigation payload |
| GET | `/api/vulnerabilities/{cve_id}/similar` | Granite cosine neighbours |
| GET | `/api/vulnerabilities/{cve_id}/timeline` | monthly EPSS/exploit/KEV points |
| GET | `/api/rankings` | top-N ranking slice |
| GET | `/api/products` | CPE vendor aggregate and search |
| GET | `/api/products/{product_id}/vulnerabilities` | vendor-associated ranked CVEs |
| POST | `/api/patch-optimizer` | four budget queues and overlap matrix |
| GET | `/api/model/performance` | held-out rows, selection, permutation importance |
| GET | `/api/discoveries` | nine findings |
| GET | `/api/explanations/{cve_id}` | generated or deterministic explanation, source labelled |
| GET | `/api/export` | CSV of ranked slice |
| GET | `/api/top500` | submission CSV |
| GET | `/api/granite/status` | model id, dimensions, capability boundary |
| POST | `/api/granite/analyze` | deterministic DNA + Granite analogs |
| POST | `/api/granite/chat` | grounded retrieval answer |

## Validation and errors

- Pydantic: `budget` 1–500, `page ≥ 1`, `size` 1–500, sort pattern whitelist, CVE string length,
  chat question 2–2,000 characters.
- Live checks: `page=0` → 422, unknown CVE → 404, unknown vendor → 404.
- Missing artefacts → 503 with a concrete "run models.predict / pipeline.features" message, never
  invented data.
- `_json_records` converts pandas missing values to JSON nulls; `_safe_float/_safe_int` guard NaN.
- CORS is open (`*`) for the local demo; there is no authentication. This is intentional for a
  hackathon demo and documented as a security limitation.
- All file reads use fixed paths under `ROOT/artifacts` or `ROOT/data`; no user-controlled path
  reaches the filesystem.

## Caching and cost

- `ranked()`, `full()`, `predict_table()`, `products_table()`, `signals_table()`, `kev_table()`,
  `granite_index()`, `granite_embeddings()`, `cwe_names()`, `descriptions()` and `explanations()` use
  `lru_cache(maxsize=1)`.
- No N+1 query pattern; product aggregation is a groupby over the CPE table once per process.
- `vulnerability()` scans the full detail table and the attribution JSON on first access (183 ms
  average in the in-process benchmark), then benefits from cached frames.
- `/api/patch-optimizer` sorts 72,670 rows four times per request (272 ms average). It is acceptable
  for 20–500 budgets and a demo; it is not optimized for high concurrency.

## Operational issue found and fixed

The first startup smoke run returned 404/405/500 on new routes. The cause was **not** the current app:
an old uvicorn process (PID 50864) still held `127.0.0.1:8000`; `start.sh` failed to bind and the test
hit the stale server. The stale listener was terminated, the current process bound successfully, and
all 21 checks passed. This is recorded because a reviewer repeating the demo could hit the same port
collision; `start.sh` correctly reports the bind failure but does not choose another port.

## Residual backend weaknesses

- No authentication, no rate limiting, no request-size middleware beyond FastAPI limits.
- Full-detail lookup is O(n) over a 72k-row frame; an index would be better at scale.
- `full()` and `ranked()` duplicate data (CSV vs parquet); this is a reproducibility trade-off, not a
  correctness defect.
- `granite_status` reports artefact availability, not a live service probe; there is no live service
  to probe.
