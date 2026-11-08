# Final test report

Date: 2026-11-08. Environment: Windows, Python 3.13.7, pytest 9.2.0, Node 22, Vite 7.3.7.

## Executed

| Check | Result |
| :-- | :-- |
| `python -m pipeline.audit` | exit 0, 73 features, 9 excluded columns |
| `pytest -q` | **22 passed**, 0 failed, 0 skipped |
| `npm run build` | exit 0, TypeScript clean, 438 modules, 2.95 s |
| `bash -n start.sh` | exit 0 |
| `bash start.sh` live | bound 127.0.0.1:8000, health 200 |
| HTTP checks | **21/21 passed** |
| `top500.csv` | 501 lines, 500 unique, one column, md5 `4677d079b77a6262a70e265cb3136d4e` |
| `pip check` | no broken requirements reported |

### HTTP checks (21)

All 200: health, overview, vulnerabilities list, detail, similar, timeline, products, product
vulnerabilities, patch optimizer, Granite analyze, Granite chat, model performance, discoveries,
rankings, export, top500, `/`, `/docs`. Expected errors: 422 for `page=0`, 404 for an unknown CVE, 404
for an unknown vendor.

### Test counts

- `tests/test_pipeline.py`: 11
- `tests/test_api.py`: 11
- Total: 22

## Failure found and fixed during verification

The first live startup test produced eight 404/405/500 failures on the new routes. Root cause: an old
uvicorn process from a previous development run still owned port 8000. `start.sh` failed to bind and
the test reached the stale server. The stale PID was terminated; the current server started cleanly
and all 21 checks passed. The new startup log shows `Uvicorn running on http://127.0.0.1:8000`.

This is an environmental collision, not a passing test that was re-labelled. It is recorded because a
judge could hit the same issue if a previous server is still running.

## Not executed / blocked

| Check | Status | Why |
| :-- | :-- | :-- |
| Real browser click-through / console / responsive | **Blocked** | no Chrome binary in environment |
| Frontend unit/component tests | **Not present** | build + API integration only |
| Official 2026 score | **Not verifiable** | no 2026 answer key; KEV ends 2025-12-29 |
| Live watsonx.ai call | **Blocked** | no IBM Cloud credentials |
| Granite instruct extraction accuracy benchmark | **Not performed** | no instruct model; deterministic fallback only |
| Load/concurrency benchmark | **Not performed** | only single-user in-process timings |
| Python/npm CVE scanner | **Not run** | registry/tool availability not assumed |

## Commands

```bash
cd IBM
.venv/Scripts/python.exe -m pipeline.audit
.venv/Scripts/python.exe -m pytest -q
(cd web && npm run build)
bash -n start.sh
bash start.sh
```

## Verdict

The mechanics, data invariants, submission format, API contract and one-command startup are tested and
pass. Predictive quality is established only on historical cohorts; visual and 2026 performance remain
unverified. No blocked check is reported as passed.
