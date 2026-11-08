# Performance audit

Measurements were taken in-process with `fastapi.testclient.TestClient` after warming the caches; five
requests per endpoint, mean reported. This measures application work, not network or browser render.

| Endpoint | Mean |
| :-- | --: |
| `/api/health` | 3.13 ms |
| `/api/overview` | 9.36 ms |
| `/api/vulnerabilities?page=1&size=50` | 7.59 ms |
| `/api/vulnerabilities/{id}` | 183.30 ms |
| `/api/vulnerabilities/{id}/similar?limit=10` | 23.86 ms |
| `/api/vulnerabilities/{id}/timeline` | 92.69 ms |
| `/api/products?q=microsoft&size=25` | 36.81 ms |
| `/api/model/performance` | 3.31 ms |
| `/api/discoveries` | 2.96 ms |
| `POST /api/patch-optimizer` | 271.58 ms |

Bundle:

- `dist/assets/index-BH7NRizC.js` 732.26 kB, gzip 216.64 kB
- `dist/assets/index-BepINlHj.css` 11.49 kB, gzip 3.31 kB
- Vite warning: one chunk > 500 kB.

## Interpretation

- Warm reads are fast. The two heavier interactions are the full CVE detail (first lookup of the
  CSV detail table and attribution) and the four-sort patch optimizer. Both are well under a second on
  this machine and acceptable for a 20–500 budget demo.
- Cold start loads parquet frames lazily; the first health/overview request may be slower than the
  warm numbers above. Startup was verified functionally, not benchmarked to the millisecond.
- No memory measurement was taken. The parquet frames and the 72,670 × 384 float32 matrix are the
  dominant resident objects; the matrix is memory-mapped with `np.load(..., mmap_mode="r")`.

## What was not optimized

- No route-level code splitting; the 732 kB bundle is a single chunk.
- Patch optimizer re-sorts the full frame for each strategy instead of precomputing strategy columns.
- Detail lookup is a full-frame scan rather than an indexed map.

These are documented opportunities, not correctness blockers. No speedup is claimed because no
before/after optimization was performed in this audit.
