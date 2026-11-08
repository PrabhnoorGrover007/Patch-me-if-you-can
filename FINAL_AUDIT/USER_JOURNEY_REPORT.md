# User journey report

Verification level: **API + build + code path**. No browser binary was available, so no journey is
claimed as a visual click-through. Where a control is described, its handler and API response were
inspected and the endpoint was exercised over HTTP.

## Journey A — understand the platform

1. `/` served 200 from the built dashboard.
2. `/api/overview` returned 72,670 analysed, 20 histogram bins, severity mix, top vendors/CWEs and the
   headline model (22) vs baseline (18).
3. Discovery cards are fed by `/api/discoveries` (9 findings).
4. The blind-spot finding is displayed with the 33/52 and 7/33 numbers from the JSON.

**Result:** data path works. Visual hierarchy was not browser-checked.

## Journey B — investigate a vulnerability

1. Explorer API: `page=1&size=5`, severity filter, EPSS filter, sort whitelist all pass.
2. Detail for `CVE-2026-2699` returned 200 with description, rank, risk score/percentile, CVSS, EPSS,
   vendor, CWE, technical fields, contributions and remediation priority.
3. Similar returned five non-self neighbours; timeline returned the CVE; explanation returned a
   deterministic source.
4. Granite analyze returned deterministic DNA and analogs; chat answered "Why is CVE-2026-2699 ranked
   here?" with the recorded rank and drivers, `generative_model: null`.

**Result:** full investigation path works at API level; UI links and handlers exist.

## Journey C — compare prioritization strategies

1. `POST /api/patch-optimizer {"budget":20}` returned four strategies, 20 items each.
2. Overlap matrix includes model↔model = 20 and the other strategies' overlaps.
3. Unique sets are returned for each strategy.
4. Historical validation is attached as `gap_analysis.json`; no 2026 hit claim.
5. Items carry `cve_id` and the detail route accepts them.

**Result:** 20-Patch Challenge works; one request averaged 272 ms in-process.

## Journey D — discover exploitation patterns

1. `/api/discoveries` returned 9 findings.
2. Each has `finding`, `n`, and confidence intervals where chart data is present; the test enforces
   interval length and ordering.
3. The Discovery Lab renders titles/findings/charts from the response; no static numbers.

**Result:** works. The strength of each finding is separately assessed in
`DATA_AND_ML_AUDIT.md`; not every finding is equally strong.

## Journey E — historical exploitation timeline

1. Timeline for a 2026 CVE returned 200; for a historical KEV CVE the signal table supplies monthly
   EPSS, exploit-source count and `in_kev`.
2. `kev_added` is included when the CVE is in KEV.
3. The response explicitly notes that 2026 has one snapshot per CVE, so no synthetic monthly path is
   fabricated.

**Result:** works for historical data; 2026 trajectory is correctly not invented.

## Journey F — product exposure

1. `/api/products?q=microsoft&size=5` returned vendor aggregates.
2. `/api/products/microsoft/vulnerabilities?size=5` returned ranked CVEs for that vendor.
3. Unknown vendor returned 404.

**Result:** vendor-level exposure works. Version-level ownership is not claimed because no asset
inventory is supplied.

## Journey G — export

1. `/api/export?limit=20` returned `text/csv` with 21 lines.
2. `/api/top500` returned 501 lines, header `cve_id`.
3. `top500.csv` itself has 500 unique rows and md5 `4677d079b77a6262a70e265cb3136d4e`.

**Result:** works.

## Overall

Seven journeys are functionally covered at the API/route-handler level. The missing piece is a real
browser pass for console errors, layout overflow, focus states and responsive behavior. That is the
honest limit of this report.
