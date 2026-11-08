# Judge perspective

This is deliberately critical. It is not the Devpost copy.

## 1. What is genuinely innovative?

The strongest original contribution is not the model architecture. It is the **blind-spot measurement**:
on the Jan–Sep 2025 pool, 33 of 52 later-exploited CVEs appear in none of the three conventional top-500
lists, and the rebuilt ranker recovers 7 of them. That is a concrete, testable statement about what
CVSS/EPSS prioritization misses, tied to a working product.

The second genuine contribution is the **audit trail**: the project found and fixed its own
NIST-review leakage, then found a second cohort bug (14 already-KEV rows) and rebuilt every metric.
Many hackathon submissions do not document a negative result or a correction.

## 2. What is ordinary?

- A gradient-boosted tabular ranker with EPSS, exploit flags, vendor history and text keywords is a
  standard security-ML baseline. The 22 vs 18 result is not a new algorithm.
- The dashboard is a competent React/FastAPI CRUD-and-charts app, not a novel interface.
- The similarity page is a nearest-neighbour list, not a full graph/network visualization.
- The deterministic "DNA" extraction is regex-based; calling it Granite intelligence would be wrong,
  and the project correctly does not.

## 3. Strongest discovery

**33/52 blind spot; 7 recovered.** It is simple enough to explain in one sentence and directly changes
how a security team should allocate a 20-patch budget. The second strongest is the correction itself:
the initial 24-hit claim was contaminated by 14 already-exploited CVEs.

## 4. Strongest technical contribution

The leakage-safe temporal construction: as-of monthly vendor priors, a nested KEV reference set for
Granite similarity, month-grouped folds inside 2024, and a held-out nine-month 2025 pool that mirrors
the benchmark. The cohort fix is part of that contribution because it shows the evaluation is not
decorative.

## 5. Strongest IBM contribution

The Granite embedding model is genuinely used: 160,577 descriptions embedded, 384-d vectors, cosine
similarity to prior KEV entries as a feature, and the same matrix powering the similar-CVE endpoint.
The controlled ablation moves the both-Granite blend from 16 to 20 hits@500. That is real, measurable
and reproducible.

The weakness is equally clear: no watsonx.ai, no Granite instruct model, no generative analyst. The
project says so on every relevant screen and API field. A judge who wants a generative IBM assistant
will mark this down.

## 6. Biggest weaknesses

1. **No 2026 answer key** — the headline 2026 performance is unknown.
2. **22 vs 18 is not statistically decisive** on 52 positives; the interval overlaps.
3. **Granite is embeddings only**, not the instruction/extraction stack the brief imagined.
4. **No browser verification** in this environment.
5. **Product exposure is vendor-level**, not an asset inventory.
6. **Frontend has no unit/e2e suite**.
7. **Residual NIST-review tilt** remains: 56.2% Analyzed, 0.2% blank severity, 0.4% blank CWE.
8. **Descriptions can be edited after publication**, a small leak-adjacent risk.
9. **Single 732 kB JS chunk**, no code splitting.

## 7. Questions judges may ask

| Question | Honest answer |
| :-- | :-- |
| Is 22 vs 18 significant? | Not on its own. Intervals overlap. The stronger claims are P@50 0.24 vs 0.08 and AP 2.5×. |
| Did you use future data? | No KEV feature; as-of priors; nested Granite reference set; 2026 never fitted. The audit found and removed 14 already-KEV candidates. |
| Is this really Granite? | Yes for embeddings, locally via public weights. No for generation/extraction; those are deterministic and labelled. |
| Why no watsonx? | No IBM Cloud account. The swap path is documented; no fake API was substituted. |
| Why does the top 500 have so many July 21 rows? | A date/vendor prior; 63/500 from one batch. It is a documented concentration, not a correctness claim. |
| Could the model just be ranking reviewed CVEs? | It no longer uses review-status/CWE-missingness, but a residual tilt remains (56.2% Analyzed) and is reported. |
| What would you do with more time? | Browser test, Granite instruct with grounded JSON schema, version-level product inventory, proper calibration and a larger positive pool. |

## 8. Evidence for major claims

- 22/52: `artifacts/model_selection.json` held-out rows; `eval/backtest.py`.
- 33/52 and 7/33: `artifacts/gap_analysis.json`; `docs/DISCOVERIES.md`.
- Granite ablation: `artifacts/granite_ablation.json`; `docs/IBM_INTEGRATION.md`.
- Cohort fix: `pipeline/features.py`; `tests/test_pipeline.py::test_labels_only_count_future_additions`.
- Top 500: `top500.csv` md5 and two pipeline tests.
- API: 18 routes, 21/21 live checks.
- Build: Vite exit 0; 732 kB bundle warning.

## 9. What could prevent this from winning

- The 2026 leaderboard result is unknown, and the historical lead is modest.
- A judge comparing Granite usage to a team with a real watsonx generative assistant may see this as
  incomplete IBM integration, even though it is honest.
- The product is broad but not visually verified; a broken layout on the judge's screen would hurt
  Communication (25%).
- The discovery is a negative/omission result, not a new predictive mechanism; it needs a crisp demo
  to land.
- The residual review-status tilt is a legitimate methodological criticism.

## Score, out of 10

| Criterion | Score | Why |
| :-- | --: | :-- |
| Discovery | 7.5 | Real blind-spot finding with intervals; not a new algorithm; 52-positive pool. |
| Data science | 8.5 | Strong leakage discipline and honest correction; small positives and residual tilt. |
| IBM integration | 6.5 | Genuine embeddings and measured ablation; no watsonx/instruct/generative assistant. |
| Technical implementation | 8.0 | Working API, UI, tests, startup; some O(n) paths and no frontend test harness. |
| Frontend / UX | 7.5 | Coherent enterprise layout and real data; not browser-verified; single bundle. |
| Communication | 8.5 | Docs are unusually candid and evidence-linked; demo video not recorded. |
| Real-world impact | 7.5 | The 20-patch framing is useful; vendor-only exposure and 2026 uncertainty limit it. |
| **Overall competition potential** | **7.6** | A defensible, working, honest submission with one strong finding and a real IBM limitation. |
