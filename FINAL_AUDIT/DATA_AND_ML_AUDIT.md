# Data and ML audit

## 1. Dataset integrity

| File | Rows | Audit result |
| :-- | --: | :-- |
| `vulnerabilities.csv` | 401,082 | 1988-10-01…2026-11-06; 72,670/72,670 scoreboard ids matched; descriptions 100%; published dates agreed |
| `affected_products.csv` | 3,155,934 | vulnerable-only aggregation; 324,005 CVEs with at least one vulnerable CPE |
| `references.csv` | 1,360,487 | summarised, never joined as features; 37,853 IBM X-Force links |
| `known_exploited.csv` | 1,484 | `date_added` 2021-11-03…2025-12-29; 62 pre-publication records excluded from lag analysis |
| monthly exploit signals | 6,463,734 | 24 months 2024-01…2025-12; February 2025 missing ~14,500 CVEs handled as `epss_missing` |
| `scoreboard_2026.csv` | 72,670 | 8 distinct snapshot months; June folds to July; all 2026 ids matched |
| `weakness_types.csv` | 1,374 | names only; used for display |

No raw file was edited. Joins were checked for row multiplication; signal rows were joined to the
vulnerability table, not the reverse. CVE ids are strings.

## 2. Target and the cohort bug

Target: `label_any = 1` iff a KEV `date_added` falls in `(snapshot_end, 2025-12-29]` for historical
cohorts, and after the snapshot for 2026. The 2026 outcome is not available.

The original filter used the monthly signal `in_kev` after filling absent rows with zero. A direct
join to the authoritative KEV date found **14 CVEs already on KEV at snapshot** that had no signal row
for that month. They were admitted as candidates and recorded as negatives. The corrected cohort
filters `kev_added <= snapshot_end` before labels are built:

- training rows: **87,907**
- positive labels: **122**
- excluded: **14**
- held-out pool: **35,280** candidates, **52** positives

This is the single most serious defect found in the audit because it changed the candidate population
and every evaluation metric. It is fixed and guarded by
`test_labels_only_count_future_additions`.

## 3. Leakage audit

| Signal | Finding | Action |
| :-- | :-- | :-- |
| NIST review status / blank severity | NIST reviews attacked CVEs first; blankness is a label proxy. The first top 500 had 0.0% blanks vs 8.7% pool | `nvd_status` excluded; every CVSS value median-imputed; no `has_cvss` flag |
| CWE missingness / CWE dummies | Same review-status leak; a multi-hot blank class is learnable | All CWE-derived model columns removed |
| `n_affected_cpes`, `n_references` | Grow with NVD attention | Excluded |
| Reference URLs/domains/tags | Added after publication | Excluded |
| `last_modified` | Every row is stamped after the snapshot | Excluded |
| CISA-ADP assigner GUID | ADP enrichment is post-publication | Collapsed to neutral |
| CPE product identity | 49.6% blank in 2026 for attention-related reasons | Excluded from model; vendor derived from assigner only |
| Granite KEV reference set | Naive nearest-KEV would include future additions | Reference set masked by `date_added <= snapshot_end` |
| Vendor KEV history | Naive full-history counts leak future KEV | Counts and rates recomputed as of each row's month end |
| Description edits | Minority of descriptions are edited later | Acknowledged as a lower-bound risk; no post-snapshot text is deliberately used |

Residual tilt: the final top 500 is **0.2% blank CVSS**, **0.4% blank CWE** and **56.2%
NIST-Analyzed**, down from 62.4% before the correction but above the roughly 43% pool rate. It is
documented, not eliminated.

## 4. Model results reproduced

Held-out Jan–Sep 2025, 35,280 candidates, 52 positives:

| Ranker | hits@500 | P@50 | P@100 | AP | ROC-AUC | bootstrap @500 |
| :-- | --: | --: | --: | --: | --: | :-- |
| CVSS | 5 | 0.06 | 0.04 | 0.00635 | 0.73215 | 2–11 |
| EPSS | 8 | 0.06 | 0.04 | 0.03092 | 0.70726 | 3–14 |
| PoC then EPSS | 18 | 0.08 | 0.08 | 0.04712 | 0.76803 | 10–27 |
| `histgb_lean` | 17 | 0.14 | 0.09 | 0.06029 | 0.83420 | 9–25 |
| `logit_core_g` | 20 | 0.08 | 0.09 | 0.05735 | 0.83506 | 11–28 |
| **Final blend** | **22** | **0.24** | **0.14** | **0.11916** | **0.84779** | **13–31** |

The 22-vs-18 lead is four hits on 52 positives; its bootstrap interval overlaps the baseline. The
stronger, less noisy claims are P@50 0.24 vs 0.08 and AP 0.119 vs 0.047.

**Baseline discrepancy explained.** `eval.backtest` prints CVSS/EPSS/PoC hits of 8/8/19, while
`model_selection.json` stores 5/8/18. The backtest adds EPSS and CVSS as secondary tie-break keys; the
selection table uses the primary key only. The final, audited table uses 5/8/18 (primary-key ordering).
Both scripts are deterministic; the discrepancy is a documented definition difference, not a data
corruption.

The competition's reference 7/6/8 is on a different pool; it is not directly comparable to 5/8/18.

## 5. Model selection honesty

Selected: `histgb_lean + logit_core_g`, `w_b = 0.8` on the Granite-augmented logistic model. 2024 OOF:
26 hits@500 / 18 hits@100. The pair's maximum @500 is 29 at `w_b=0.2`; the Granite preference rule
allows a two-hit tolerance (best pair 30, selected pair 29), then a noisy @100 tie-break chooses 0.8.
This is a documented judgment call, not a clean pre-registered win. Held-out 22 is confirmation, not
selection evidence.

## 6. Discovery validity

Nine findings in `artifacts/discoveries.json`; each has n and Wilson intervals where applicable.

- **Blind spot:** 33 of 52 held-out positives are missed by all three baselines' top 500; the model
  recovers 7. This is the strongest practical finding. The 33 figure is descriptive of this historical
  pool, not a universal rate.
- **Exploit code:** later KEV rate 0.09% (0 sources), 1.58% (1), 8.92% (2); 85,956 / 1,774 / 157 rows.
  Strong but covers only 2.5% of candidates.
- **EPSS:** monotone calibration but 99.9% of candidates below 0.10; an EPSS-only ordering is
  structurally limited.
- **CVSS:** CRITICAL 0.538% vs LOW 0.052% is a real ratio, but 99.5% of critical CVEs are never
  exploited.
- **CWE/description/vendor:** descriptive lifts are reported; CWE is not a model feature because of
  the review-status leak.
- **Granite similarity:** ROC-AUC 0.742 alone; independent text signal.

No discovery is presented as causal. The model comparison is the evidence; the discovery report does
not claim statistical significance where intervals overlap.

## 7. Reliability

- No random train/test split; every split is by month.
- 2026 rows never enter fitting, selection, weight choice or threshold choice.
- No threshold tuning on held-out; the deliverable is a ranking.
- Labels are right-censored at 2025-12-29, so late-2025 positives are under-counted.
- 122 positives / 52 held-out positives is small; all headline uncertainty is reported.

## Reproduce

```bash
python -m pipeline.prepare_data
python -m pipeline.features
python -m models.train
python -m models.predict
python -m eval.backtest
python -m eval.gap
python -m eval.granite_ablation
python -m pipeline.discoveries
pytest -q
```
