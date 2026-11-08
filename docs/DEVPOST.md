# Devpost submission draft

## Project name

PATCH ME IF YOU CAN — exploit-aware vulnerability prioritisation

## Tagline

Rank 72,670 CVEs by what attackers will actually exploit, not by how scary the score looks.

**Code repository:** https://github.com/PrabhnoorGrover007/Patch-me-if-you-can — the IBM-track solution
lives in `ml-ranking/` on branch `feature/ml-ranking-solution`; `main` holds the team's other track.
**Submission file:** `top500.csv` — 500 unique `cve_id` values, one column, attached to this submission.

## Inspiration

Every security team we have spoken to runs the same triage: sort by CVSS, work down the list until
the queue is unmanageable, then start guessing. The data says that sort order is close to useless for
the only question that matters — will anyone attack this? In our corpus, fewer than 1 in 250
published vulnerabilities is ever confirmed exploited, and severity does not tell you which one. We
wanted to build the ranking an analyst would actually trust, and be honest about how much better it
is.

## What it does

It scores every CVE in the 2026 benchmark and produces `top500.csv`: the 500 vulnerabilities most
likely to be added to CISA's Known Exploited Vulnerabilities list, using only information available
at each CVE's snapshot month. Alongside it, a dashboard lets an analyst search the full ranking, open
any CVE and read *why* it scored where it did — EPSS at snapshot, public exploit code, weakness class,
vendor history, and how close its description sits to vulnerabilities already being exploited.

## How we built it

A four-stage pipeline: data preparation, as-of feature engineering, model selection with month-grouped
cross-validation, then scoring. The ranker blends gradient boosting with an L2 logistic model on
rank-averaged scores. IBM Granite embeddings (`granite-embedding-30m-english`, run locally on CPU)
turn each description into a vector so we can measure semantic similarity to previously exploited
CVEs — a signal no structured field carries. The dashboard is React + TypeScript on a FastAPI backend.

## The finding we are proudest of

We measured what the standard rankings miss. On the held-out pool, **33 of 52 exploited CVEs appear
in none of the three baseline top 500 lists** — not CVSS, not EPSS, not exploit-first-then-EPSS. Our
model finds 7 of those 33. They are mostly products with a KEV history but no public exploit code at
snapshot time: exactly the case a severity-plus-EPSS pipeline is blind to, and exactly the case that
gets an organisation breached.

## Which columns we used — and which we refused

The brief warns that the NIST files are today's versions, so some fields were filled in after attacks
happened. We split the data on that basis.

**Used:** description text, CVSS 3/2/4 numeric fields and vector components, `cwe_ids`, `assigner`,
`published`, `snapshot_month`; EPSS and exploit flags from `exploit_signals_*` dated at or before the
row's `snapshot_month`; KEV `date_added` — as *history* when it predates the snapshot month end, as
*the label* only when it comes strictly after it.

**Refused, with reasons:**

- `nvd_status`, `n_affected_cpes`, `n_references` — their presence mostly encodes whether NIST has
  reviewed the CVE, and NIST reviews attacked CVEs first. Using them imports the answer.
- Blank-severity as a signal, and CWE missingness (`cwe_missing`, CWE dummies) — the same leak
  wearing a different hat. Both were removed after an independent review showed the model was
  selecting only reviewed records.
- `references.csv` links and tags (patch / exploit / advisory / news) — attached after publication,
  and 37,853 of them point at IBM X-Force Exchange.
- CPE product strings — 49.6% are blank in 2026 for attention-related reasons, so product identity
  would carry the same bias.

Every exclusion and its rationale is tabulated in `docs/FEATURE_AUDIT.md`, and
`tests/test_pipeline.py::test_kev_never_used_as_feature` asserts that no KEV column reaches the model.

## Data sources and links

- **Organiser dataset** (`data.zip`, supplied with the challenge, not redistributed in the repo): NVD
  mirror `fkie-cad/nvd-json-data-feeds` (6 Nov 2026), CISA KEV to 2025-12-29, FIRST EPSS, public
  exploit flags from `t0sche/cvss-bt`, MITRE CWE 4.14.
- CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS — https://www.first.org/epss/
- NIST NVD — https://nvd.nist.gov/ (mirror: https://github.com/fkie-cad/nvd-json-data-feeds)
- MITRE CWE — https://cwe.mitre.org/
- t0sche/cvss-bt exploit flags — https://github.com/t0sche/cvss-bt
- IBM Granite embedding model — https://huggingface.co/ibm-granite/granite-embedding-30m-english

No other outside data was used.

## Challenges

- **The label is the hard part.** KEV `date_added` must be compared to the *end* of each snapshot
  month, and 62 KEV records predate their CVE's publication, so they had to be filtered rather than
  counted as hits.
- **Leakage hides in metadata.** Columns like NVD review status, CPE counts and reference counts look
  like features but mostly encode how much attention a CVE received — which is itself a precursor to
  exploitation. We excluded them and documented why.
- **Small positive counts.** With 52 positives in a nine-month pool, a one-hit difference is noise.
  Every claim in our writeup is paired with a bootstrap interval, and where the interval overlaps the
  baseline we say so instead of claiming a win.
- **No cloud account.** watsonx.ai was unavailable, so we ran the Granite embedding model locally via
  its public weights and kept the feature contract identical to what a watsonx call would produce.

## Accomplishments

- 22 of 52 held-out exploited CVEs in the top 500, against 18 for the strongest baseline, with 3.0x
  the baseline's precision at 50 and 2.5x its average precision.
- A measured Granite ablation: in the controlled comparison, the embeddings take the both-Granite
  blend from 16 to 20 hits@500; the shipped mixed blend reaches 22.
- A correction we are not hiding: an independent review found NIST-review leakage in the first model,
  and a follow-up audit removed 14 already-KEV rows from the candidate cohort. The rebuilt model scores
  22; the earlier 24 came from the contaminated candidate population. The correction is published in
  `docs/MODEL_EVALUATION.md` rather than buried.
- A dashboard where every ranking is explainable from recorded evidence, with the explanation source
  labelled rather than implied.
- A feature gate fixed before evaluation: four candidate features raised the single model but cost the
  shipped blend 2 held-out hits, so they were reverted and the negative result is published in
  `docs/MODEL_EVALUATION.md` instead of being quietly dropped.
- 22 executable tests covering label construction, feature as-of integrity, submission format and the
  API contract.

## What we learned

Severity is a description of damage, not a prediction of behaviour. The strongest single signal is EPSS *combined with* public exploit code; vendor history and
description semantics catch the tail. A weakness-class feature looked strong until we noticed it was
learning whether NIST had reviewed the record, so it had to go.

## What we corrected after an independent review

A second team reviewed this submission. Three of its criticisms were correct, and we fixed them rather
than defending the first version.

- **NIST-review leakage.** The first model kept blank CVSS as `NaN` (a tree splits on that) and shipped
  `cwe_missing` plus CWE dummies. Because NIST reviews attacked CVEs first, "blank" meant "not reviewed
  yet": our top 500 had 0.0% blank-severity rows against an 8.7% pool, and every training row with a
  blank score or blank CWE was a negative. Those features are gone and severity is imputed.
- **Selection leakage.** The 2024 out-of-fold score came from folds fitted on 2024-2025, so selection
  saw a year of future data. Folds now live inside 2024.
- **Weight chosen on a noisy cut-off.** hits@500 on 67 positives is about +/-4; the rule now breaks the
  tie on hits@100, which keeps the blend at the weight shipped before the correction.

Two claims did not survive checking, and we record that too: the alleged 15-15 tie does not reproduce
under our label definition, and the list was not chosen from 2026 outcomes - `top500.csv` predates the
2026 scoring code. The correction is not complete: the rebuilt list is 0.2% blank-severity, 0.4% blank-CWE and
56.2% NIST-Analyzed against a roughly 43% base rate, so a residual review-status tilt survives. We report it as a
limitation instead of claiming the list is clean.

## Built with

Python, pandas, scikit-learn, LightGBM-style gradient boosting, IBM Granite embeddings,
sentence-transformers, FastAPI, Next.js, React, TypeScript, Tailwind, Recharts, pytest.

## Demo video (2–3 minutes)

**Video link:** _paste the recorded URL here before submitting._ Shot list, cuts, fallback and Q&A prep
are in [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md); the beats are:

1. **0:00 — the problem.** Two CVEs, both CVSS 9.8. One is on KEV, one was never touched. Show the
   base rate: fewer than 1 in 250.
2. **0:25 — the product.** Open the dashboard overview: 72,670 analysed, top-500 profile versus pool
   (EPSS 8.7× higher, exploit code in 69.2% of rows).
3. **1:00 — the ranking.** Search a vendor, open a CVE, read the evidence panel: which signals fired
   and what each contributed.
4. **1:45 — the proof.** Performance page: held-out table, bootstrap interval, blind-spot number
   (7 of 33 recovered), Granite ablation.
5. **2:30 — the deliverable.** `top500.csv`, 500 unique ids, reproducible in one command.
6. **2:45 — the honesty slide.** Unknown 2026 score, small positive count, KEV lag.
