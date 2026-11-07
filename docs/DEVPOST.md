# Devpost submission draft

## Project name

Before the Breach — exploit-aware vulnerability prioritisation

## Tagline

Rank 72,670 CVEs by what attackers will actually exploit, not by how scary the score looks.

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
model finds 8 of those 33. They are mostly products with a KEV history but no public exploit code at
snapshot time: exactly the case a severity-plus-EPSS pipeline is blind to, and exactly the case that
gets an organisation breached.

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

- 24 of 52 held-out exploited CVEs in the top 500, against 18 for the strongest baseline, with 2.5×
  the baseline's precision at 50 and 2.5× its average precision.
- A measured Granite ablation: the embedding features take the blend from 19 to 24 hits@500.
- A dashboard where every ranking is explainable from recorded evidence, with the explanation source
  labelled rather than implied.
- 18 executable tests covering label construction, feature as-of integrity, submission format and the
  API contract.

## What we learned

Severity is a description of damage, not a prediction of behaviour. The strongest single signal is an
interaction: a dangerous weakness class *combined with* public exploit code. Vendor history and
description semantics catch the tail that the interaction misses.

## What's next

Wire a KEV-refresh loop so the model retrains monthly as new confirmations land; add asset context so
the same score can be re-ranked per customer environment; move explanations to a Granite instruct
model behind a caching layer once GPU capacity is available.

## Built with

Python, pandas, scikit-learn, LightGBM-style gradient boosting, IBM Granite embeddings,
sentence-transformers, FastAPI, React, TypeScript, Vite, Recharts, pytest.

## Demo script (3 minutes)

1. **0:00 — the problem.** Two CVEs, both CVSS 9.8. One is on KEV, one was never touched. Show the
   base rate: fewer than 1 in 250.
2. **0:25 — the product.** Open the dashboard overview: 72,670 analysed, top-500 profile versus pool
   (EPSS 7.9× higher, exploit code in 57% of rows).
3. **1:00 — the ranking.** Search a vendor, open a CVE, read the evidence panel: which signals fired
   and what each contributed.
4. **1:45 — the proof.** Performance page: held-out table, bootstrap interval, blind-spot number
   (8 of 33 recovered), Granite ablation.
5. **2:30 — the deliverable.** `top500.csv`, 500 unique ids, reproducible in one command.
6. **2:45 — the honesty slide.** Unknown 2026 score, small positive count, KEV lag.
