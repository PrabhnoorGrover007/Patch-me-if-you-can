# Demo script — 3 minutes

Target length 2:50, leaving 10 seconds of slack. Record at 1440×900 or larger with the browser zoom at
100%. Start the app with `bash start.sh` (or `start.bat`) and open <http://127.0.0.1:8000> **before**
you hit record, so the first frame is already loaded.

| Time | Screen | Say (paraphrase, do not read) |
| :-- | :-- | :-- |
| 0:00–0:20 | `/` overview | "Two CVEs, both CVSS 9.8. One is on CISA's exploited list, one was never touched. In this corpus fewer than 1 in 250 published vulnerabilities is ever confirmed exploited — so severity tells you how bad an attack *could* be, not whether anyone will attack." |
| 0:20–0:40 | overview stats row | "We scored all 72,670 CVEs in the 2026 benchmark. Our top 500 has 7.9× the pool's mean EPSS and public exploit code in 57% of rows, against a pool where most rows have neither." |
| 0:40–1:10 | Explorer, filter severity + search a vendor | "Here is the full ranking. It's searchable and filterable, and every row is linkable." Open one row. |
| 1:10–1:40 | CVE detail | "This is the part analysts actually need: why. EPSS at snapshot, exploit-code sources, weakness class, vendor history, and how close the description sits to CVEs already being exploited — with the contribution of each shown, and the explanation labelled as deterministic, not generated." |
| 1:40–2:15 | Performance | "Held-out proof: nine months the model never saw. We find 24 of 52 exploited CVEs in the top 500; the best conventional ranking finds 18, and 33 of the 52 appear in none of the three baselines' top 500s. We recover 8 of those 33. Precision at 50 is 2.5× the baseline's." |
| 2:15–2:35 | Performance, then Discoveries | "And the intervals are on screen. 52 positives is a small pool — our hits@500 interval is 14 to 33 and overlaps the baseline's — so we claim better precision and ordering, not a guaranteed margin." |
| 2:35–2:50 | terminal: `head top500.csv` | "The deliverable is one column, 500 unique IDs, all from the scoreboard, reproducible with one command. The 2026 score itself is unknown until judges run it." |

## Beats that must land

1. **The base rate** — most CVEs are never exploited, so severity-first wastes the budget.
2. **The blind spot** — 33 of 52 are invisible to CVSS, EPSS and exploit-first ranking.
3. **Explained rankings** — the evidence panel, not a black-box score.
4. **Honest intervals** — the model is better, and we say by how much and with what uncertainty.

## Cuts if you overrun

Drop the Explorer filter demo (0:40–1:10) to 15 seconds; keep the CVE detail and the blind-spot number.
Never cut the limitation beat — judges score communication, and overclaiming is the fastest way to lose it.

## Fallback if the live app fails on stage

The recording path is `/docs` (Swagger) plus the artefacts: `/api/model/performance` returns the same
held-out table, `/api/discoveries` the same findings, and `top500.csv` is on disk. Narrate the same
beats over those three responses; the numbers are identical.

## On-screen facts you may be asked about

| Question | Answer |
| :-- | :-- |
| Why not just use EPSS? | 99.9% of candidates sit below 0.10 at snapshot; it can only rank a tiny corner. |
| Is 24 vs 18 significant? | Intervals overlap (14–33 vs 10–27). We claim precision and ordering: P@50 0.20 vs 0.08, AP 2.5×. |
| Where does IBM tech enter? | Granite embeddings turn each description into a vector; similarity to already-listed KEV entries is a model feature. Ablation: 19 → 24 hits@500 when added. |
| Could you have leaked the answer? | No KEV field in the feature matrix, priors computed as-of each snapshot month, month-grouped splits, 2026 never used in fitting. |
| What is the 2026 score? | Unknown — the release has no 2026 answer key. Everything shown is historical validation. |
