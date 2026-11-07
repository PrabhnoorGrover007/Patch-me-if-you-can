# Data + ML pipeline: how to run it and how it works

Owner: Zahan (data engineering + ML). Teammates' dashboard and Granite code read
`outputs/ranked_2026.csv` and don't need to run anything here.

## Run it (Windows PowerShell, repo root)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Expand-Archive -Path C:\path\to\data.zip -DestinationPath . -Force   # creates .\data\*.csv

python prepare_data.py --data-dir data         # about 1 minute
python model.py                                # about 10 seconds
python validate_outputs.py                     # must end with "ALL CHECKS PASSED"
python -m unittest discover -s tests -v        # unit tests, no data needed
```
If PowerShell blocks `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

## What each step does

### 1. `prepare_data.py`: raw CSVs to two clean tables
1. **Load only what we need.** It reads selected columns from `vulnerabilities.csv` in chunks, the KEV
   list, and the 2024/2025 monthly signal files. It doesn't read `references.csv` or
   `affected_products.csv`.
2. **Pick a "photo date" (the snapshot) for each CVE.** That's the end of the month it was published,
   the same rule the 2026 scoreboard uses. February 2025 uses March, because the February signal
   file is missing many CVEs.
3. **Attach what was known on that date.** That's the EPSS score and the four public-exploit flags
   from that month's signal file. A missing row means EPSS 0 and flags 0, matching the scoreboard.
4. **Remove CVEs already on KEV by then.** The scoreboard doesn't contain them, so we don't train on
   them either.
5. **Create the label.** It's 1 if CISA added the CVE to KEV after the photo date and by
   2025-12-31, otherwise 0.
6. **Engineer features.**
   - EPSS percentile within the month, which fixes the March 2025 EPSS model change.
   - Exploit-flag count and days since publication.
   - CVSS score plus the network, no-login and no-click flags. A blank score becomes 7.5, with no
     "was blank" flag, because blanks reveal NIST review status.
   - 14 description keyword flags.
   - How many KEV entries the vendor and the assigning organization had **before** that month.
7. **Validate and save.** The script checks row counts, unique IDs, no blanks and no banned
   columns. Then it writes `outputs/train.csv` and `outputs/predict_2026.csv`. The exact schema is
   in `docs/data_contract.md`.

### 2. `model.py`: learn, check, rank
1. **Honest test.** It trains on 2024 CVEs and tests on 2025 CVEs. Splitting by time means the model
   never sees the future.
2. **Compare.** It scores logistic regression, gradient boosting and simple rankings (CVSS, EPSS,
   exploit flags then EPSS, and a hand-made rule) on the same 2025 rows. The measure is Hits@K:
   how many truly exploited CVEs land in the top K.
3. **Pick and retrain.** The model with the most hits in the top 274 (the same 0.69% share as the
   top 500 of the scoreboard) wins. It's retrained on all history, then scores the 72,670
   scoreboard CVEs.
4. **Write outputs.**
   - `ranked_2026.csv`: every CVE with its rank, score, plain-English risk factors and description.
   - `top500.csv`: the submission.
   - `validation_results.json`: every number above.
   If training fails, the hand-made rule ranks instead, and the output is labelled as a baseline.

### 3. `validate_outputs.py`: end-to-end checks
It re-derives every label from the raw KEV file and checks the 72,670 rows and the 500 unique
scoreboard CVEs. It also confirms no banned columns, valid dates and finite scores, and that
re-running the model gives the same top 500.

## What the risk score is (and isn't)
It's a **ranking score**: higher means "fix first". It isn't a calibrated probability of
exploitation.
