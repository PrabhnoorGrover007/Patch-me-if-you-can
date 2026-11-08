"""
timemachine.py - export the 2025 replay data for the web app's Time Machine and Patch Budget pages.

It repeats model.py's historical check exactly (train on 2024 cohorts, rank the 2025 cohorts) and
records, for each ranking method, where every 2025 CVE landed and when CISA added it to KEV.
Nothing here is tuned: same features, same model settings, same baselines as model.py.

    in : outputs/train.csv (from prepare_data.py), data/known_exploited.csv
    out: app/src/data/timemachine.json

Safety check: Hits@K recomputed here must equal outputs/validation_results.json, or it stops.

Usage (PowerShell):
    python timemachine.py --data-dir data
"""

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from model import MODELS, TOP_N, VALIDATION_START, baseline_scores, risk_factors
from prepare_data import FEATURE_COLUMNS

# (key in validation_results.json, group there, label shown in the app)
METHODS = [
    ("logistic_regression", "models", "Our model (submitted)"),
    ("exploit_flags_then_epss", "baselines", "Exploit code, then EPSS"),
    ("epss_first", "baselines", "EPSS score first"),
    ("cvss_first", "baselines", "Severity score (CVSS) first"),
]
LIST_LEN = TOP_N  # the replay shows each method's top 500


def ranks_from(score):
    # Same ordering as model.hits_at_k: descending score, stable on ties (row order)
    order = np.argsort(-np.asarray(score, dtype=float), kind="stable")
    ranks = np.empty(len(order), dtype=int)
    ranks[order] = np.arange(1, len(order) + 1)
    return ranks


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", default="data")
    p.add_argument("--out-dir", default="outputs")
    p.add_argument("--app-out", default="app/src/data/timemachine.json")
    a = p.parse_args()
    out_dir = Path(a.out_dir)

    train = pd.read_csv(out_dir / "train.csv", dtype={"cve_id": str, "snapshot_month": str})
    fit = train[train.snapshot_month < VALIDATION_START]
    val = train[train.snapshot_month >= VALIDATION_START].reset_index(drop=True)
    y = val.label.to_numpy()

    scores = {}
    model = MODELS["logistic_regression"]().fit(fit[FEATURE_COLUMNS], fit.label)
    scores["logistic_regression"] = model.predict_proba(val[FEATURE_COLUMNS])[:, 1]
    for k, s in baseline_scores(val).items():
        scores[k] = s.to_numpy()
    ranks = {k: ranks_from(scores[k]) for k, _, _ in METHODS}

    # Safety check against the team's published results
    report = json.loads((out_dir / "validation_results.json").read_text(encoding="utf-8"))
    for key, group, _ in METHODS:
        for k in (report["k_scaled"], TOP_N):
            mine = int(y[ranks[key] <= k].sum())
            theirs = report["validation"][group][key][f"hits_at_{k}"]
            if mine != theirs:
                raise SystemExit(f"Mismatch for {key} @ {k}: {mine} here vs {theirs} in validation_results.json")
    print("hit counts match validation_results.json")

    kev = pd.read_csv(Path(a.data_dir) / "known_exploited.csv", usecols=["cve_id", "date_added"])
    kev_date = dict(zip(kev.cve_id, kev.date_added))

    # Pool = every CVE that appears in any method's top 500, plus every attacked CVE
    in_pool = y == 1
    for key, _, _ in METHODS:
        in_pool |= ranks[key] <= LIST_LEN
    pool_idx = np.flatnonzero(in_pool)
    pos_in_pool = {int(i): n for n, i in enumerate(pool_idx)}

    pool = []
    for i in pool_idx:
        r = val.iloc[i]
        pool.append({
            "id": r.cve_id,
            "listed": r.snapshot_end[:10],          # end of publish month = when the list could include it
            "kev": kev_date.get(r.cve_id) if r.label == 1 else None,
            "cvss": round(float(r.cvss_score), 1),
            "why": risk_factors(r),
            "desc": str(r.description)[:280],
            "epss_pct": round(float(r.epss_pct_in_month), 3),   # EPSS percentile within its month
            "code": [n for n, f in (("Exploit-DB", r.exploitdb), ("Metasploit", r.metasploit),
                                    ("Nuclei", r.nuclei), ("GitHub PoC", r.poc_github)) if f],
            "ranks": {key: int(ranks[key][i]) for key, _, _ in METHODS},
        })

    lists = {}
    for key, _, _ in METHODS:
        top = np.argsort(ranks[key])[:LIST_LEN]
        lists[key] = [pos_in_pool[int(i)] for i in top]  # index into pool, in rank order

    out = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "train_period": report["train_period"],
        "validation_period": report["validation_period"],
        "pool_size": int(len(val)),
        "attacked_total": int(y.sum()),
        "k_scaled": report["k_scaled"],
        "label_cutoff": "2025-12-31",
        "methods": [
            {"key": key, "label": label,
             "hits_at_500": report["validation"][group][key]["hits_at_500"],
             "hits_at_k_scaled": report["validation"][group][key][f"hits_at_{report['k_scaled']}"]}
            for key, group, label in METHODS
        ],
        "pool": pool,
        "lists": lists,
        "sources": ["outputs/train.csv (prepare_data.py)", "data/known_exploited.csv (date_added)",
                    "outputs/validation_results.json (hit counts, checked)"],
    }
    Path(a.app_out).write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {a.app_out}: pool {len(pool)} CVEs, {int(y.sum())} attacked, "
          f"{Path(a.app_out).stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
