"""Ablation: does the IBM Granite similarity feature help, and by how much?

Every comparison trains on the 2024 cohorts and scores the held-out Jan-Sep 2025 pool.
The out-of-fold (2024) columns are the selection signal; the held-out columns are reported
for transparency, not used to fit anything.

Writes artifacts/granite_ablation.json
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

import eval.backtest as bt
from models.train import CANDIDATES, load_data, rank_pct
from models.train import pool_hits

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"


def main() -> None:
    train, sets = load_data()
    if not sets["core_g"] or sets["core_g"][-1] not in train.columns:
        print("granite features unavailable")
        return
    m24 = train.snapshot_month.str.startswith("2024").to_numpy()
    tr24 = train[m24]
    pool = bt.make_pool(train, bt.POOL_2025)

    scores = {}
    for name in ["histgb_lean", "histgb_lean_g", "logit_core", "logit_core_g"]:
        fn, set_name = CANDIDATES[name]
        model = fn()
        model.fit(tr24[sets[set_name]], tr24["label_any"].to_numpy())
        scores[name] = model.predict_proba(pool[sets[set_name]])[:, 1]

    rows = []
    for name, s in scores.items():
        row = bt.score_summary(pool, s, name)
        rows.append({k: row[k] for k in ("model", "hits@500", "precision@50",
                                          "average_precision", "roc_auc")})
        print(f"  {name:16s} @500={row['hits@500']:3d} P@50={row['precision@50']:.3f} "
              f"AP={row['average_precision']:.3f}")

    blends = []
    for a, b, tag in [("histgb_lean", "logit_core", "no_granite"),
                      ("histgb_lean_g", "logit_core_g", "granite")]:
        for w in (0.2, 0.35, 0.5):
            s = (1 - w) * rank_pct(scores[a]) + w * rank_pct(scores[b])
            row = bt.score_summary(pool, s, f"{tag}_w{w}")
            blends.append({"models": f"{a}+{b}", "uses_granite": tag == "granite", "w": w,
                           "hits@500": row["hits@500"], "precision@50": row["precision@50"],
                           "average_precision": row["average_precision"]})
            print(f"  blend {tag:11s} {a}+{b} w={w:.2f} @500={row['hits@500']:3d} "
                  f"P@50={row['precision@50']:.3f} AP={row['average_precision']:.3f}")

    (ART / "granite_ablation.json").write_text(json.dumps(
        {"pool": "Jan-Sep 2025 held-out", "single_models": rows, "blends": blends}, indent=2))


if __name__ == "__main__":
    main()
