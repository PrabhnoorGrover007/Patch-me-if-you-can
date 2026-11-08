"""How much of the conventional-ranking blind spot does the final model recover?

Scores the held-out Jan-Sep 2025 pool with the frozen model, builds the three baseline top-500
lists, and counts exploited CVEs that (a) no baseline finds and (b) the model does find.

Writes artifacts/gap_analysis.json
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import eval.backtest as bt

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"


def rank_pct(x: np.ndarray) -> np.ndarray:
    return pd.Series(np.nan_to_num(x, nan=-1.0)).rank(pct=True).to_numpy()


def main() -> None:
    bundle = joblib.load(ART / "model.joblib")
    blend = bundle["blend"]
    train = bt.load_train()
    vuln = pd.read_parquet(ART / "vulnerabilities.parquet", columns=["cve_id", "cwe_ids"])
    train = train.merge(vuln, on="cve_id", how="left")
    gpath = ART / "granite_features.parquet"
    if gpath.exists():
        gf = pd.read_parquet(gpath)
        train = train.merge(
            gf[gf["split"] == "train"][["cve_id", "granite_knn_max", "granite_knn_mean5"]],
            on="cve_id", how="left")

    # Held-out pool, scored by a model that never saw 2025 rows (blend weights fixed on 2024).
    tr24 = train[train.snapshot_month.str.startswith("2024")]
    pool = bt.make_pool(train, bt.POOL_2025)
    scores = {}
    for name, model in bundle["models"].items():
        model.fit(tr24[bundle["feature_sets"][name]], tr24["label_any"].to_numpy())
        scores[name] = model.predict_proba(pool[bundle["feature_sets"][name]])[:, 1]
    model_score = (1 - blend["w_b"]) * rank_pct(scores[blend["a"]]) + blend["w_b"] * rank_pct(scores[blend["b"]])

    tmp = pool[["cve_id", "y"]].copy()
    tmp["s"] = model_score
    model_top = set(pool["cve_id"].to_numpy()[bt.top_k_idx(tmp, "s")])

    base_tops = {}
    for name, cols in bt.BASELINE_KEYS.items():
        order = pool[["cve_id", "y", *cols]].copy()
        base_tops[name] = set(pool["cve_id"].to_numpy()[bt.top_k_idx(order, *cols)])

    union = set().union(*base_tops.values())
    positives = pool[pool["y"] == 1]
    missed = positives[~positives["cve_id"].isin(union)]
    recovered = missed[missed["cve_id"].isin(model_top)]

    out = {
        "pool": "Jan-Sep 2025 (held-out)",
        "candidates": int(len(pool)),
        "positives": int(len(positives)),
        "model_top500_hits": len({p for p in positives["cve_id"] if p in model_top}),
        "baseline_union_hits": len({p for p in positives["cve_id"] if p in union}),
        "missed_by_all_baselines": int(len(missed)),
        "missed_but_recovered_by_model": int(len(recovered)),
        "recovered_ids": recovered["cve_id"].tolist()[:40],
        "overlap_with_baseline_union": len(model_top & union),
        "recovered_examples": recovered.head(8)[
            ["cve_id", "snapshot_month", "cvss3", "epss", "vendor_key", "cwe_ids"]
        ].to_dict("records"),
    }
    (ART / "gap_analysis.json").write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps({k: v for k, v in out.items() if k not in {"recovered_ids", "recovered_examples"}}, indent=2))


if __name__ == "__main__":
    main()
