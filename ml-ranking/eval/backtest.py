"""Backtest harness.

The official metric is: of the 500 highest-ranked CVEs in the benchmark pool, how many were
later added to KEV. `scoreboard_2026.csv` is one pool of 72,670 candidates covering
snapshots 2026-01 .. 2026-09. To imitate it we rebuild the same kind of pool from history:

    pool = CVEs published in months m1..m9, not in KEV at the end of month m,
           labelled 1 if CISA added them to KEV at any point after the end of month m.

Jan-Sep 2025 is the primary held-out pool: same nine-month shape, same snapshot logic, and
its outcome window (to 2025-12-29) is fully observed. Jan-Sep 2024 is the robustness pool.
Baselines are the three published in the problem statement.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"

K = 500
POOL_2024 = [f"2024-{m:02d}" for m in range(1, 10)]
POOL_2025 = [f"2025-{m:02d}" for m in range(1, 10)]
POOL_2026 = [f"2026-{m:02d}" for m in range(1, 10)]
TRAIN_2024 = [f"2024-{m:02d}" for m in range(1, 13)]


def load_train() -> pd.DataFrame:
    return pd.read_parquet(ART / "train.parquet")


def load_predict() -> pd.DataFrame:
    return pd.read_parquet(ART / "predict.parquet")


def make_pool(df: pd.DataFrame, months: list[str], label: str = "label_any") -> pd.DataFrame:
    pool = df[df["snapshot_month"].isin(months)].copy()
    pool["y"] = pool[label].astype("int8")
    return pool


def _order(df: pd.DataFrame, *cols: str) -> np.ndarray:
    """Deterministic multi-key descending sort, ties broken by cve_id."""
    work = df.copy()
    keys = []
    for c in cols:
        keys.append(-work[c].fillna(-1.0).to_numpy(dtype="float64"))
    keys.append(work["cve_id"].to_numpy())
    return np.lexsort(tuple(reversed(keys)))


def top_k_idx(df: pd.DataFrame, *cols: str, k: int = K) -> np.ndarray:
    return _order(df, *cols)[:k]


def hits_at_k(pool: pd.DataFrame, *cols: str, k: int = K) -> int:
    return int(pool["y"].to_numpy()[top_k_idx(pool, *cols, k=k)].sum())


def precision_at_k(pool: pd.DataFrame, score: np.ndarray, k: int) -> float:
    tmp = pool[["cve_id"]].copy()
    tmp["s"] = score
    idx = _order(tmp, "s")[:k]
    return float(pool["y"].to_numpy()[idx].mean())


def score_summary(pool: pd.DataFrame, score: np.ndarray, name: str) -> dict:
    tmp = pool[["cve_id", "y"]].copy()
    tmp["s"] = np.asarray(score, dtype="float64")
    tmp["s"] = tmp["s"].fillna(-1.0)
    out = {"model": name, "n_candidates": int(len(tmp)), "positives": int(tmp["y"].sum())}
    for k in (50, 100, 250, 500):
        out[f"precision@{k}"] = round(precision_at_k(tmp, tmp["s"].to_numpy(), k), 5)
    out["hits@500"] = int(precision_at_k(tmp, tmp["s"].to_numpy(), K) * K)
    out["recall@500"] = round(out["hits@500"] / max(int(tmp["y"].sum()), 1), 5)
    out["average_precision"] = round(float(average_precision_score(tmp["y"], tmp["s"])), 5)
    try:
        out["roc_auc"] = round(float(roc_auc_score(tmp["y"], tmp["s"])), 5)
    except ValueError:
        out["roc_auc"] = None
    return out


def bootstrap_hits(pool: pd.DataFrame, score: np.ndarray, k: int = K, n: int = 2000, seed: int = 0) -> dict:
    """Row-level bootstrap: resample candidates, re-rank, recount. Gives a 95% interval that
    reflects how much the hit count depends on a handful of CVEs."""
    rng = np.random.default_rng(seed)
    y = pool["y"].to_numpy()
    s = np.nan_to_num(np.asarray(score, dtype="float64"), nan=-1.0)
    n_rows = len(y)
    hits = np.empty(n, dtype="int32")
    for i in range(n):
        idx = rng.integers(0, n_rows, n_rows)
        sy = y[idx]
        ss = s[idx]
        top = np.argpartition(-ss, k - 1)[:k]
        hits[i] = sy[top].sum()
    return {
        "mean": round(float(hits.mean()), 2),
        "p2.5": int(np.percentile(hits, 2.5)),
        "p97.5": int(np.percentile(hits, 97.5)),
        "n": n,
    }


def baseline_scores(pool: pd.DataFrame) -> dict[str, np.ndarray]:
    """The three published baselines, with deterministic tie-breaks."""
    cvss = pool["cvss3"].fillna(-1.0).to_numpy(dtype="float64")
    epss = pool["epss"].fillna(-1.0).to_numpy(dtype="float64")
    exploit = pool["any_exploit"].fillna(0).to_numpy(dtype="float64")
    # A single scalar that encodes the documented ordering; ties are broken lexicographically
    # inside hits_at_k, so these need only reproduce the primary key.
    return {
        "cvss3_first": cvss,
        "epss_first": epss,
        "poc_then_epss": exploit * 1e6 + epss,
    }


BASELINE_KEYS = {
    "cvss3_first": ("cvss3", "epss"),
    "epss_first": ("epss", "cvss3"),
    "poc_then_epss": ("any_exploit", "epss", "cvss3"),
}


def run(pool: pd.DataFrame, scores: dict[str, np.ndarray], label: str) -> dict:
    rows = []
    for name, s in scores.items():
        row = score_summary(pool, s, name)
        row["bootstrap_hits@500"] = bootstrap_hits(pool, s)
        rows.append(row)
    return {"pool": label, "months": sorted(pool["snapshot_month"].unique().tolist()),
            "rows": rows}


def baseline_table(pool: pd.DataFrame) -> list[dict]:
    rows = []
    for name, cols in BASELINE_KEYS.items():
        tmp = pool[["cve_id", "y", *cols]].copy()
        hits = hits_at_k(tmp, *cols)
        rows.append({"model": name, "hits@500": hits,
                     "precision@500": round(hits / K, 5)})
    return rows


def per_month(pool: pd.DataFrame, score_col: str | None = None, scores: np.ndarray | None = None) -> list[dict]:
    rows = []
    for m, g in pool.groupby("snapshot_month"):
        if scores is None:
            hits = hits_at_k(g, score_col)
        else:
            tmp = g[["cve_id", "y"]].copy()
            tmp["s"] = scores[g.index]
            hits = hits_at_k(tmp, "s")
        rows.append({"month": m, "candidates": int(len(g)), "positives": int(g["y"].sum()),
                     "hits@500": hits})
    return rows


def main() -> None:
    train = load_train()
    results = {}
    for label, months in (("2025_jan_sep", POOL_2025), ("2024_jan_sep", POOL_2024)):
        pool = make_pool(train, months)
        base = baseline_table(pool)
        results[label] = {
            "candidates": int(len(pool)),
            "positives": int(pool["y"].sum()),
            "base_rate": round(float(pool["y"].mean()), 5),
            "baselines": base,
            "per_month_positives": pool.groupby("snapshot_month")["y"].sum().astype(int).to_dict(),
            "recall_at_500_ceiling": round(K / max(int(pool["y"].sum()), 1), 4),
        }
        print(f"\n== {label}: {len(pool):,} candidates, {int(pool['y'].sum())} positives "
              f"({pool['y'].mean():.3%})")
        for r in base:
            print(f"   {r['model']:16s} hits@500 = {r['hits@500']}")
    (ART / "backtest_baselines.json").write_text(json.dumps(results, indent=2))
    print("\nwrote artifacts/backtest_baselines.json")


if __name__ == "__main__":
    main()
