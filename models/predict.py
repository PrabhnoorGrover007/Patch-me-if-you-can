"""Score the 2026 benchmark pool with the frozen model and emit the official submission.

Outputs
-------
top500.csv                  official artefact: exactly one column, 500 unique CVE ids
artifacts/ranked_2026.csv   ranked table consumed by the API and dashboard
artifacts/full_rankings.csv internal detail with component scores
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
K = 500


def rank_pct(x: np.ndarray) -> np.ndarray:
    return pd.Series(np.nan_to_num(x, nan=-1.0)).rank(pct=True).to_numpy()


def build_reasons(df: pd.DataFrame) -> pd.DataFrame:
    """Deterministic, data-grounded one-liners. No LLM, no invented evidence."""
    out = df.copy()
    pct = (out["epss_rank"].fillna(0) * 100).to_numpy()
    drivers, reasons = [], []
    for i, r in enumerate(out.itertuples(index=False)):
        d = []
        if pd.notna(r.epss) and r.epss >= 0.5:
            d.append(f"EPSS {r.epss:.2f} (top {max(1, round(100 - pct[i]))}% of its cohort)")
        elif pd.notna(r.epss) and r.epss >= 0.1:
            d.append(f"EPSS {r.epss:.2f} — elevated attack probability")
        elif getattr(r, "epss_missing", 0) == 1:
            d.append("no EPSS score at snapshot — unmeasured exposure")
        if getattr(r, "poc_github", 0) == 1:
            d.append("public proof-of-concept on GitHub at snapshot")
        if getattr(r, "metasploit", 0) == 1:
            d.append("Metasploit module available")
        elif getattr(r, "nuclei", 0) == 1:
            d.append("Nuclei detection template available")
        if pd.notna(r.vendor_kev_n) and r.vendor_kev_n >= 20:
            d.append(f"vendor already has {int(r.vendor_kev_n)} KEV entries in this window")
        if getattr(r, "kw_rce", 0) == 1:
            d.append("description indicates remote code execution")
        if getattr(r, "kw_auth_bypass", 0) == 1:
            d.append("description indicates an authentication bypass")
        if pd.notna(r.granite_knn_max) and r.granite_knn_max >= 0.70:
            d.append(f"description is semantically close to prior exploited CVEs (cos {r.granite_knn_max:.2f})")
        if not d:
            d.append("composite of severity, exposure and vendor history only")
        drivers.append("; ".join(d[:3]))
        reasons.append(d[0])
    out["driver_1"] = drivers
    out["reason"] = reasons
    return out


def main() -> None:
    bundle = joblib.load(ART / "model.joblib")
    models, blend = bundle["models"], bundle["blend"]
    predict = bt.load_predict()
    extra = pd.read_parquet(ART / "vulnerabilities.parquet",
                            columns=["cve_id", "cwe_ids", "cvss3_severity"])
    predict = predict.merge(extra, on="cve_id", how="left", validate="one_to_one")

    gpath = ART / "granite_features.parquet"
    if gpath.exists():
        gf = pd.read_parquet(gpath)
        gf = gf[gf["split"] == "predict"][["cve_id", "granite_knn_max", "granite_knn_mean5"]]
        predict = predict.merge(gf, on="cve_id", how="left", validate="one_to_one")
    else:
        predict["granite_knn_max"] = np.nan
        predict["granite_knn_mean5"] = np.nan

    scores = {}
    for name, model in models.items():
        scores[name] = model.predict_proba(predict[bundle["feature_sets"][name]])[:, 1]
    a, b = blend["a"], blend["b"]
    risk = (1 - blend["w_b"]) * rank_pct(scores[a]) + blend["w_b"] * rank_pct(scores[b])

    predict["vendor_kev_n"] = np.expm1(predict["vendor_kev_n_log"].fillna(0)).round()
    out = predict[["cve_id", "snapshot_month", "published", "cvss3", "cvss3_severity", "epss",
                   "epss_rank", "poc_github", "nuclei", "metasploit", "vendor_key",
                   "cwe_ids", "vendor_kev_n", "granite_knn_max",
                   "any_exploit", "kw_rce", "kw_auth_bypass", "age_days"]].copy()
    out["histgb_score"] = scores.get(a)
    out["logit_score"] = scores.get(b)
    out["risk_score"] = risk
    out["rank"] = out["risk_score"].rank(ascending=False, method="first").astype(int)
    out = out.sort_values("rank").reset_index(drop=True)
    out["risk_percentile"] = (1 - out["rank"] / len(out)).round(6)
    out["cwe_top"] = out["cwe_ids"].fillna("").str.split(";").str[0].replace("", "unknown")
    out = build_reasons(out)

    ranked = out[["cve_id", "rank", "risk_score", "risk_percentile", "snapshot_month", "published",
                  "cvss3", "cvss3_severity", "epss", "poc_github", "vendor_key", "cwe_top",
                  "reason", "driver_1"]].rename(columns={"cvss3": "cvss3_score",
                                                          "vendor_key": "vendor",
                                                          "epss": "epss_score"})
    ranked.to_parquet(ART / "ranked_2026.parquet", index=False)
    ranked.to_csv(ART / "ranked_2026.csv", index=False)

    full = out.copy()
    full.to_csv(ART / "full_rankings.csv", index=False)

    top = ranked.head(K)
    assert len(top) == K, f"expected {K} rows, got {len(top)}"
    assert top["cve_id"].is_unique, "duplicate CVE ids in top 500"
    board = set(pd.read_csv(ROOT / "data" / "scoreboard_2026.csv", usecols=["cve_id"])["cve_id"])
    unknown = set(top["cve_id"]) - board
    assert not unknown, f"ids not in scoreboard: {list(unknown)[:5]}"
    top[["cve_id"]].to_csv(ROOT / "top500.csv", index=False)

    summary = {
        "rows_scored": int(len(out)),
        "top500_unique": int(top["cve_id"].nunique()),
        "top500_snapshot_months": top["snapshot_month"].value_counts().sort_index().to_dict(),
        "top500_vendors": top["vendor"].value_counts().head(15).to_dict(),
        "top500_cwe": top["cwe_top"].value_counts().head(10).to_dict(),
        "top500_mean_epss": round(float(top["epss_score"].mean()), 4),
        "top500_poc_share": round(float(top["poc_github"].mean()), 4),
        "top500_mean_cvss": round(float(top["cvss3_score"].mean()), 3),
        "all_mean_epss": round(float(pd.to_numeric(out["epss"], errors="coerce").mean()), 4),
        "all_mean_cvss": round(float(pd.to_numeric(out["cvss3"], errors="coerce").mean()), 3),
    }
    (ART / "submission_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"\nwrote top500.csv (+ artifacts/ranked_2026.csv, full_rankings.csv)")


if __name__ == "__main__":
    main()
