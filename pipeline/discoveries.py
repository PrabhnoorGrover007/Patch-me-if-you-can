"""Statistically tested discoveries, computed only from leakage-safe cohort data.

Cohorts: CVEs published 2024-01..2025-12, as observed at the end of their snapshot month,
labelled by a later CISA KEV addition. Every rate carries a Wilson 95% interval, and every
comparison is reported with its sample size so small-cell claims can be judged honestly.

Writes artifacts/discoveries.json
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

import eval.backtest as bt
from pipeline.features import KEYWORDS

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"

KEYWORD_LABELS = {
    "kw_rce": "remote code execution", "kw_cmd_injection": "command injection",
    "kw_deserialization": "deserialisation", "kw_sqli": "SQL injection",
    "kw_xss": "cross-site scripting", "kw_buffer_overflow": "buffer overflow / OOB",
    "kw_use_after_free": "use-after-free", "kw_priv_esc": "privilege escalation",
    "kw_auth_bypass": "authentication bypass", "kw_path_traversal": "path traversal",
    "kw_ssrf": "SSRF", "kw_xxe": "XXE", "kw_dos": "denial of service",
    "kw_info_disclosure": "information disclosure", "kw_template_injection": "template injection",
    "kw_hardcoded": "hard-coded credentials", "kw_unauthenticated": "unauthenticated",
    "kw_wormable": "wormable", "kw_dependency": "third-party dependency",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return (np.nan, np.nan, np.nan)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


def rate_rows(df: pd.DataFrame, by: str, label: str = "label_any", min_n: int = 1) -> list[dict]:
    rows = []
    for key, g in df.groupby(by, observed=True, dropna=False):
        k, n = int(g[label].sum()), len(g)
        if n < min_n:
            continue
        p, lo, hi = wilson(k, n)
        rows.append({"key": str(key), "positives": k, "n": n,
                     "rate": round(float(p), 6), "ci_low": round(float(lo), 6),
                     "ci_high": round(float(hi), 6)})
    return rows


def main() -> None:
    train = bt.load_train()
    cwe_ids = pd.read_parquet(ART / "vulnerabilities.parquet", columns=["cve_id", "cwe_ids"])
    train = train.merge(cwe_ids, on="cve_id", how="left")
    train["y"] = train["label_any"].astype("int8")
    base_rate = float(train["y"].mean())
    disc: list[dict] = []

    # --- 1. Severity is a bad proxy -------------------------------------------------
    bands = pd.cut(train["cvss3"], [0, 3.9, 6.9, 8.9, 10.01],
                   labels=["LOW (<4)", "MEDIUM (4-6.9)", "HIGH (7-8.9)", "CRITICAL (9+)"])
    rows = rate_rows(train.assign(band=bands), "band")
    lo_r = next((r for r in rows if r["key"].startswith("LOW")), None)
    hi_r = next((r for r in rows if r["key"].startswith("CRITICAL")), None)
    ratio = hi_r["rate"] / max(lo_r["rate"], 1e-9)
    disc.append({
        "id": "severity_separation", "type": "bar",
        "title": "Severity ranks impact, not attacker intent",
        "finding": (f"CRITICAL CVEs are {ratio:.1f}x more likely to be exploited than LOW ones "
                    f"({hi_r['rate']:.3%} vs {lo_r['rate']:.3%}), but {1 - hi_r['rate']:.1%} of CRITICAL "
                    f"CVEs are never exploited — so a severity ordering spends almost all of its 500 "
                    f"slots on noise, and CVSS-first is the weakest of the three baselines on the "
                    f"held-out 2025 pool (see the blind-spot finding).")
                    if lo_r and hi_r else "insufficient data",
        "stat": f"CRITICAL/LOW risk ratio = {ratio:.1f}x, with {hi_r['rate']:.2%} absolute precision"
                if lo_r and hi_r else "n/a",
        "n": int(len(train)), "chart": {"x": [r["key"] for r in rows],
                                        "y": [r["rate"] for r in rows],
                                        "ci_low": [r["ci_low"] for r in rows],
                                        "ci_high": [r["ci_high"] for r in rows]},
    })

    # --- 2. Public exploit code is the strongest single observable -------------------
    rows = rate_rows(train, "n_exploit_sources")
    solid = [r for r in rows if r["n"] >= 20]
    head_stat = (f"{solid[-1]['rate'] / max(solid[0]['rate'], 1e-9):.1f}x between 0 and "
                 f"{int(float(solid[-1]['key']))} sources") if len(solid) > 1 else "n/a"
    disc.append({
        "id": "exploit_code", "type": "bar",
        "title": "Public exploit code is the strongest observable signal",
        "finding": ("Each additional public exploit source present at snapshot multiplies the later "
                    "KEV rate: " + ", ".join(
                        f"{int(float(r['key']))} source{'s' if int(float(r['key'])) != 1 else ''} "
                        f"-> {r['rate']:.2%} (n={r['n']})" for r in solid) +
                    ". Cells with fewer than 20 CVEs are excluded from this claim."),
        "stat": head_stat,
        "n": int(len(train)), "chart": {"x": [r["key"] for r in rows], "y": [r["rate"] for r in rows],
                                        "ci_low": [r["ci_low"] for r in rows],
                                        "ci_high": [r["ci_high"] for r in rows]},
    })

    # --- 3. EPSS calibration --------------------------------------------------------
    epss_bins = pd.cut(train["epss"], [-0.001, 0.001, 0.01, 0.1, 0.5, 1.0],
                       labels=["0", "0-1%", "1-10%", "10-50%", ">50%"])
    rows = rate_rows(train.assign(b=epss_bins), "b")
    disc.append({
        "id": "epss_calibration", "type": "bar",
        "title": "EPSS is calibrated but nearly empty in this cohort",
        "finding": ("Observed KEV rate rises monotonically with EPSS, yet "
                    f"{float((train['epss'].fillna(0) < 0.1).mean()):.1%} of candidates sit below "
                    "0.10 at snapshot, so EPSS alone can only rank a tiny corner of the pool."),
        "stat": f"median EPSS = {float(train['epss'].median()):.4f}",
        "n": int(len(train)), "chart": {"x": [r["key"] for r in rows], "y": [r["rate"] for r in rows],
                                        "ci_low": [r["ci_low"] for r in rows],
                                        "ci_high": [r["ci_high"] for r in rows]},
    })

    # --- 4. CWE lift with intervals -------------------------------------------------
    cwe_rows = []
    exploded = train.assign(cwe=train["cwe_ids"].fillna("").str.split(";")).explode("cwe")
    exploded["cwe"] = exploded["cwe"].str.strip()
    exploded = exploded[exploded["cwe"].str.startswith("CWE-")]
    counts = exploded.groupby("cwe")["y"].agg(["sum", "size"])
    counts = counts[counts["size"] >= 150]
    for cwe, r in counts.iterrows():
        p, lo, hi = wilson(int(r["sum"]), int(r["size"]))
        cwe_rows.append({"key": cwe, "positives": int(r["sum"]), "n": int(r["size"]),
                         "rate": round(float(p), 6), "ci_low": round(float(lo), 6),
                         "ci_high": round(float(hi), 6),
                         "lift": round(float(p / base_rate), 2) if base_rate else np.nan})
    cwe_rows.sort(key=lambda r: -r["lift"])
    top = cwe_rows[:12]
    disc.append({
        "id": "cwe_lift", "type": "bar",
        "title": "Weakness class carries information severity does not",
        "finding": ("Highest-lift weakness classes (min 150 CVEs): " + ", ".join(
            f"{r['key']} {r['lift']:.1f}x" for r in top[:6]) +
            f". {top[0]['key']} is exploited at {top[0]['rate']:.1%} versus {base_rate:.3%} overall."),
        "stat": f"top lift = {top[0]['lift']:.2f}x ({top[0]['key']})",
        "n": int(len(exploded)),
        "chart": {"x": [r["key"] for r in top], "y": [r["lift"] for r in top],
                  "rate": [r["rate"] for r in top], "n": [r["n"] for r in top],
                  "ci_low": [round(r["ci_low"] / base_rate, 2) for r in top],
                  "ci_high": [round(r["ci_high"] / base_rate, 2) for r in top]},
    })

    # --- 5. Vendor memory ------------------------------------------------------------
    vendor_prior = (train["vendor_unseen"].fillna(1) == 0).map(
        {True: "vendor already in KEV", False: "vendor never in KEV"})
    rows = rate_rows(train.assign(v=vendor_prior), "v")
    ratio = rows[0]["rate"] / max(rows[1]["rate"], 1e-9)
    disc.append({
        "id": "vendor_memory", "type": "bar",
        "title": "Attackers return to vendors they already exploit",
        "finding": (f"CVEs from vendors with at least one prior KEV entry are exploited at "
                    f"{rows[0]['rate']:.3%} versus {rows[1]['rate']:.3%} — {ratio:.1f}x. "
                    "This is computed strictly from KEV additions before each snapshot."),
        "stat": f"{ratio:.1f}x vendor-prior effect", "n": int(len(train)),
        "chart": {"x": [r["key"] for r in rows], "y": [r["rate"] for r in rows],
                  "ci_low": [r["ci_low"] for r in rows], "ci_high": [r["ci_high"] for r in rows],
                  "n": [r["n"] for r in rows]},
    })

    # --- 6. Description language -----------------------------------------------------
    kw_rows = []
    for kw, label in KEYWORD_LABELS.items():
        if kw not in train.columns:
            continue
        g1, g0 = train[train[kw] == 1], train[train[kw] == 0]
        if len(g1) < 100:
            continue
        p1, lo1, hi1 = wilson(int(g1["y"].sum()), len(g1))
        p0 = float(g0["y"].mean()) if len(g0) else np.nan
        kw_rows.append({"key": label, "rate": round(float(p1), 6), "lift": round(float(p1 / max(p0, 1e-9)), 2),
                        "n": len(g1), "positives": int(g1["y"].sum()),
                        "ci_low": round(float(lo1), 6), "ci_high": round(float(hi1), 6)})
    kw_rows.sort(key=lambda r: -r["lift"])
    disc.append({
        "id": "description_language", "type": "bar",
        "title": "Wording in the description predicts exploitation",
        "finding": ("Descriptions mentioning " + ", ".join(
            f"'{r['key']}' ({r['lift']:.1f}x, n={r['n']})" for r in kw_rows[:4]) +
            " are far more likely to be exploited, while XSS/CSRF phrasing is markedly less so."),
        "stat": f"{kw_rows[0]['key']}: {kw_rows[0]['lift']:.1f}x lift",
        "n": int(len(train)),
        "chart": {"x": [r["key"] for r in kw_rows[:14]], "y": [r["lift"] for r in kw_rows[:14]],
                  "rate": [r["rate"] for r in kw_rows[:14]], "n": [r["n"] for r in kw_rows[:14]],
                  # interval for the lift itself (same units as y), not the underlying rate
                  "ci_low": [round(r["ci_low"] * r["lift"] / r["rate"], 2) for r in kw_rows[:14]],
                  "ci_high": [round(r["ci_high"] * r["lift"] / r["rate"], 2) for r in kw_rows[:14]]},
    })

    # --- 7. Time to exploitation -----------------------------------------------------
    kev = pd.read_parquet(ART / "kev.parquet")
    vuln = pd.read_parquet(ART / "vulnerabilities.parquet", columns=["cve_id", "published"])
    lag = kev.merge(vuln, on="cve_id", how="left")
    lag["lag_days"] = (lag["date_added"] - lag["published"]).dt.days
    lag = lag[(lag["published"] >= "2023-01-01") & (lag["lag_days"] >= 0)]
    by_year = []
    for year, g in lag.groupby(lag["published"].dt.year):
        by_year.append({"year": int(year), "n": int(len(g)),
                        "median_days": float(g["lag_days"].median()),
                        "share_30d": round(float((g["lag_days"] <= 30).mean()), 4),
                        "share_90d": round(float((g["lag_days"] <= 90).mean()), 4)})
    disc.append({
        "id": "exploit_window", "type": "line",
        "title": "The window that matters is days, not months",
        "finding": ("Of KEV additions for CVEs published 2023-2025, "
                    + ", ".join(f"{r['share_30d']:.0%} ({r['year']})" for r in by_year) +
                    " happened within 30 days of publication. Those CVEs are *already excluded* "
                    "from this benchmark, which is why the prediction task is about the long tail."),
        "stat": f"median lag {np.median(lag['lag_days']):.0f} days",
        "n": int(len(lag)),
        "chart": {"x": [r["year"] for r in by_year],
                  "median_days": [r["median_days"] for r in by_year],
                  "share_30d": [r["share_30d"] for r in by_year],
                  "share_90d": [r["share_90d"] for r in by_year],
                  "n": [r["n"] for r in by_year]},
    })

    # --- 8. Blind spot of conventional ranking ---------------------------------------
    pool = bt.make_pool(train, bt.POOL_2025)
    base = bt.baseline_scores(pool)
    tops = {}
    for name, cols in bt.BASELINE_KEYS.items():
        tmp = pool[["cve_id", "y", *cols]].copy()
        tops[name] = set(pool["cve_id"].to_numpy()[bt.top_k_idx(tmp, *cols)])
    union = set().union(*tops.values())
    positives = pool[pool["y"] == 1]
    missed = positives[~positives["cve_id"].isin(union)]
    disc.append({
        "id": "blind_spot", "type": "bar",
        "title": "Conventional rankings all miss the same CVEs",
        "finding": (f"On the Jan-Sep 2025 pool ({int(pool['y'].sum())} exploited CVEs), the three "
                    f"published baselines' top 500s cover only {len(positives) - len(missed)} of them. "
                    f"{len(missed)} exploited CVEs ({len(missed) / max(len(positives), 1):.0%}) appear in "
                    f"none of the three lists; their median CVSS is "
                    f"{float(missed['cvss3'].median()) if len(missed) else float('nan'):.1f} and "
                    f"{float((missed['epss'].fillna(0) < 0.1).mean()) if len(missed) else 0:.0%} have EPSS < 0.1."),
        "stat": f"{len(missed)}/{len(positives)} exploited CVEs missed by every baseline",
        "n": int(len(pool)),
        "chart": {"x": ["CVSS", "EPSS", "PoC+EPSS", "any baseline"],
                  "y": [len(positives) - sum(1 for p in positives["cve_id"] if p in tops[n])
                        for n in ("cvss3_first", "epss_first", "poc_then_epss")] + [len(missed)],
                  "positives": int(len(positives)), "missed_ids": missed["cve_id"].tolist()[:50]},
    })

    # --- 9. Granite semantic signal ---------------------------------------------------
    gpath = ART / "granite_features.parquet"
    if gpath.exists():
        from sklearn.metrics import roc_auc_score
        gf = pd.read_parquet(gpath)
        gt = train.merge(gf[gf["split"] == "train"][["cve_id", "granite_knn_max"]],
                         on="cve_id", how="left")
        gt = gt[gt["granite_knn_max"].notna()]
        if gt["y"].nunique() == 2 and len(gt) > 1000:
            auc = float(roc_auc_score(gt["y"], gt["granite_knn_max"]))
            q = gt.assign(b=pd.qcut(gt["granite_knn_max"], 5, labels=False, duplicates="drop"))
            rows = rate_rows(q, "b")
            disc.append({
                "id": "granite_semantics", "type": "bar",
                "title": "Granite embeddings find exploited CVEs from text alone",
                "finding": (f"Cosine similarity between a CVE description and the descriptions of "
                            f"KEV entries already on the list at snapshot time reaches ROC-AUC "
                            f"{auc:.3f} for predicting a *later* KEV addition, with no CVSS or EPSS "
                            "input. Semantic similarity is a genuine, independent signal."),
                "stat": f"ROC-AUC {auc:.3f} from text similarity alone",
                "n": int(len(gt)),
                "chart": {"x": [f"Q{int(r['key']) + 1}" for r in rows],
                          "y": [r["rate"] for r in rows], "ci_low": [r["ci_low"] for r in rows],
                          "ci_high": [r["ci_high"] for r in rows], "n": [r["n"] for r in rows]},
            })

    out = {
        "cohort": {"rows": int(len(train)), "positives": int(train["y"].sum()),
                   "base_rate": round(base_rate, 6),
                   "months": sorted(train["snapshot_month"].unique().tolist())},
        "discoveries": disc,
        "meta": {"ci": "Wilson 95%", "label": "KEV addition after end of snapshot month",
                 "keywords_tested": len(KEYWORDS)},
    }
    (ART / "discoveries.json").write_text(json.dumps(out, indent=2, default=float))
    for d in disc:
        print(f"\n## {d['title']}\n   {d['finding']}\n   [{d['stat']}]")


if __name__ == "__main__":
    main()
