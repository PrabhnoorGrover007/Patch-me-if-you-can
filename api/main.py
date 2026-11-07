"""BEFORE THE BREACH — FastAPI backend.

Every number served here comes from artefacts produced by the pipeline; nothing is mocked.
If an artefact is missing the API fails loudly with 503 instead of inventing data.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
WEB_DIST = ROOT / "web" / "dist"

app = FastAPI(title="Before the Breach", version="1.0.0",
              description="Predictive vulnerability intelligence — IBM track, Sheridan Datathon 2026")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def load_json(name: str, default=None):
    p = ART / name
    if not p.exists():
        return default
    return json.loads(p.read_text())


@lru_cache(maxsize=1)
def ranked() -> pd.DataFrame:
    p = ART / "ranked_2026.parquet"
    if not p.exists():
        raise HTTPException(503, "artifacts/ranked_2026.parquet missing — run models.predict")
    df = pd.read_parquet(p)
    df["published"] = pd.to_datetime(df["published"])
    return df


@lru_cache(maxsize=1)
def full() -> pd.DataFrame:
    p = ART / "full_rankings.csv"
    if not p.exists():
        raise HTTPException(503, "artifacts/full_rankings.csv missing — run models.predict")
    return pd.read_csv(p)


@lru_cache(maxsize=1)
def cwe_names() -> dict[str, str]:
    p = ROOT / "data" / "weakness_types.csv"
    if not p.exists():
        return {}
    w = pd.read_csv(p, usecols=["cwe_id", "name"])
    return dict(zip(w["cwe_id"], w["name"]))


@lru_cache(maxsize=1)
def descriptions() -> dict[str, str]:
    p = ART / "vulnerabilities.parquet"
    if not p.exists():
        return {}
    v = pd.read_parquet(p, columns=["cve_id", "description"])
    return dict(zip(v["cve_id"], v["description"].fillna("")))


@lru_cache(maxsize=1)
def explanations() -> dict:
    return load_json("explanations.json", {}) or {}


@app.get("/api/health")
def health():
    ok = (ART / "ranked_2026.parquet").exists() and (ROOT / "top500.csv").exists()
    stats = ranked().shape if (ART / "ranked_2026.parquet").exists() else (0, 0)
    return {"status": "ok" if ok else "degraded", "rows": int(stats[0]),
            "columns": int(stats[1]), "granite": bool(load_json("granite_meta.json"))}


@app.get("/api/overview")
def overview():
    df = ranked()
    sub = load_json("submission_summary.json", {})
    perfs = load_json("model_selection.json", {})
    disc = load_json("discoveries.json", {})
    held = (perfs.get("heldout_2025") or {}).get("rows", [])
    model_row = next((r for r in held if r["model"] == "final_blend"), {})
    base_row = next((r for r in held if r["model"] == "poc_then_epss"), {})

    risk_hist, edges = np.histogram(df["risk_score"], bins=20, range=(0, 1))
    bands = pd.cut(df["cvss3_score"], [0, 3.9, 6.9, 8.9, 10.01],
                   labels=["Low", "Medium", "High", "Critical"])
    return {
        "analyzed": int(len(df)),
        "high_priority": int((df["risk_percentile"] >= 0.99).sum()),
        "top500": int(min(500, len(df))),
        "mean_cvss_all": round(float(df["cvss3_score"].mean()), 3),
        "mean_cvss_top500": round(float(df.head(500)["cvss3_score"].mean()), 3),
        "epss_coverage": round(float(df["epss_score"].notna().mean()), 4),
        "exploit_code_share": round(float(df["poc_github"].fillna(0).mean()), 4),
        "risk_distribution": [{"bin": round(float((edges[i] + edges[i + 1]) / 2), 3),
                               "count": int(risk_hist[i])} for i in range(len(risk_hist))],
        "severity_mix": {str(k): int(v) for k, v in bands.value_counts().sort_index().items()},
        "top_vendors": df.head(500)["vendor"].value_counts().head(10).to_dict(),
        "top_cwe": df.head(500)["cwe_top"].value_counts().head(10).to_dict(),
        "snapshot_months": {str(k): int(v) for k, v in
                            df.head(500)["snapshot_month"].value_counts().sort_index().items()},
        "headline_model": model_row,
        "headline_baseline": base_row,
        "discoveries": [{"title": d.get("title"), "finding": d.get("finding")}
                        for d in (disc.get("discoveries") or [])][:3],
        "submission": sub,
    }


@app.get("/api/vulnerabilities")
def vulnerabilities(
    page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=500),
    sort: str = Query("rank", pattern="^(rank|risk_score|epss_score|cvss3_score|published)$"),
    order: str = Query("asc", pattern="^(asc|desc)$"),
    severity: str | None = None, vendor: str | None = None, cwe: str | None = None,
    min_epss: float | None = Query(None, ge=0, le=1), exploit_only: bool = False,
    q: str | None = None,
):
    df = ranked()
    if severity:
        sev = {s.strip().upper() for s in severity.split(",") if s.strip()}
        df = df[df["cvss3_severity"].fillna("").str.upper().isin(sev)]
    if vendor:
        df = df[df["vendor"].str.lower() == vendor.lower()]
    if cwe:
        df = df[df["cwe_top"].str.upper() == cwe.upper()]
    if min_epss is not None:
        df = df[df["epss_score"].fillna(-1) >= min_epss]
    if exploit_only:
        df = df[df["poc_github"].fillna(0) == 1]
    if q:
        needle = q.strip()
        mask = df["cve_id"].str.contains(needle, case=False, regex=False)
        if needle.isdigit():
            mask |= df["description"].fillna("").str.contains(needle, case=False, regex=False) \
                if "description" in df.columns else False
        df = df[mask]

    total = int(len(df))
    df = df.sort_values(sort, ascending=(order == "asc")).iloc[(page - 1) * size: page * size]
    cols = ["cve_id", "rank", "risk_score", "risk_percentile", "snapshot_month", "published",
            "cvss3_score", "cvss3_severity", "epss_score", "poc_github", "vendor", "cwe_top", "reason"]
    return {"total": total, "page": page, "size": size, "pages": int(np.ceil(total / size)),
            "items": df[cols].assign(published=df["published"].dt.strftime("%Y-%m-%d")).to_dict("records")}


@app.get("/api/vulnerabilities/{cve_id}")
def vulnerability(cve_id: str):
    df = ranked()
    hit = df[df["cve_id"].str.upper() == cve_id.upper()]
    if hit.empty:
        raise HTTPException(404, f"{cve_id} is not in the 2026 benchmark pool")
    row = hit.iloc[0]
    detail = full()
    drow = detail[detail["cve_id"] == row["cve_id"]]
    drow = drow.iloc[0] if len(drow) else None
    contribution = []
    att = load_json("attribution.json", {})
    if drow is not None and att:
        for f, med, mu, sd, coef in zip(att["features"], att["median"], att["mean"],
                                        att["scale"], att["coef"]):
            if f not in drow:
                continue
            v = drow[f]
            v = med if pd.isna(v) else float(v)
            contribution.append({"feature": f, "contribution": round(float(coef * ((v - mu) / sd)), 4)})
        contribution = sorted(contribution, key=lambda c: -abs(c["contribution"]))[:8]
    return {
        "cve_id": row["cve_id"],
        "description": descriptions().get(row["cve_id"], ""),
        "published": str(row["published"].date()),
        "snapshot_month": row["snapshot_month"],
        "rank": int(row["rank"]),
        "risk_score": float(row["risk_score"]),
        "risk_percentile": float(row["risk_percentile"]),
        "cvss3_score": None if pd.isna(row["cvss3_score"]) else float(row["cvss3_score"]),
        "cvss3_severity": row["cvss3_severity"],
        "epss_score": None if pd.isna(row["epss_score"]) else float(row["epss_score"]),
        "poc_github": int(row["poc_github"] or 0),
        "vendor": row["vendor"],
        "cwe_top": row["cwe_top"],
        "cwe_name": cwe_names().get(row["cwe_top"], "unknown"),
        "reason": row["reason"],
        "drivers": row["driver_1"],
        "technical": {
            "attack_vector": None if drow is None else drow.get("av_ord"),
            "privileges_required": None if drow is None else drow.get("pr_ord"),
            "user_interaction": None if drow is None else drow.get("ui_required"),
            "n_exploit_sources": None if drow is None else drow.get("n_exploit_sources"),
            "vendor_kev_prior": None if drow is None or pd.isna(drow.get("vendor_kev_n"))
            else int(drow.get("vendor_kev_n")),
            "cwe_kev_rate": None if drow is None or pd.isna(drow.get("cwe_kev_rate_max"))
            else round(float(drow.get("cwe_kev_rate_max")), 4),
            "granite_similarity": None if drow is None or pd.isna(drow.get("granite_knn_max"))
            else round(float(drow.get("granite_knn_max")), 4),
        },
        "contributions": contribution,
        "remediation_priority": ("Immediate — patch inside 72 hours"
                                 if row["risk_percentile"] >= 0.99 else
                                 "Scheduled — next maintenance window"
                                 if row["risk_percentile"] >= 0.95 else "Monitor"),
        "disclaimer": "Prediction of exploitation likelihood, not confirmation of exploitation.",
    }


@app.get("/api/rankings")
def rankings(limit: int = Query(100, ge=1, le=500)):
    df = ranked().head(limit)
    return {"count": int(len(df)), "items": df[["cve_id", "rank", "risk_score", "cvss3_score",
                                                 "epss_score", "vendor", "cwe_top"]].to_dict("records")}


@app.get("/api/model/performance")
def model_performance():
    perf = load_json("model_selection.json")
    if not perf:
        raise HTTPException(503, "model_selection.json missing — run models.train")
    base = load_json("backtest_baselines.json", {})
    return {"protocol": perf.get("protocol"), "label": perf.get("label"),
            "train_rows": perf.get("train_rows"), "train_positives": perf.get("train_positives"),
            "selection": perf.get("selection"),
            "heldout_2025": perf.get("heldout_2025"),
            "selected_blend": perf.get("selected_blend"),
            "baseline_reproduction": base,
            "permutation_importance": perf.get("permutation_importance")}


@app.get("/api/discoveries")
def discoveries():
    d = load_json("discoveries.json")
    if not d:
        raise HTTPException(503, "discoveries.json missing — run pipeline.discoveries")
    return d


@app.get("/api/explanations/{cve_id}")
def explanation(cve_id: str):
    e = explanations().get(cve_id.upper()) or explanations().get(cve_id)
    if e:
        return {"cve_id": cve_id.upper(), "source": e.get("source", "granite"), **e}
    detail = vulnerability(cve_id)
    return {"cve_id": detail["cve_id"], "source": "deterministic",
            "summary": detail["description"],
            "why_it_matters": detail["drivers"],
            "recommended_action": detail["remediation_priority"]}


@app.get("/api/export")
def export(limit: int = Query(500, ge=1, le=5000)):
    df = ranked().head(limit)[["cve_id", "rank", "risk_score", "cvss3_score", "epss_score",
                               "vendor", "cwe_top", "reason"]]
    return PlainTextResponse(df.to_csv(index=False), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=prioritized.csv"})


@app.get("/api/top500")
def top500():
    p = ROOT / "top500.csv"
    if not p.exists():
        raise HTTPException(503, "top500.csv missing — run models.predict")
    return PlainTextResponse(p.read_text(), media_type="text/csv")


if WEB_DIST.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIST), html=True), name="web")
else:
    @app.get("/")
    def root():
        return JSONResponse({"service": "Before the Breach API",
                             "note": "frontend build not found at web/dist",
                             "docs": "/docs"})
