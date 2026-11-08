"""PATCH ME IF YOU CAN — FastAPI backend.

Every number served here comes from artefacts produced by the pipeline; nothing is mocked.
If an artefact is missing the API fails loudly with 503 instead of inventing data.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
WEB_DIST = ROOT / "web" / "dist"
PRODUCT = "PATCH ME IF YOU CAN"
GRANITE_MODEL = "ibm-granite/granite-embedding-30m-english"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

app = FastAPI(
    title=PRODUCT,
    version="1.1.0",
    description="Exploit-aware vulnerability prioritisation — IBM Before the Breach track, Sheridan Datathon 2026",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class PatchRequest(BaseModel):
    budget: int = Field(20, ge=1, le=500)


class AnalyzeRequest(BaseModel):
    cve_id: str = Field(..., min_length=5, max_length=40)


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=2000)
    cve_id: str | None = Field(None, max_length=40)


def load_json(name: str, default=None):
    p = ART / name
    if not p.exists():
        return default
    return json.loads(p.read_text(encoding="utf-8"))


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
def predict_table() -> pd.DataFrame:
    """Feature table used for technical evidence in the investigation page."""
    p = ART / "predict.parquet"
    if not p.exists():
        raise HTTPException(503, "artifacts/predict.parquet missing — run pipeline.features")
    return pd.read_parquet(
        p,
        columns=["cve_id", "av_ord", "pr_ord", "ui_required", "n_exploit_sources",
                 "poc_github", "nuclei", "metasploit", "epss_rank"],
    )


@lru_cache(maxsize=1)
def products_table() -> pd.DataFrame:
    p = ART / "cve_products.parquet"
    if not p.exists():
        raise HTTPException(503, "artifacts/cve_products.parquet missing — run pipeline.prepare_data")
    return pd.read_parquet(p)


@lru_cache(maxsize=1)
def signals_table() -> pd.DataFrame:
    p = ART / "signals.parquet"
    if not p.exists():
        raise HTTPException(503, "artifacts/signals.parquet missing — run pipeline.prepare_data")
    return pd.read_parquet(p)


@lru_cache(maxsize=1)
def kev_table() -> pd.DataFrame:
    p = ART / "kev.parquet"
    if not p.exists():
        raise HTTPException(503, "artifacts/kev.parquet missing — run pipeline.prepare_data")
    return pd.read_parquet(p, columns=["cve_id", "date_added", "vendor", "product", "known_ransomware_use"])


@lru_cache(maxsize=1)
def granite_index() -> pd.DataFrame:
    p = ART / "granite_embed_index.parquet"
    if not p.exists():
        raise HTTPException(503, "artifacts/granite_embed_index.parquet missing — run models.granite_embed")
    return pd.read_parquet(p)


@lru_cache(maxsize=1)
def granite_embeddings() -> np.ndarray:
    p = ART / "granite_embed_2026.npy"
    if not p.exists():
        raise HTTPException(503, "artifacts/granite_embed_2026.npy missing — run models.granite_embed")
    return np.load(p, mmap_mode="r")


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


def _safe_float(value: Any) -> float | None:
    try:
        if value is None or pd.isna(value):
            return None
        return round(float(value), 6)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or pd.isna(value):
            return None
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _json_records(df: pd.DataFrame) -> list[dict]:
    """Replace pandas missing values with JSON nulls before serialising API rows."""
    return df.astype(object).where(pd.notna(df), None).to_dict("records")


def _technical(drow: pd.Series | None, prow: pd.Series | None, key: str) -> Any:
    for frame in (drow, prow):
        if frame is not None and key in frame and not pd.isna(frame[key]):
            return frame[key]
    return None


@app.get("/api/health")
def health():
    ok = (ART / "ranked_2026.parquet").exists() and (ROOT / "top500.csv").exists()
    stats = ranked().shape if (ART / "ranked_2026.parquet").exists() else (0, 0)
    return {
        "product": PRODUCT,
        "status": "ok" if ok else "degraded",
        "rows": int(stats[0]),
        "columns": int(stats[1]),
        "granite": bool(load_json("granite_meta.json")),
        "api_version": app.version,
    }


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
        "product": PRODUCT,
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
        if needle:
            desc = df["cve_id"].map(descriptions()).fillna("")
            mask = mask | desc.str.contains(needle, case=False, regex=False)
        df = df[mask]

    total = int(len(df))
    df = df.sort_values(sort, ascending=(order == "asc")).iloc[(page - 1) * size: page * size]
    cols = ["cve_id", "rank", "risk_score", "risk_percentile", "snapshot_month", "published",
            "cvss3_score", "cvss3_severity", "epss_score", "poc_github", "vendor", "cwe_top", "reason"]
    items = df[cols].copy()
    items["published"] = items["published"].dt.strftime("%Y-%m-%d")
    return {"total": total, "page": page, "size": size, "pages": int(np.ceil(total / size)),
            "items": _json_records(items)}


@app.get("/api/vulnerabilities/{cve_id}")
def vulnerability(cve_id: str):
    df = ranked()
    hit = df[df["cve_id"].str.upper() == cve_id.upper()]
    if hit.empty:
        raise HTTPException(404, f"{cve_id} is not in the 2026 benchmark pool")
    row = hit.iloc[0]
    cid = row["cve_id"]
    detail = full()
    drow = detail[detail["cve_id"] == cid]
    drow = drow.iloc[0] if len(drow) else None
    ptable = predict_table()
    prow = ptable[ptable["cve_id"] == cid]
    prow = prow.iloc[0] if len(prow) else None

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

    def tech(key: str):
        value = _technical(drow, prow, key)
        return None if value is None else (round(float(value), 4) if key in {"granite_knn_max"} else value)

    return {
        "cve_id": cid,
        "description": descriptions().get(cid, ""),
        "published": str(row["published"].date()),
        "snapshot_month": row["snapshot_month"],
        "rank": int(row["rank"]),
        "risk_score": float(row["risk_score"]),
        "risk_percentile": float(row["risk_percentile"]),
        "cvss3_score": _safe_float(row["cvss3_score"]),
        "cvss3_severity": row["cvss3_severity"],
        "epss_score": _safe_float(row["epss_score"]),
        "poc_github": _safe_int(row["poc_github"]) or 0,
        "vendor": row["vendor"],
        "cwe_top": row["cwe_top"],
        "cwe_name": cwe_names().get(row["cwe_top"], "unknown"),
        "reason": row["reason"],
        "drivers": row["driver_1"],
        "technical": {
            "attack_vector": _safe_int(tech("av_ord")),
            "privileges_required": _safe_int(tech("pr_ord")),
            "user_interaction": _safe_int(tech("ui_required")),
            "n_exploit_sources": _safe_int(tech("n_exploit_sources")),
            "vendor_kev_prior": _safe_int(_technical(drow, prow, "vendor_kev_n")),
            "granite_similarity": tech("granite_knn_max"),
        },
        "contributions": contribution,
        "remediation_priority": ("Immediate — patch inside 72 hours"
                                 if row["risk_percentile"] >= 0.99 else
                                 "Scheduled — next maintenance window"
                                 if row["risk_percentile"] >= 0.95 else "Monitor"),
        "disclaimer": "Prediction of exploitation likelihood, not confirmation of exploitation.",
    }


@app.get("/api/vulnerabilities/{cve_id}/similar")
def similar(cve_id: str, limit: int = Query(8, ge=1, le=50)):
    df = ranked()
    hit = df[df["cve_id"].str.upper() == cve_id.upper()]
    if hit.empty:
        raise HTTPException(404, f"{cve_id} is not in the 2026 benchmark pool")
    cid = hit.iloc[0]["cve_id"]
    index = granite_index()
    pos = index[index["cve_id"] == cid]
    if pos.empty:
        raise HTTPException(503, "Granite index does not contain this CVE — rerun models.granite_embed")
    emb = granite_embeddings()
    row = int(pos.iloc[0]["row"])
    if row >= len(emb):
        raise HTTPException(503, "Granite embedding matrix and index are out of sync")
    scores = np.asarray(emb @ np.asarray(emb[row], dtype=np.float32)).ravel()
    order = np.argsort(-scores)
    items: list[dict] = []
    for i in order:
        other = str(index.iloc[int(i)]["cve_id"])
        if other == cid:
            continue
        other_row = df[df["cve_id"] == other]
        if other_row.empty:
            continue
        r = other_row.iloc[0]
        items.append({
            "cve_id": other,
            "similarity": round(float(scores[int(i)]), 6),
            "rank": int(r["rank"]),
            "risk_score": round(float(r["risk_score"]), 6),
            "cvss3_score": _safe_float(r["cvss3_score"]),
            "epss_score": _safe_float(r["epss_score"]),
            "vendor": r["vendor"],
            "cwe_top": r["cwe_top"],
        })
        if len(items) >= limit:
            break
    meta = load_json("granite_meta.json", {}) or {}
    return {
        "cve_id": cid,
        "source": GRANITE_MODEL,
        "dim": meta.get("dim"),
        "note": "Cosine similarity between Granite description embeddings. Similarity is not a probability of exploitation.",
        "items": items,
    }


@app.get("/api/vulnerabilities/{cve_id}/timeline")
def timeline(cve_id: str):
    cid = cve_id.upper()
    df = ranked()
    hit = df[df["cve_id"] == cid]
    row = hit.iloc[0] if len(hit) else None
    vuln_path = ART / "vulnerabilities.parquet"
    if row is None:
        if not vuln_path.exists():
            raise HTTPException(404, f"{cid} not found")
        v = pd.read_parquet(vuln_path, columns=["cve_id", "published"])
        vh = v[v["cve_id"] == cid]
        if vh.empty:
            raise HTTPException(404, f"{cid} not found")
        published = pd.to_datetime(vh.iloc[0]["published"]).date().isoformat()
        snapshot = None
    else:
        published = str(row["published"].date())
        snapshot = row["snapshot_month"]

    kev = kev_table()
    kh = kev[kev["cve_id"] == cid]
    kev_added = None if kh.empty or pd.isna(kh.iloc[0]["date_added"]) else str(pd.to_datetime(kh.iloc[0]["date_added"]).date())
    hist = signals_table()
    hist = hist[hist["cve_id"] == cid].sort_values("month")
    points = []
    for _, s in hist.iterrows():
        points.append({
            "month": str(s["month"]),
            "epss": _safe_float(s["epss"]),
            "in_kev": bool(int(s["in_kev"])) if pd.notna(s["in_kev"]) else False,
            "exploit_sources": int(float(s["exploitdb"]) + float(s["metasploit"]) +
                                   float(s["nuclei"]) + float(s["poc_github"])),
        })
    note = ("Monthly exploit-signal history is available for 2024–2025. "
            "The 2026 benchmark provides one snapshot per CVE, so no synthetic monthly path is shown.")
    return {"cve_id": cid, "published": published, "snapshot_month": snapshot,
            "kev_added": kev_added, "points": points, "note": note}


@app.get("/api/rankings")
def rankings(limit: int = Query(100, ge=1, le=500)):
    df = ranked().head(limit)
    return {"count": int(len(df)), "items": _json_records(df[["cve_id", "rank", "risk_score", "cvss3_score",
                                                              "epss_score", "vendor", "cwe_top"]])}


@app.get("/api/products")
def products(q: str | None = None, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200)):
    p = products_table()
    p = p[p["cpe_vendor"].notna() & (p["cpe_vendor"].astype(str).str.strip() != "")]
    if q:
        p = p[p["cpe_vendor"].astype(str).str.contains(q.strip(), case=False, regex=False)]
    agg = (p.groupby("cpe_vendor", as_index=False)
             .agg(vulnerabilities=("cve_id", "nunique"), cpe_product_rows=("n_products", "sum")))
    agg = agg.sort_values(["vulnerabilities", "cpe_vendor"], ascending=[False, True])
    total = int(len(agg))
    page_df = agg.iloc[(page - 1) * size: page * size]
    items = [{"product_id": str(r.cpe_vendor), "vendor": str(r.cpe_vendor),
              "vulnerabilities": int(r.vulnerabilities), "cpe_product_rows": int(r.cpe_product_rows)}
             for r in page_df.itertuples(index=False)]
    return {"total": total, "page": page, "size": size, "pages": int(np.ceil(total / size)),
            "note": "CPE vendor is derived from affected_products.csv. Absence of a CPE is not evidence that a product is unaffected.",
            "items": items}


@app.get("/api/products/{product_id}/vulnerabilities")
def product_vulnerabilities(product_id: str, page: int = Query(1, ge=1),
                            size: int = Query(25, ge=1, le=100)):
    p = products_table()
    product = p[p["cpe_vendor"].astype(str).str.lower() == product_id.lower()]
    if product.empty:
        raise HTTPException(404, f"CPE vendor {product_id!r} not found")
    df = ranked().merge(product[["cve_id"]].drop_duplicates(), on="cve_id", how="inner")
    total = int(len(df))
    df = df.sort_values("rank").iloc[(page - 1) * size: page * size]
    cols = ["cve_id", "rank", "risk_score", "cvss3_score", "cvss3_severity", "epss_score",
            "vendor", "cwe_top", "reason"]
    items = df[cols].copy()
    for c in ["risk_score", "cvss3_score", "epss_score"]:
        items[c] = items[c].map(_safe_float)
    return {"product_id": product_id, "total": total, "page": page, "size": size,
            "pages": int(np.ceil(total / size)), "items": _json_records(items)}


def _ordered(df: pd.DataFrame, columns: list[str], ascending: list[bool]) -> pd.DataFrame:
    return df.sort_values(columns + ["cve_id"], ascending=ascending + [True], na_position="last")


@app.post("/api/patch-optimizer")
def patch_optimizer(req: PatchRequest):
    df = ranked().merge(full()[["cve_id", "any_exploit", "n_exploit_sources"]],
                        on="cve_id", how="left")
    budget = req.budget
    fields = ["cve_id", "rank", "risk_score", "cvss3_score", "cvss3_severity",
              "epss_score", "poc_github", "n_exploit_sources", "vendor", "cwe_top", "reason"]
    choices = {
        "cvss": _ordered(df, ["cvss3_score", "epss_score"], [False, False]),
        "epss": _ordered(df, ["epss_score", "cvss3_score"], [False, False]),
        "exploit_then_epss": _ordered(df, ["any_exploit", "epss_score", "cvss3_score"], [False, False, False]),
        "model": _ordered(df, ["rank"], [True]),
    }
    labels = {
        "cvss": "Highest CVSS",
        "epss": "EPSS first",
        "exploit_then_epss": "Public exploit code, then EPSS",
        "model": PRODUCT,
    }
    selected: dict[str, list[dict]] = {}
    ids: dict[str, list[str]] = {}
    for name, frame in choices.items():
        part = frame.head(budget)[fields].copy()
        for c in ["risk_score", "cvss3_score", "epss_score"]:
            part[c] = part[c].map(_safe_float)
        part["poc_github"] = part["poc_github"].map(_safe_int)
        part["n_exploit_sources"] = part["n_exploit_sources"].map(_safe_int)
        selected[name] = _json_records(part)
        ids[name] = part["cve_id"].tolist()
    overlap = {a: {b: len(set(ids[a]) & set(ids[b])) for b in ids} for a in ids}
    unique = {a: sorted(set(ids[a]) - set().union(*(set(ids[b]) for b in ids if b != a))) for a in ids}
    return {
        "budget": budget,
        "strategies": {k: {"label": labels[k], "count": len(selected[k]), "items": selected[k]}
                       for k in selected},
        "overlap": overlap,
        "unique": unique,
        "historical_validation": load_json("gap_analysis.json", {}),
        "note": "The 2026 benchmark has no public answer key. Historical KEV validation is shown separately; no 2026 hit count is claimed.",
    }


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text or "") if s.strip()]


def _evidence(text: str, patterns: list[str]) -> str | None:
    for sentence in _sentences(text):
        if any(re.search(p, sentence, re.IGNORECASE) for p in patterns):
            return sentence
    return None


def _dna(description: str) -> dict:
    text = description or ""
    lower = text.lower()
    evidence: list[dict] = []
    uncertainty: list[str] = []

    def add(field: str, value: Any, patterns: list[str]):
        if value is None:
            uncertainty.append(f"{field} not established by the description")
            return
        clip = _evidence(text, patterns)
        evidence.append({"characteristic": field, "source_text": clip or text[:300]})

    if re.search(r"unauthenticated|without authentication|no authentication", lower):
        auth = False
        add("authentication_required", auth, [r"unauthenticated", r"without authentication", r"no authentication"])
    elif re.search(r"authenticated|requires authentication|authentication is required", lower):
        auth = True
        add("authentication_required", auth, [r"authenticated", r"requires authentication"])
    else:
        auth = None
        add("authentication_required", auth, [])

    if re.search(r"\bremote\b|\bnetwork\b|\bhttp\b|\bweb\b", lower):
        surface = "network"
        add("remote_exploitation_possible", True, [r"\bremote\b", r"\bnetwork\b", r"\bhttp\b", r"\bweb\b"])
    elif re.search(r"\blocal\b|\bphysical\b", lower):
        surface = "local"
        add("remote_exploitation_possible", False, [r"\blocal\b", r"\bphysical\b"])
    else:
        surface = "unknown"
        add("remote_exploitation_possible", None, [])

    code_exec = bool(re.search(r"remote code execution|\brce\b|code execution|command injection|arbitrary code", lower))
    add("code_execution", True if code_exec else None,
        [r"remote code execution", r"\brce\b", r"code execution", r"command injection", r"arbitrary code"])

    priv = bool(re.search(r"privilege escalation|elevated privileg|gain elevated", lower))
    add("privilege_escalation", True if priv else None,
        [r"privilege escalation", r"elevated privileg", r"gain elevated"])

    disclosure = bool(re.search(r"information disclosure|sensitive information|data leak|expos", lower))
    add("information_disclosure", True if disclosure else None,
        [r"information disclosure", r"sensitive information", r"data leak", r"expos"])

    classes = [
        ("remote_code_execution", [r"remote code execution", r"\brce\b"]),
        ("sql_injection", [r"sql injection", r"\bsqli\b"]),
        ("cross_site_scripting", [r"cross.site scripting", r"\bxss\b"]),
        ("authentication_bypass", [r"authentication bypass", r"auth(?:entication)? bypass"]),
        ("deserialization", [r"deserializ", r"unserialize"]),
        ("path_traversal", [r"path traversal", r"directory traversal"]),
        ("ssrf", [r"server.side request forgery", r"\bssrf\b"]),
        ("xxe", [r"xml external entit", r"\bxxe\b"]),
        ("denial_of_service", [r"denial of service", r"\bdos\b"]),
        ("buffer_overflow", [r"buffer overflow", r"out.of.bounds"]),
    ]
    vulnerability_class = "unknown"
    for name, patterns in classes:
        if any(re.search(p, lower) for p in patterns):
            vulnerability_class = name
            break

    return {
        "attack_surface": surface,
        "authentication_required": auth,
        "remote_exploitation_possible": True if surface == "network" else (False if surface == "local" else None),
        "code_execution": True if code_exec else None,
        "privilege_escalation": True if priv else None,
        "information_disclosure": True if disclosure else None,
        "vulnerability_class": vulnerability_class,
        "evidence": evidence,
        "uncertainty": uncertainty,
        "method": "deterministic description rules; no generative model",
    }


@app.get("/api/granite/status")
def granite_status():
    meta = load_json("granite_meta.json", {}) or {}
    return {
        "product": PRODUCT,
        "embedding_model": meta.get("model", GRANITE_MODEL),
        "dim": meta.get("dim"),
        "available": bool(meta),
        "generative_model": None,
        "capabilities": ["semantic similarity", "similar-CVE retrieval", "grounded evidence retrieval"],
        "limitation": "No Granite instruct/generative model is configured in this environment. Analyst answers are retrieval-grounded deterministic responses.",
    }


@app.post("/api/granite/analyze")
def granite_analyze(req: AnalyzeRequest):
    detail = vulnerability(req.cve_id)
    dna = _dna(detail["description"])
    analogs = []
    try:
        analogs = similar(detail["cve_id"], limit=5)["items"]
    except HTTPException:
        pass
    meta = load_json("granite_meta.json", {}) or {}
    return {
        "cve_id": detail["cve_id"],
        "source": "deterministic_rules",
        "embedding_model": meta.get("model", GRANITE_MODEL),
        "generative_model": None,
        "extracted": dna,
        "verified": {
            "cvss3_score": detail["cvss3_score"],
            "cvss3_severity": detail["cvss3_severity"],
            "epss_score": detail["epss_score"],
            "cwe_top": detail["cwe_top"],
            "cwe_name": detail["cwe_name"],
            "technical": detail["technical"],
        },
        "analogs": analogs,
        "note": "Properties are extracted only when the description contains supporting text. Unknown values remain unknown. Granite embeddings power the analog retrieval, not the extraction.",
    }


@app.post("/api/granite/chat")
def granite_chat(req: ChatRequest):
    question = req.question.strip()
    cid = req.cve_id
    if not cid:
        match = CVE_RE.search(question)
        cid = match.group(0) if match else None

    if cid:
        detail = vulnerability(cid)
        lower = question.lower()
        if "similar" in lower or "analog" in lower:
            sim = similar(detail["cve_id"], limit=5)
            ids = ", ".join(f"{x['cve_id']} ({x['similarity']:.3f})" for x in sim["items"])
            answer = (f"Granite embeddings place these historical/2026 CVEs closest to {detail['cve_id']}: "
                      f"{ids}. Similarity is not a probability of exploitation; the model risk rank is "
                      f"#{detail['rank']} of 72,670.")
        elif "uncertain" in lower or "missing" in lower:
            missing = [k for k, v in detail["technical"].items() if v is None]
            answer = (f"Missing or unavailable evidence for {detail['cve_id']}: "
                      f"{', '.join(missing) if missing else 'none among the displayed technical fields'}. "
                      f"The model output is a ranking, not a calibrated probability, and absence of evidence is not evidence of safety.")
        elif "cvss" in lower or "epss" in lower or "compare" in lower:
            answer = (f"{detail['cve_id']}: CVSS {detail['cvss3_score']}, EPSS {detail['epss_score']}, "
                      f"model rank #{detail['rank']} of 72,670 (risk score {detail['risk_score']:.3f}). "
                      f"Recorded drivers: {detail['drivers']}.")
        else:
            answer = (f"{detail['cve_id']} ranks #{detail['rank']} of 72,670 with risk score "
                      f"{detail['risk_score']:.3f}. Recorded drivers: {detail['drivers']}. "
                      f"CVSS is {detail['cvss3_score']} and EPSS at snapshot is {detail['epss_score']}. "
                      f"Prediction is not confirmation of exploitation.")
        return {"cve_id": detail["cve_id"], "answer": answer, "source": "grounded-retrieval",
                "generative_model": None,
                "citations": ["ranked_2026.parquet", "attribution.json", "granite_embed_2026.npy"]}

    if any(word in question.lower() for word in ["top", "first", "priorit", "investigat", "patch"]):
        top = ranked().head(5)
        lines = [f"#{int(r['rank'])} {r['cve_id']} ({r['vendor']}, risk {r['risk_score']:.3f}): {r['reason']}"
                 for _, r in top.iterrows()]
        return {"answer": "Top-ranked CVEs in the 2026 benchmark:\n" + "\n".join(lines),
                "source": "grounded-retrieval", "generative_model": None,
                "citations": ["ranked_2026.parquet"]}

    return {
        "answer": ("Ask about a specific CVE (for example, “Why is CVE-2026-39808 ranked here?”), "
                   "or ask for the highest-priority CVEs. Answers are assembled from the ranked table, "
                   "the linear attribution and the Granite similarity index; no generative model is configured."),
        "source": "grounded-retrieval",
        "generative_model": None,
        "citations": ["ranked_2026.parquet"],
    }


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
    return PlainTextResponse(p.read_text(encoding="utf-8"), media_type="text/csv")


if WEB_DIST.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIST), html=True), name="web")
else:
    @app.get("/")
    def root():
        return JSONResponse({"service": f"{PRODUCT} API",
                             "note": "frontend build not found at web/dist",
                             "docs": "/docs"})
