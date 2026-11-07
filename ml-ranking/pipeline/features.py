"""Stage 2: snapshot-aligned feature tables for training cohorts and the 2026 benchmark.

The single rule: a row's features may only use information observable at the END of its
`snapshot_month`. Training cohorts are built from the monthly exploit-signal snapshots
(2024-01 .. 2025-12), which are exactly the same kind of snapshot the 2026 scoreboard gives.

Outputs
-------
artifacts/train.parquet    one row per (cve, snapshot_month) candidate, with labels
artifacts/predict.parquet  one row per 2026 scoreboard CVE
artifacts/feature_meta.json
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"

KEV_CUTOFF = pd.Timestamp("2025-12-29")     # last observable KEV observation
COMP_CUTOFF = pd.Timestamp("2026-11-04")    # official evaluation date (labels unknown to us)

TOP_CWES = [
    "CWE-20", "CWE-22", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-119",
    "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-190", "CWE-200", "CWE-269", "CWE-284",
    "CWE-287", "CWE-295", "CWE-306", "CWE-352", "CWE-362", "CWE-400", "CWE-401", "CWE-416",
    "CWE-434", "CWE-476", "CWE-502", "CWE-611", "CWE-639", "CWE-787", "CWE-798", "CWE-862",
    "CWE-863", "CWE-918", "CWE-1321", "CWE-400",
]
TOP_CWES = list(dict.fromkeys(TOP_CWES))

KEYWORDS = {
    "kw_rce": r"\bremote code execution\b|\brce\b|\bcode execution\b",
    "kw_cmd_injection": r"command injection|os command|shell command|command execution",
    "kw_deserialization": r"deserializ|unserialize|pickle|marshalling",
    "kw_sqli": r"sql injection|\bsqli\b",
    "kw_xss": r"cross[- ]site scripting|\bxss\b",
    "kw_buffer_overflow": r"buffer overflow|out[- ]of[- ]bounds|heap overflow|stack overflow|memory corruption",
    "kw_use_after_free": r"use[- ]after[- ]free|double free|dangling pointer",
    "kw_priv_esc": r"privilege escalation|escalat\w+ (?:of )?privileg|gain elevated",
    "kw_auth_bypass": r"authentication bypass|auth(?:entication)? bypass|bypass(?:ing)? (?:the )?(?:auth|authentication)",
    "kw_path_traversal": r"path traversal|directory traversal|\.\./",
    "kw_ssrf": r"server[- ]side request forgery|\bssrf\b",
    "kw_xxe": r"xml external entit|\bxxe\b",
    "kw_csrf": r"cross[- ]site request forgery|\bcsrf\b",
    "kw_dos": r"denial of service|\bdos\b",
    "kw_info_disclosure": r"information disclosure|expos\w+ (?:sensitive|information)|data leak",
    "kw_file_upload": r"unrestricted file upload|arbitrary file upload|upload(?:ing)? a file",
    "kw_template_injection": r"template injection|\bssti\b",
    "kw_hardcoded": r"hard[- ]coded (?:credential|password|key)|default (?:password|credential)",
    "kw_integer": r"integer overflow|integer underflow|signedness",
    "kw_race": r"race condition|time[- ]of[- ]check",
    "kw_open_redirect": r"open redirect",
    "kw_zip_slip": r"zip slip|archive extraction",
    "kw_prototype": r"prototype pollution",
    "kw_dependency": r"dependency|third[- ]party (?:component|library)|transitive",
    "kw_unauthenticated": r"unauthenticated|without authentication|no authentication",
    "kw_zero_click": r"zero[- ]click|no user interaction",
    "kw_wormable": r"wormable|self[- ]propagat",
    "kw_kev_ref": r"known exploited|actively exploited|exploited in the wild",
}
KEYWORD_RE = {k: re.compile(v, re.IGNORECASE) for k, v in KEYWORDS.items()}

SEVERITY_ORD = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
AV_ORD = {"NETWORK": 3, "ADJACENT_NETWORK": 2, "ADJACENT": 2, "LOCAL": 1, "PHYSICAL": 0}
PR_ORD = {"NONE": 0, "LOW": 1, "HIGH": 2}
IMPACT_ORD = {"NONE": 0, "LOW": 1, "HIGH": 2}


def log(msg: str) -> None:
    print(f"[features] {msg}", flush=True)


def normalise_vendor(value) -> str:
    """Map an NVD `assigner` (email, domain, or CVE-numbering-authority id) to a vendor key.

    Assigner is fixed when the CVE ID is reserved, i.e. before publication, so it is
    available at snapshot time. The CISA-ADP GUID is deliberately collapsed to `cisaadp`
    because those ADP enrichments are applied after publication (documented in the audit).
    """
    s = str(value).lower().strip()
    if not s or s == "nan":
        return "unknown"
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s):
        return "cisaadp"
    if "@" in s:
        s = s.split("@")[-1]
    parts = [p for p in s.split(".") if p]
    if len(parts) >= 2:
        s = parts[-2]
    return re.sub(r"[^a-z0-9]", "", s) or "unknown"


def add_static_features(df: pd.DataFrame) -> pd.DataFrame:
    """Features derived from the vulnerability record itself (known at publication)."""
    out = df.copy()
    out["published"] = pd.to_datetime(out["published"])
    out["pub_month"] = out["published"].dt.month.astype("int16")
    out["pub_dow"] = out["published"].dt.day_of_week.astype("int16")
    out["pub_day"] = out["published"].dt.day.astype("int16")
    out["age_days"] = (out["snapshot_end"] - out["published"]).dt.days.clip(lower=0).astype("float32")

    out["cvss3"] = pd.to_numeric(out["cvss3_score"], errors="coerce")
    out["cvss3_sev_ord"] = out["cvss3_severity"].map(SEVERITY_ORD).astype("float32")
    out["cvss4"] = pd.to_numeric(out.get("cvss4_score"), errors="coerce")
    out["cvss2"] = pd.to_numeric(out.get("cvss2_score"), errors="coerce")
    out["av_ord"] = out["attack_vector"].map(AV_ORD).astype("float32")
    out["ac_low"] = (out["attack_complexity"] == "LOW").astype("float32")
    out["pr_ord"] = out["privileges_required"].map(PR_ORD).astype("float32")
    out["ui_required"] = (out["user_interaction"] == "REQUIRED").astype("float32")
    out["scope_changed"] = (out["scope"] == "CHANGED").astype("float32")
    for side in ["confidentiality", "integrity", "availability"]:
        out[f"{side[:3]}_ord"] = out[f"{side}_impact"].map(IMPACT_ORD).astype("float32")
    out["cvss3_exploitability"] = pd.to_numeric(out["cvss3_exploitability_score"], errors="coerce")
    out["cvss3_impact"] = pd.to_numeric(out["cvss3_impact_score"], errors="coerce")

    cwe = out["cwe_ids"].fillna("")
    out["n_cwe"] = cwe.apply(lambda s: len([c for c in str(s).split(";") if c.strip()])).astype("float32")
    out["cwe_missing"] = (out["n_cwe"] == 0).astype("float32")
    for c in TOP_CWES:
        out["has_" + c.replace("-", "_").lower()] = cwe.str.contains(c, regex=False).astype("float32")

    desc = out["description"].fillna("").astype(str)
    out["desc_len"] = desc.str.len().astype("float32")
    out["desc_len_log"] = np.log1p(out["desc_len"]).astype("float32")
    out["desc_words"] = desc.str.count(r"\s+").astype("float32")
    for name, rx in KEYWORD_RE.items():
        out[name] = desc.map(lambda d: 1.0 if rx.search(d) else 0.0).astype("float32")
    out["vendor_key"] = out["assigner"].map(normalise_vendor)
    return out


def add_signal_features(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    epss = pd.to_numeric(out["epss"], errors="coerce").clip(1e-6, 1 - 1e-6)
    out["epss"] = epss.astype("float32")
    out["epss_logit"] = np.log(epss / (1 - epss)).astype("float32")
    out["epss_missing"] = epss.isna().astype("float32")
    out["epss_rank"] = out.groupby("snapshot_month")["epss"].rank(pct=True).astype("float32")
    flag_cols = ["exploitdb", "metasploit", "nuclei", "poc_github"]
    for c in flag_cols:
        out[c] = pd.to_numeric(out[c], errors="coerce").fillna(0).astype("float32")
    out["n_exploit_sources"] = out[flag_cols].sum(axis=1).astype("float32")
    out["any_exploit"] = (out["n_exploit_sources"] > 0).astype("float32")
    out["horizon_days"] = (out["cutoff"] - out["snapshot_end"]).dt.days.clip(lower=0).astype("float32")
    return out


def _month_ends(months: list[str]) -> dict[str, pd.Timestamp]:
    return {m: (pd.Timestamp(m + "-01") + pd.offsets.MonthEnd(0)) for m in sorted(months)}


def build_prior_tables(months: list[str], kev: pd.DataFrame, vuln: pd.DataFrame) -> dict:
    """Per-snapshot-month historical priors, each computed with `date_added <= month_end`.

    Returns {month: {"vendor": DataFrame, "cwe": DataFrame}}. These are counts of *past*
    KEV additions only; nothing after the snapshot month ever enters.
    """
    kev = kev[kev["date_added"].notna()].copy()
    kev["vendor_key"] = kev["kev_vendor"].map(lambda s: re.sub(r"[^a-z0-9]", "", str(s).lower()))
    kev_cwe = kev.assign(cwe=kev["cwe_ids"].fillna("").str.split(";")).explode("cwe")
    kev_cwe["cwe"] = kev_cwe["cwe"].str.strip()
    kev_cwe = kev_cwe[kev_cwe["cwe"].str.startswith("CWE-")]

    vuln_cwe = vuln[["cve_id", "published", "cwe_ids"]].copy()
    vuln_cwe["cwe"] = vuln_cwe["cwe_ids"].fillna("").str.split(";")
    vuln_cwe = vuln_cwe.explode("cwe")
    vuln_cwe["cwe"] = vuln_cwe["cwe"].str.strip()
    vuln_cwe = vuln_cwe[vuln_cwe["cwe"].str.startswith("CWE-")]

    tables = {}
    for month, end in _month_ends(months).items():
        km = kev[kev["date_added"] <= end]
        vk = km.groupby("vendor_key").agg(
            vendor_kev_n=("cve_id", "size"), vendor_kev_ransomware=("ransomware", "sum")
        )
        exp = vuln[vuln["published"] <= end].groupby("vendor_key").size().rename("vendor_cve_n")
        vk = vk.join(exp, how="outer").fillna(0.0)
        vk["vendor_kev_n"] = vk["vendor_kev_n"].astype(float)
        vk["vendor_cve_n"] = vk["vendor_cve_n"].astype(float)
        vk["vendor_kev_rate"] = (vk["vendor_kev_n"] + 1.0) / (vk["vendor_cve_n"] + 40.0)
        vk["vendor_ransomware_share"] = vk["vendor_kev_ransomware"].fillna(0.0) / vk["vendor_kev_n"].clip(lower=1)
        for days in (90, 365):
            window = kev[(kev["date_added"] <= end) & (kev["date_added"] > end - pd.Timedelta(days=days))]
            vk[f"vendor_kev_{days}"] = window.groupby("vendor_key").size().reindex(vk.index).fillna(0.0)

        kc = km.explode("cwe") if False else kev_cwe[kev_cwe["date_added"] <= end]
        kc = kc.groupby("cwe").size().rename("cwe_kev_n")
        ce = vuln_cwe[vuln_cwe["published"] <= end].groupby("cwe").size().rename("cwe_cve_n")
        cwe_tab = pd.concat([kc, ce], axis=1).fillna(0.0)
        cwe_tab["cwe_kev_rate"] = (cwe_tab["cwe_kev_n"] + 1.0) / (cwe_tab["cwe_cve_n"] + 60.0)
        tables[month] = {"vendor": vk, "cwe": cwe_tab}
    return tables


def apply_priors(df: pd.DataFrame, tables: dict) -> pd.DataFrame:
    out = df.copy()
    vendor_cols = ["vendor_kev_n", "vendor_cve_n", "vendor_kev_rate", "vendor_ransomware_share",
                   "vendor_kev_90", "vendor_kev_365"]
    cwe_cols = ["cwe_kev_rate"]
    for c in vendor_cols + ["cwe_kev_rate_max", "cwe_kev_rate_mean", "cwe_kev_n_max"]:
        out[c] = np.nan

    for month, grp in out.groupby("snapshot_month"):
        tab = tables[month]
        v = tab["vendor"].reindex(grp["vendor_key"])
        for c in vendor_cols:
            out.loc[grp.index, c] = v[c].to_numpy()
        cwe_tab = tab["cwe"]["cwe_kev_rate"]
        n = len(grp)
        maxr = np.full(n, np.nan, dtype="float32")
        meanr = np.full(n, np.nan, dtype="float32")
        maxk = np.zeros(n, dtype="float32")
        for j, s in enumerate(grp["cwe_ids"].fillna("")):
            ids = [c.strip() for c in str(s).split(";") if c.strip() in cwe_tab.index]
            if not ids:
                continue
            vals = cwe_tab.loc[ids].to_numpy(dtype="float64")
            maxr[j] = vals.max()
            meanr[j] = vals.mean()
            maxk[j] = float(tab["cwe"].reindex(ids)["cwe_kev_n"].max())
        out.loc[grp.index, "cwe_kev_rate_max"] = maxr
        out.loc[grp.index, "cwe_kev_rate_mean"] = meanr
        out.loc[grp.index, "cwe_kev_n_max"] = maxk

    out["vendor_kev_n_log"] = np.log1p(out["vendor_kev_n"]).astype("float32")
    out["vendor_cve_n_log"] = np.log1p(out["vendor_cve_n"]).astype("float32")
    out["vendor_kev_90_log"] = np.log1p(out["vendor_kev_90"]).astype("float32")
    out["vendor_kev_365_log"] = np.log1p(out["vendor_kev_365"]).astype("float32")
    out["vendor_unseen"] = (out["vendor_kev_n"].fillna(0) == 0).astype("float32")
    out["vendor_is_generic_cna"] = out["vendor_key"].isin(
        ["github", "mitre", "cisaadp", "vulncheck", "unknown", "patchstack", "wordfence", "wpscan", "vuldb"]
    ).astype("float32")
    return out


def add_interactions(df: pd.DataFrame) -> pd.DataFrame:
    """Cheap interactions the additive models cannot build on their own."""
    out = df.copy()
    out["epss_x_exploit"] = (out["epss"].fillna(0.0) * out["any_exploit"]).astype("float32")
    cwe = out["cwe_kev_rate_max"].fillna(float(out["cwe_kev_rate_max"].median()))
    out["cwe_x_exploit"] = (cwe * out["any_exploit"]).astype("float32")
    out["is_wordpress_eco"] = out["vendor_key"].isin(["wordfence", "patchstack", "wpscan"]).astype("float32")
    out["is_github_cna"] = (out["vendor_key"] == "github").astype("float32")
    out["silent_crit"] = ((out["cvss3"] >= 9) & (out["any_exploit"] == 0)).astype("float32")
    return out


def build_train(vuln: pd.DataFrame, signals: pd.DataFrame, kev: pd.DataFrame, tables: dict) -> pd.DataFrame:
    """Candidates published 2024-01..2025-12, not in KEV at the end of their snapshot month.

    `snapshot_month` = publication month, exactly like the 2026 scoreboard.
    """
    base = vuln[(vuln["published"] >= "2024-01-01") & (vuln["published"] <= "2025-12-31")].copy()
    base["snapshot_month"] = base["published"].dt.strftime("%Y-%m")
    sig = signals[["cve_id", "month", "epss", "in_kev", "exploitdb", "metasploit", "nuclei", "poc_github"]]
    sig = sig.rename(columns={"month": "snapshot_month"})
    df = base.merge(sig, on=["cve_id", "snapshot_month"], how="left", validate="one_to_one")
    df["in_kev"] = df["in_kev"].fillna(0).astype("int8")
    log(f"2024-2025 published: {len(df):,}; with a signal snapshot: {df['epss'].notna().sum():,} "
        f"(missing snapshot rows are CVEs with no EPSS and no exploit flags)")
    df = df[df["in_kev"] == 0].copy()

    df["snapshot_end"] = pd.to_datetime(df["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0)
    df["cutoff"] = KEV_CUTOFF

    kev_add = kev.drop_duplicates("cve_id").set_index("cve_id")["date_added"]
    df["kev_added"] = df["cve_id"].map(kev_add)
    df["days_to_kev"] = (df["kev_added"] - df["snapshot_end"]).dt.days

    for h in (90, 180):
        df[f"label_{h}"] = (df["days_to_kev"].notna() & (df["days_to_kev"] > 0) & (df["days_to_kev"] <= h)).astype("int8")
    df["label_any"] = (df["days_to_kev"].notna() & (df["days_to_kev"] > 0)).astype("int8")
    df["observed_days"] = (KEV_CUTOFF - df["snapshot_end"]).dt.days.astype("int16")

    df = add_static_features(df)
    df = add_signal_features(df)
    df = apply_priors(df, tables)
    df = add_interactions(df)
    return df


def build_predict(vuln: pd.DataFrame, scoreboard: pd.DataFrame, tables: dict) -> pd.DataFrame:
    df = scoreboard.copy()
    df["cutoff"] = COMP_CUTOFF
    df["kev_added"] = pd.NaT
    for c in ["label_any", "label_90", "label_180", "days_to_kev", "in_kev"]:
        df[c] = np.nan
    df["observed_days"] = (COMP_CUTOFF - df["snapshot_end"]).dt.days.astype("int16")
    df = add_static_features(df)
    df = add_signal_features(df)
    df = apply_priors(df, tables)
    df = add_interactions(df)
    return df


FEATURE_GROUPS = {
    "calendar": ["pub_month", "pub_dow", "pub_day", "age_days"],
    "cvss": ["cvss3", "cvss3_sev_ord", "cvss4", "cvss2", "av_ord", "ac_low", "pr_ord",
             "ui_required", "scope_changed", "con_ord", "int_ord", "ava_ord",
             "cvss3_exploitability", "cvss3_impact"],
    "weakness": ["n_cwe", "cwe_missing"] + ["has_" + c.replace("-", "_").lower() for c in TOP_CWES]
                + ["cwe_kev_rate_max", "cwe_kev_rate_mean", "cwe_kev_n_max"],
    "epss_exploit": ["epss", "epss_logit", "epss_missing", "epss_rank", "exploitdb", "metasploit",
                     "nuclei", "poc_github", "n_exploit_sources", "any_exploit"],
    "vendor_history": ["vendor_kev_n_log", "vendor_cve_n_log", "vendor_kev_rate",
                       "vendor_ransomware_share", "vendor_unseen", "vendor_is_generic_cna",
                       "vendor_kev_90_log", "vendor_kev_365_log"],
    "text": ["desc_len_log", "desc_words"] + list(KEYWORDS),
    "interactions": ["epss_x_exploit", "cwe_x_exploit", "is_wordpress_eco", "is_github_cna",
                     "silent_crit"],
    "horizon": ["horizon_days"],
}
FEATURES = [f for g in FEATURE_GROUPS.values() for f in g]


def main() -> None:
    vuln = pd.read_parquet(ART / "vulnerabilities.parquet")
    vuln["vendor_key"] = vuln["assigner"].map(normalise_vendor)
    signals = pd.read_parquet(ART / "signals.parquet")
    kev = pd.read_parquet(ART / "kev.parquet")
    scoreboard = pd.read_parquet(ART / "scoreboard.parquet")

    months = sorted(set(signals["month"].unique()) | set(scoreboard["snapshot_month"].unique()))
    tables = build_prior_tables(months, kev, vuln)

    train = build_train(vuln, signals, kev, tables)
    predict = build_predict(vuln, scoreboard, tables)

    missing = [f for f in FEATURES if f not in train.columns or f not in predict.columns]
    assert not missing, f"feature mismatch: {missing}"
    assert len(predict) == len(scoreboard), "predict table lost rows"
    assert train["cve_id"].is_unique and predict["cve_id"].is_unique

    cols = ["cve_id", "snapshot_month", "snapshot_end", "published", "cutoff", "kev_added",
            "days_to_kev", "label_any", "label_90", "label_180", "observed_days",
            "description", "vendor_key", *FEATURES]
    train[cols].to_parquet(ART / "train.parquet", index=False)
    predict[cols].to_parquet(ART / "predict.parquet", index=False)

    stats = {
        "train_rows": int(len(train)),
        "predict_rows": int(len(predict)),
        "features": FEATURES,
        "feature_groups": FEATURE_GROUPS,
        "positives": {c: int(train[c].sum()) for c in ["label_any", "label_90", "label_180"]},
        "positives_by_month": train.groupby("snapshot_month")[["label_any", "label_90", "label_180"]].sum().astype(int).to_dict("index"),
        "train_months": sorted(train.snapshot_month.unique().tolist()),
        "predict_months": sorted(predict.snapshot_month.unique().tolist()),
        "missing_predict": {f: int(predict[f].isna().sum()) for f in FEATURES if predict[f].isna().any()},
        "missing_train": {f: int(train[f].isna().sum()) for f in FEATURES if train[f].isna().any()},
    }
    (ART / "feature_meta.json").write_text(json.dumps(stats, indent=2, default=str))
    log(f"train {len(train):,} rows | positives any/90/180 = "
        f"{int(train.label_any.sum())}/{int(train.label_90.sum())}/{int(train.label_180.sum())}")
    log(f"predict {len(predict):,} rows | {len(FEATURES)} features")


if __name__ == "__main__":
    main()
