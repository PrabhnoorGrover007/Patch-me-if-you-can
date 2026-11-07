"""
prepare_data.py - turn the raw IBM challenge CSVs into two model-ready files.

    outputs/train.csv        historical CVEs (2024-01 .. 2025-11) with a 0/1 `label`
    outputs/predict_2026.csv the 72,670 scoreboard CVEs, same features, no label

The full rules (cutoffs, label window, every feature) are in docs/data_contract.md.

Big idea: every row describes a CVE *as it looked at the end of its snapshot month*.
Features may only use information that existed at that moment.

Usage (PowerShell):
    python prepare_data.py --data-dir data --out-dir outputs
"""

import argparse
import re
import time
from pathlib import Path

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
TRAIN_PUBLISHED_FROM = pd.Timestamp("2024-01-01")
TRAIN_PUBLISHED_TO = pd.Timestamp("2025-11-30")  # Dec 2025 would have a 0-day outcome window
LABEL_CUTOFF = pd.Timestamp("2025-12-31")  # last KEV date in known_exploited.csv
EXPECTED_PREDICT_ROWS = 72_670
CVSS_FILL_VALUE = 7.5  # constant fill, no "missing" flag (blank CVSS leaks NIST review status)
EPSS_V4_START = "2025-03"  # EPSS changed its model in March 2025

# Months whose signal file is incomplete -> use the next month instead
SNAPSHOT_OVERRIDES = {"2025-02": "2025-03"}

FLAG_COLUMNS = ["exploitdb", "metasploit", "nuclei", "poc_github"]

# Description keywords (lower-case regex). Text is set by the vendor at publication, so
# these are the most defensible "what kind of bug is it" signals we have.
KEYWORD_PATTERNS = {
    "kw_rce": r"remote code execution|arbitrary code execution|execute arbitrary code|code execution",
    "kw_command_injection": r"command injection|code injection|execute arbitrary (?:os |system |shell )?commands|inject (?:arbitrary )?(?:os )?commands",
    "kw_auth_bypass": r"authentication bypass|bypass (?:the )?authentication|auth bypass|missing authentication|improper authentication",
    "kw_unauthenticated": r"unauthenticated|without authentication|unauthorized remote",
    "kw_deserialization": r"deserializ",
    "kw_path_traversal": r"path traversal|directory traversal|\.\./",
    "kw_sql_injection": r"sql injection",
    "kw_memory_corruption": r"buffer overflow|use[- ]after[- ]free|out[- ]of[- ]bounds write|type confusion|heap (?:corruption|overflow)|memory corruption|stack[- ]based (?:buffer )?overflow",
    "kw_privilege_escalation": r"privilege escalation|escalat\w* (?:of )?privileges?|elevation of privilege|elevate privileges|gain (?:root|administrator|elevated) privileges",
    "kw_xss": r"cross[- ]site scripting|\bxss\b",
    "kw_dos": r"denial[- ]of[- ]service|\bdos\b",
    "kw_edge_device": r"\bvpn\b|firewall|gateway|router|load balancer|remote access|appliance|edge device",
    "kw_exploited_in_wild": r"exploited in the wild|may have been exploited|actively exploited|exploitation in the wild|has been exploited",
    "kw_wordpress": r"wordpress",
}

# The exact feature list shared with model.py (see docs/data_contract.md section 4c)
FEATURE_COLUMNS = (
    ["epss", "epss_missing", "epss_pct_in_month", "epss_v4"]
    + FLAG_COLUMNS
    + ["n_exploit_sources", "days_public_at_cutoff",
       "cvss_score", "cvss_network", "cvss_no_privileges", "cvss_no_user_interaction"]
    + list(KEYWORD_PATTERNS)
    + ["desc_length", "vendor_prior_kev_count", "assigner_prior_kev_count"]
)
ID_COLUMNS = ["cve_id", "published", "snapshot_month", "snapshot_end", "description"]
TRAIN_ONLY_COLUMNS = ["label", "label_window_days"]

# Columns that must never reach the output files (leakage bans)
BANNED_COLUMNS = {"nvd_status", "n_affected_cpes", "n_references", "in_kev", "date_added",
                  "last_modified", "kev_date_added"}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# 1. Load raw data (only the columns we need)
# ---------------------------------------------------------------------------
def load_vulnerabilities(data_dir):
    """Read vulnerabilities.csv in chunks.

    We keep cve_id/published/assigner for ALL CVEs (needed to know which organisation
    assigned past KEV CVEs) but only keep descriptions and CVSS for CVEs published 2024+,
    which keeps memory low.
    """
    cols = ["cve_id", "published", "assigner", "description",
            "cvss3_score", "attack_vector", "privileges_required", "user_interaction",
            "cvss4_score", "cvss4_vector"]
    keep_all, keep_recent = [], []
    for chunk in pd.read_csv(data_dir / "vulnerabilities.csv", usecols=cols, dtype=str,
                             chunksize=100_000):
        chunk["published"] = pd.to_datetime(chunk["published"], errors="coerce")
        keep_all.append(chunk[["cve_id", "published", "assigner"]])
        keep_recent.append(chunk[chunk["published"] >= TRAIN_PUBLISHED_FROM])
    all_vulns = pd.concat(keep_all, ignore_index=True).drop_duplicates("cve_id")
    recent = pd.concat(keep_recent, ignore_index=True).drop_duplicates("cve_id")
    log(f"vulnerabilities: {len(all_vulns):,} total, {len(recent):,} published 2024+")
    return all_vulns, recent


def load_kev(data_dir):
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "vendor", "date_added"],
                      dtype=str)
    kev["date_added"] = pd.to_datetime(kev["date_added"], errors="coerce")
    kev = kev.dropna(subset=["date_added"]).sort_values("date_added").drop_duplicates("cve_id")
    log(f"KEV: {len(kev):,} rows, {kev.date_added.min().date()} .. {kev.date_added.max().date()}")
    return kev


def load_signals_for(data_dir, wanted):
    """Read the 2024/2025 monthly signal files in chunks and keep only (cve_id, month)
    pairs we actually need (each training CVE at its snapshot month)."""
    keys = wanted[["cve_id", "snapshot_month"]].rename(columns={"snapshot_month": "month"})
    dtypes = {"month": str, "cve_id": str, "epss": "float64", "in_kev": "Int8",
              **{c: "Int8" for c in FLAG_COLUMNS}}
    parts = []
    for year in (2024, 2025):
        for chunk in pd.read_csv(data_dir / f"exploit_signals_{year}.csv", dtype=dtypes,
                                 chunksize=500_000):
            parts.append(chunk.merge(keys, on=["cve_id", "month"], how="inner"))
    signals = pd.concat(parts, ignore_index=True).drop_duplicates(["cve_id", "month"])
    log(f"signals matched at snapshot month: {len(signals):,} of {len(wanted):,} training CVEs")
    return signals.rename(columns={"month": "snapshot_month"})


# ---------------------------------------------------------------------------
# 2. Build the training cohort and labels
# ---------------------------------------------------------------------------
def month_end(month_str):
    return pd.PeriodIndex(month_str, freq="M").to_timestamp(how="end").normalize()


def build_train_base(recent, kev, data_dir):
    """Pick training CVEs, give each a snapshot month, attach signals, drop CVEs already
    on KEV at the cutoff, and create the label."""
    base = recent[(recent["published"] >= TRAIN_PUBLISHED_FROM)
                  & (recent["published"] <= TRAIN_PUBLISHED_TO)].copy()
    base["snapshot_month"] = base["published"].dt.strftime("%Y-%m").replace(SNAPSHOT_OVERRIDES)
    base["snapshot_end"] = month_end(base["snapshot_month"])

    signals = load_signals_for(data_dir, base)
    base = base.merge(signals, on=["cve_id", "snapshot_month"], how="left")

    base = base.merge(kev[["cve_id", "date_added"]], on="cve_id", how="left")
    already_on_kev = (base["date_added"] <= base["snapshot_end"]) | (base["in_kev"] == 1)
    log(f"dropping {int(already_on_kev.sum()):,} CVEs already on KEV at their cutoff "
        "(the scoreboard excludes these too)")
    base = base[~already_on_kev].copy()

    # Label: added to KEV after the cutoff and by the last KEV date we have
    base["label"] = ((base["date_added"] > base["snapshot_end"])
                     & (base["date_added"] <= LABEL_CUTOFF)).astype(int)
    base["label_window_days"] = (LABEL_CUTOFF - base["snapshot_end"]).dt.days.astype(int)
    base = base.drop(columns=["date_added", "in_kev"])
    log(f"training rows: {len(base):,}, positives: {int(base.label.sum())}")
    return base


def build_predict_base(recent, data_dir):
    sb = pd.read_csv(data_dir / "scoreboard_2026.csv", dtype={"cve_id": str, "snapshot_month": str})
    sb = sb.drop_duplicates("cve_id")
    sb["published"] = pd.to_datetime(sb["published"], errors="coerce")
    sb["snapshot_end"] = month_end(sb["snapshot_month"])
    info = recent.drop(columns=["published"])
    sb = sb.merge(info, on="cve_id", how="left")
    log(f"scoreboard rows: {len(sb):,} (missing in vulnerabilities.csv: "
        f"{int(sb['assigner'].isna().sum())})")
    return sb


# ---------------------------------------------------------------------------
# 3. Feature engineering (same functions for train and predict)
# ---------------------------------------------------------------------------
def add_signal_features(df):
    """EPSS + exploit flags at the cutoff. Missing signal row -> EPSS 0 and flags 0."""
    df["epss_missing"] = df["epss"].isna().astype(int)
    df["epss"] = df["epss"].fillna(0.0).astype(float)
    for c in FLAG_COLUMNS:
        df[c] = df[c].fillna(0).astype(int)
    df["n_exploit_sources"] = df[FLAG_COLUMNS].sum(axis=1).astype(int)
    # Percentile of EPSS within the same snapshot month: removes the v3 -> v4 scale jump
    pct = df.loc[df["epss_missing"] == 0].groupby("snapshot_month")["epss"].rank(pct=True)
    df["epss_pct_in_month"] = pct.reindex(df.index).fillna(0.0)
    df["epss_v4"] = (df["snapshot_month"] >= EPSS_V4_START).astype(int)
    df["days_public_at_cutoff"] = (df["snapshot_end"] - df["published"]).dt.days.astype(int)
    return df


def add_cvss_features(df):
    """CVSS 3 score, else CVSS 4 score, else constant 7.5. No missing-indicator on purpose."""
    s3 = pd.to_numeric(df["cvss3_score"], errors="coerce")
    s4 = pd.to_numeric(df["cvss4_score"], errors="coerce")
    df["cvss_score"] = s3.fillna(s4).fillna(CVSS_FILL_VALUE).astype(float)
    v4 = df["cvss4_vector"].fillna("")
    av = df["attack_vector"].fillna("")
    pr = df["privileges_required"].fillna("")
    ui = df["user_interaction"].fillna("")
    has3 = av != ""
    df["cvss_network"] = np.where(has3, av == "NETWORK", v4.str.contains("AV:N")).astype(int)
    df["cvss_no_privileges"] = np.where(has3, pr == "NONE", v4.str.contains("PR:N")).astype(int)
    df["cvss_no_user_interaction"] = np.where(has3, ui == "NONE", v4.str.contains("UI:N")).astype(int)
    return df


def add_keyword_features(df):
    text = df["description"].fillna("").str.lower()
    for name, pattern in KEYWORD_PATTERNS.items():
        df[name] = text.str.contains(pattern, regex=True).astype(int)
    df["desc_length"] = df["description"].fillna("").str.len().astype(int)
    return df


def prior_count(dates_by_key, keys, cutoffs):
    """For each row: how many KEV additions for its key happened strictly before its cutoff."""
    out = np.zeros(len(keys), dtype=int)
    for i, (k, cut) in enumerate(zip(keys, cutoffs)):
        dates = dates_by_key.get(k)
        if dates is not None:
            out[i] = np.searchsorted(dates, cut, side="left")
    return out


def add_history_features(df, kev, all_vulns):
    """Point-in-time vendor history: KEV additions dated before the snapshot month starts."""
    month_start = pd.PeriodIndex(df["snapshot_month"], freq="M").to_timestamp().values

    # (a) by assigning organisation (CNA), e.g. secure@microsoft.com
    kev_assigner = kev.merge(all_vulns[["cve_id", "assigner"]], on="cve_id", how="left")
    by_assigner = {a: np.sort(g["date_added"].values)
                   for a, g in kev_assigner.dropna(subset=["assigner"]).groupby("assigner")}
    df["assigner_prior_kev_count"] = prior_count(by_assigner, df["assigner"].fillna(""), month_start)

    # (b) by KEV vendor name mentioned in the description (case-sensitive whole word)
    by_vendor = {v: np.sort(g["date_added"].values) for v, g in kev.groupby("vendor")}
    names = sorted((v for v in by_vendor if len(v) >= 2), key=len, reverse=True)
    vendor_re = re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b")
    mentioned = df["description"].fillna("").map(lambda t: set(vendor_re.findall(t)))
    counts = np.zeros(len(df), dtype=int)
    for i, (vendors, cut) in enumerate(zip(mentioned, month_start)):
        for v in vendors:
            counts[i] = max(counts[i], np.searchsorted(by_vendor[v], cut, side="left"))
    df["vendor_prior_kev_count"] = counts
    return df


def engineer_features(df, kev, all_vulns):
    df = df.reset_index(drop=True)
    df = add_signal_features(df)
    df = add_cvss_features(df)
    df = add_keyword_features(df)
    df = add_history_features(df, kev, all_vulns)
    return df


# ---------------------------------------------------------------------------
# 4. Validation
# ---------------------------------------------------------------------------
def validate(train, predict):
    problems = []
    if len(predict) != EXPECTED_PREDICT_ROWS:
        problems.append(f"predict has {len(predict)} rows, expected {EXPECTED_PREDICT_ROWS}")
    for name, df in (("train", train), ("predict", predict)):
        if df["cve_id"].duplicated().any():
            problems.append(f"{name} has duplicate cve_id")
        if df[FEATURE_COLUMNS].isna().any().any():
            problems.append(f"{name} has blanks in feature columns")
        if BANNED_COLUMNS & set(df.columns):
            problems.append(f"{name} contains banned columns {BANNED_COLUMNS & set(df.columns)}")
        if (df["snapshot_end"] < df["published"]).any():
            problems.append(f"{name} has cutoff before publish date")
        if not np.isfinite(df[FEATURE_COLUMNS].to_numpy(dtype=float)).all():
            problems.append(f"{name} has non-finite feature values")
    if "label" in predict.columns:
        problems.append("predict contains a label column")
    if not set(train["label"].unique()) <= {0, 1}:
        problems.append("label is not 0/1")
    if (train["snapshot_end"] >= LABEL_CUTOFF).any():
        problems.append("training cutoff at/after label cutoff")
    if problems:
        raise SystemExit("VALIDATION FAILED:\n  - " + "\n  - ".join(problems))
    log("validation passed: row counts, unique IDs, no blanks, no banned columns, valid dates")


# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
REQUIRED_RAW_FILES = ["vulnerabilities.csv", "known_exploited.csv", "exploit_signals_2024.csv",
                      "exploit_signals_2025.csv", "scoreboard_2026.csv"]


def check_raw_files(data_dir):
    """Stop early with a clear message if the raw CSVs are not where we expect them."""
    missing = [f for f in REQUIRED_RAW_FILES if not (data_dir / f).exists()]
    if missing:
        raise SystemExit(
            f"Missing raw files in '{data_dir.resolve()}': {', '.join(missing)}\n"
            "Unzip data.zip in the repo root (it creates a data\\ folder) or pass --data-dir.")


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", default="data", help="folder with the raw CSVs")
    parser.add_argument("--out-dir", default="outputs")
    args = parser.parse_args()
    data_dir, out_dir = Path(args.data_dir), Path(args.out_dir)
    check_raw_files(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_vulns, recent = load_vulnerabilities(data_dir)
    kev = load_kev(data_dir)

    train = engineer_features(build_train_base(recent, kev, data_dir), kev, all_vulns)
    predict = engineer_features(build_predict_base(recent, data_dir), kev, all_vulns)

    train = train[ID_COLUMNS + FEATURE_COLUMNS + TRAIN_ONLY_COLUMNS].sort_values(["snapshot_month", "cve_id"])
    predict = predict[ID_COLUMNS + FEATURE_COLUMNS].sort_values(["snapshot_month", "cve_id"])
    validate(train, predict)

    for df in (train, predict):
        df["published"] = df["published"].dt.strftime("%Y-%m-%d")
        df["snapshot_end"] = df["snapshot_end"].dt.strftime("%Y-%m-%d")
    train.to_csv(out_dir / "train.csv", index=False)
    predict.to_csv(out_dir / "predict_2026.csv", index=False)
    log(f"wrote {out_dir / 'train.csv'} ({len(train):,} rows, {int(train.label.sum())} positives)")
    log(f"wrote {out_dir / 'predict_2026.csv'} ({len(predict):,} rows)")


if __name__ == "__main__":
    main()
