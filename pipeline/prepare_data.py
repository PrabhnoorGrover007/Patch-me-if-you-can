"""Stage 1: raw CSVs -> columnar artifacts.

Reads the untouched files in data/ and writes Parquet into artifacts/.
Source data is never modified. Run:  python -m pipeline.prepare_data
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import duckdb
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
ART = ROOT / "artifacts"
ART.mkdir(exist_ok=True)

VULN_COLS = [
    "cve_id", "published", "last_modified", "nvd_status", "assigner", "description",
    "cvss3_version", "cvss3_score", "cvss3_severity", "cvss3_vector",
    "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
    "scope", "confidentiality_impact", "integrity_impact", "availability_impact",
    "cvss3_exploitability_score", "cvss3_impact_score", "cvss3_source",
    "cvss4_score", "cvss4_severity", "cvss2_score", "cvss2_severity",
    "cwe_ids", "n_references", "n_affected_cpes",
]


def log(msg: str) -> None:
    print(f"[prepare] {msg}", flush=True)


def build_vulnerabilities() -> pd.DataFrame:
    df = pd.read_csv(DATA / "vulnerabilities.csv", usecols=VULN_COLS, low_memory=False)
    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    df["last_modified"] = pd.to_datetime(df["last_modified"], errors="coerce")
    df["description"] = df["description"].fillna("")
    df.to_parquet(ART / "vulnerabilities.parquet", index=False)
    log(f"vulnerabilities: {len(df):,} rows, published {df.published.min().date()} -> {df.published.max().date()}")
    return df


def build_products(con: duckdb.DuckDBPyConnection) -> None:
    """One row per CVE: primary CPE vendor, product count. 3.16M rows -> ~150k."""
    t0 = time.time()
    con.execute(
        """
        COPY (
          WITH v AS (
            SELECT cve_id, vendor, product
            FROM read_csv(?, header=true, all_varchar=true, quote='"', escape='"', strict_mode=false)
            WHERE vulnerable = 'Y'
          ),
          vend AS (SELECT cve_id, vendor, count(*) AS n FROM v GROUP BY 1, 2),
          top_vend AS (
            SELECT cve_id, vendor FROM (
              SELECT *, row_number() OVER (PARTITION BY cve_id ORDER BY n DESC, vendor) AS rn
              FROM vend
            ) WHERE rn = 1
          ),
          agg AS (SELECT cve_id, count(DISTINCT product) AS n_products FROM v GROUP BY 1)
          SELECT a.cve_id, t.vendor AS cpe_vendor, a.n_products
          FROM agg a LEFT JOIN top_vend t USING (cve_id)
        ) TO ? (FORMAT parquet, COMPRESSION zstd)
        """,
        [str(DATA / "affected_products.csv"), str(ART / "cve_products.parquet")],
    )
    n = con.execute("SELECT count(*) FROM read_parquet(?)", [str(ART / "cve_products.parquet")]).fetchone()[0]
    log(f"cve_products: {n:,} rows in {time.time() - t0:.1f}s")


def build_signals(con: duckdb.DuckDBPyConnection) -> None:
    t0 = time.time()
    con.execute(
        """
        COPY (
          SELECT month, cve_id,
                 CASE WHEN epss = '' THEN NULL ELSE CAST(epss AS DOUBLE) END AS epss,
                 CAST(in_kev AS TINYINT) AS in_kev,
                 CAST(exploitdb AS TINYINT) AS exploitdb,
                 CAST(metasploit AS TINYINT) AS metasploit,
                 CAST(nuclei AS TINYINT) AS nuclei,
                 CAST(poc_github AS TINYINT) AS poc_github
          FROM read_csv([?, ?], header=true, all_varchar=true, quote='"', escape='"', strict_mode=false)
        ) TO ? (FORMAT parquet, COMPRESSION zstd)
        """,
        [str(DATA / "exploit_signals_2024.csv"), str(DATA / "exploit_signals_2025.csv"),
         str(ART / "signals.parquet")],
    )
    stats = con.execute(
        "SELECT count(*), count(DISTINCT month), min(month), max(month) FROM read_parquet(?)",
        [str(ART / "signals.parquet")],
    ).fetchone()
    log(f"signals: {stats[0]:,} rows, months {stats[1]} ({stats[2]} -> {stats[3]}) in {time.time() - t0:.1f}s")


def build_kev() -> pd.DataFrame:
    kev = pd.read_csv(DATA / "known_exploited.csv")
    kev["date_added"] = pd.to_datetime(kev["date_added"], errors="coerce")
    kev["kev_vendor"] = kev["vendor"].str.strip().str.lower()
    kev["ransomware"] = (kev["known_ransomware_use"] == "Known").astype("int8")
    kev.to_parquet(ART / "kev.parquet", index=False)
    log(f"kev: {len(kev):,} rows, added {kev.date_added.min().date()} -> {kev.date_added.max().date()}")
    return kev


def build_scoreboard(vuln: pd.DataFrame) -> pd.DataFrame:
    sb = pd.read_csv(DATA / "scoreboard_2026.csv")
    sb["published"] = pd.to_datetime(sb["published"], errors="coerce")
    sb["snapshot_month"] = sb["snapshot_month"].astype(str)
    for c in ["epss", "exploitdb", "metasploit", "nuclei", "poc_github"]:
        sb[c] = pd.to_numeric(sb[c], errors="coerce")
    for c in ["exploitdb", "metasploit", "nuclei", "poc_github"]:
        sb[c] = sb[c].fillna(0).astype("int8")
    sb = sb.merge(
        vuln[["cve_id", "assigner", "description", "cvss3_score", "cvss3_severity", "cwe_ids",
              "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
              "scope", "confidentiality_impact", "integrity_impact", "availability_impact",
              "cvss3_exploitability_score", "cvss3_impact_score", "cvss3_vector",
              "cvss4_score", "cvss2_score", "published"]].rename(columns={"published": "vuln_published"}),
        on="cve_id", how="left", validate="one_to_one",
    )
    mismatch = int((sb["published"] != sb["vuln_published"]).sum())
    sb["snapshot_end"] = pd.to_datetime(sb["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0)
    sb.to_parquet(ART / "scoreboard.parquet", index=False)
    log(f"scoreboard: {len(sb):,} rows, snapshot months {sb.snapshot_month.nunique()}, "
        f"joined description {sb.description.notna().mean():.4f}, published mismatch {mismatch}")
    return sb


def build_reference_summary(con: duckdb.DuckDBPyConnection) -> None:
    """Reference-domain aggregates are NOT model features (post-hoc leak). Used only for
    the leak audit and the discovery narrative, so we summarise instead of loading 1.36M rows."""
    t0 = time.time()
    con.execute(
        """
        COPY (
          SELECT domain, count(*) AS n_refs, count(DISTINCT cve_id) AS n_cves,
                 sum(CASE WHEN tags LIKE '%Exploit%' THEN 1 ELSE 0 END) AS n_exploit_tagged
          FROM read_csv(?, header=true, all_varchar=true, quote='"', escape='"', strict_mode=false)
          GROUP BY 1 ORDER BY n_refs DESC
        ) TO ? (FORMAT parquet)
        """,
        [str(DATA / "references.csv"), str(ART / "reference_domains.parquet")],
    )
    log(f"reference_domains: summarised in {time.time() - t0:.1f}s")


def main() -> None:
    t0 = time.time()
    vuln = build_vulnerabilities()
    con = duckdb.connect()
    con.execute("PRAGMA threads=4")
    build_products(con)
    build_signals(con)
    build_reference_summary(con)
    kev = build_kev()
    sb = build_scoreboard(vuln)

    summary = {
        "vulnerabilities": int(len(vuln)),
        "kev": int(len(kev)),
        "scoreboard": int(len(sb)),
        "scoreboard_snapshot_months": sorted(sb.snapshot_month.unique().tolist()),
        "scoreboard_missing_cvss3": int(sb.cvss3_score.isna().sum()),
        "scoreboard_missing_epss": int(sb.epss.isna().sum()),
        "kev_max_date": str(kev.date_added.max().date()),
        "seconds": round(time.time() - t0, 1),
    }
    (ART / "stage1_summary.json").write_text(json.dumps(summary, indent=2))
    log(f"done in {time.time() - t0:.1f}s -> artifacts/")


if __name__ == "__main__":
    main()
