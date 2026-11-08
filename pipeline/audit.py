"""Formal feature-availability audit.

For every feature we record: source, calculation, whether it is available at prediction time,
its leakage risk, whether it is in the final model, and why. Also documents the columns we
deliberately excluded. Writes artifacts/feature_audit.json and docs/FEATURE_AUDIT.md.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline.features import FEATURE_GROUPS, KEYWORDS, TOP_CWES

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

GROUP_META = {
    "calendar": {
        "source": "vulnerabilities.csv (published) + snapshot_month",
        "calc": "Publication month, day-of-week, day-of-month, and days between publication and snapshot month end",
        "available": True,
        "risk": "none",
        "why": "Timestamps known at publication and at the snapshot boundary",
    },
    "cvss": {
        "source": "vulnerabilities.csv CVSS 3/2/4 fields",
        "calc": "Numeric components and CVSS vector decomposition; missing values median-imputed before the model sees them",
        "available": True,
        "risk": "medium — blank severity is itself a NIST-review signal, so a tree must not be able to split on 'missing'; the imputer removes that split",
        "why": "Severity components are the baseline comparator; missingness is filled, never encoded",
    },
    "epss_exploit": {
        "source": "exploit_signals_2024/2025.csv (train) and scoreboard_2026.csv (predict)",
        "calc": "EPSS score, logit, within-month percentile, missing flag; Exploit-DB / Metasploit / Nuclei / GitHub PoC flags",
        "available": True,
        "risk": "none — these files are exactly the state at month end by construction",
        "why": "Only source of public-exposure evidence that is provably as-of",
    },
    "vendor_history": {
        "source": "vulnerabilities.csv assigner + known_exploited.csv date_added",
        "calc": "Vendor key from the CVE assigner domain; KEV counts and rates computed with date_added <= month end; 90/365-day recency windows",
        "available": True,
        "risk": "low — assigner is fixed at ID reservation; the CISA-ADP GUID assigner is collapsed to a neutral key because ADP enrichment is applied after publication",
        "why": "84% of KEV entries come from vendors already represented in KEV",
    },
    "text": {
        "source": "vulnerabilities.csv description",
        "calc": f"Length/word counts and {len(KEYWORDS)} regex indicators (RCE, deserialisation, auth bypass, ...)",
        "available": True,
        "risk": "low — descriptions are written at publication; a minority are edited later, so keyword rates are a lower bound",
        "why": "Descriptions carry wording that CVSS does not encode",
    },
    "interactions": {
        "source": "derived",
        "calc": "epss x exploit-code, WordPress-ecosystem and GitHub-CNA flags, 'silent critical' flag",
        "available": True,
        "risk": "none — products of already-validated features",
        "why": "Captures conditional effects additive models miss, with no new data dependency",
    },
    "horizon": {
        "source": "snapshot_month + evaluation cutoff",
        "calc": "Days from snapshot month end to the evaluation cutoff (2025-12-29 for train, 2026-11-04 for the competition)",
        "available": True,
        "risk": "low — the cutoff is a published competition rule, not per-CVE information",
        "why": "Exposure windows differ by cohort; without it the model cannot distinguish a 10-month from a 1-month window",
    },
    "granite": {
        "source": "ibm-granite/granite-embedding-30m-english over CVE descriptions",
        "calc": "Max and mean-of-top-5 cosine similarity to KEV descriptions added BEFORE the row's snapshot month end",
        "available": True,
        "risk": "none — the reference set is nested by month; future KEV additions are masked out",
        "why": "Adds a semantic signal that is independent of CVSS and EPSS",
    },
}

EXCLUDED = [
    ("nvd_status", "NIST reviews attacked CVEs first; status is a post-hoc signal", "Excluded from all features"),
    ("n_affected_cpes", "CPE rows are added during NVD analysis; 49.6% of the 2026 pool is blank", "Excluded"),
    ("n_references", "Reference count grows after exploitation is reported", "Excluded"),
    ("references.url / domain / tags", "News and threat-research links are added after attacks; 37,853 IBM X-Force links alone", "Summarised for the audit only, never a feature"),
    ("blank cvss3_score as signal", "Blank severity means NIST has not reviewed the record yet, and NIST reviews attacked CVEs first", "Median-imputed before the model sees it; no missingness indicator"),
    ("cwe_ids missingness (cwe_missing, has_cwe_* dummies, cwe_kev_rate_*)", "CWE is assigned during NVD analysis, so a blank weakness class carries the same review-status signal as a blank score", "Dropped from the model entirely: the model was selecting only reviewed CVEs"),
    ("last_modified", "Every row is stamped mid-2026 or later", "Excluded"),
    ("assigner == CISA-ADP GUID", "ADP enrichment is applied after publication", "Collapsed to a neutral category"),
    ("affected_products vendor/product", "CPE coverage itself leaks NVD attention", "Excluded from the model; used only in EDA"),
]


def main() -> None:
    rows = []
    for group, feats in FEATURE_GROUPS.items():
        meta = GROUP_META[group]
        for f in feats:
            rows.append({"feature": f, "group": group, **meta, "included": True})
    rows.append({"feature": "granite_knn_max", "group": "granite", **GROUP_META["granite"], "included": True})
    rows.append({"feature": "granite_knn_mean5", "group": "granite", **GROUP_META["granite"], "included": True})

    payload = {
        "features": rows,
        "n_features": len(rows),
        "excluded": [{"column": c, "reason": r, "decision": d} for c, r, d in EXCLUDED],
        "principle": "a feature is admissible only if its value could have been known at the end of the "
                     "vulnerability's snapshot month",
    }
    (ART / "feature_audit.json").write_text(json.dumps(payload, indent=2))

    lines = [
        "# Feature availability audit", "",
        "Every feature is admissible only if its value could have been known at the end of the "
        "vulnerability's `snapshot_month`. This table is generated by `python -m pipeline.audit`.", "",
        f"Features in the final model: **{len(rows)}**.", "",
        "| Feature group | Source | Calculation | Available at snapshot | Leakage risk | In model | Justification |",
        "|---|---|---|---|---|---|---|",
    ]
    for group, meta in GROUP_META.items():
        n = len(FEATURE_GROUPS.get(group, [])) + (2 if group == "granite" else 0)
        lines.append(
            f"| **{group}** ({n}) | {meta['source']} | {meta['calc']} | "
            f"{'yes' if meta['available'] else 'no'} | {meta['risk']} | yes | {meta['why']} |"
        )
    lines += ["", "## Deliberately excluded columns", "",
              "| Column | Why it is unsafe | Decision |", "|---|---|---|"]
    lines += [f"| `{c}` | {r} | {d} |" for c, r, d in EXCLUDED]
    lines += ["", "## Notes", "",
              "- CWE features are not in the model: blank CWE tracks NIST review, and a multi-hot encoding "
              "makes 'no weakness class' a distinct, learnable pattern.",
              f"- Text indicators ({len(KEYWORDS)}): " + ", ".join(sorted(KEYWORDS)),
              "- Proc- and CPE-derived vendor/product features are excluded from the model because 49.6% of the "
              "2026 pool lacks them for reasons that correlate with NVD attention.",
              "- Exploit-signal files cover 2024-01 to 2025-12 only; 2023 cohorts are therefore excluded from "
              "training rather than imputed, because a fully-missing EPSS column is not a neutral imputation."]
    (DOCS / "FEATURE_AUDIT.md").write_text("\n".join(lines) + "\n")
    print(f"[audit] {len(rows)} features, {len(EXCLUDED)} excluded columns -> docs/FEATURE_AUDIT.md")


if __name__ == "__main__":
    main()
