"""Score candidate top-500 submissions against the live CISA KEV catalogue.

The 2026 answer key is absent from the release, so this script rebuilds it from
CISA's public feed using the benchmark's own definitions:

    positive = the CVE is in KEV, with dateAdded strictly after the end of its
               own snapshot_month, and on or before --cutoff

Two submissions are then compared on the official metric (how many exploited
CVEs are inside the 500-row list), on precision at the top of the list, on how
much they overlap, and with a paired bootstrap for the difference.

This is evaluation only: nothing here feeds a feature, a weight or a threshold.

Usage
-----
    python eval/compare_submissions.py top500.csv other_top500.csv --names ours,theirs
    python eval/compare_submissions.py top500.csv --cutoff 2026-11-04

Outputs a table on stdout and artifacts/submission_comparison.json.

The KEV feed is downloaded on first run and cached in data/external/kev_live.json;
delete that file to refresh it.
"""

from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOREBOARD = ROOT / "data" / "scoreboard_2026.csv"
DEFAULT_KEV = ROOT / "data" / "external" / "kev_live.json"
DEFAULT_OUT = ROOT / "artifacts" / "submission_comparison.json"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KS = (50, 100, 250, 500)


def load_kev(path: Path) -> pd.DataFrame:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading KEV feed -> {path}")
        urllib.request.urlretrieve(KEV_URL, path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload["vulnerabilities"]

    def pick(row: dict, *keys: str) -> str:
        for key in keys:
            if key in row:
                return row[key]
        raise KeyError(f"none of {keys} in KEV entry: {sorted(row)}")

    kev = pd.DataFrame({"cve_id": [pick(r, "cveID", "cveId", "cve_id") for r in rows],
                        "date_added": [pick(r, "dateAdded", "date_added") for r in rows]})
    kev["date_added"] = pd.to_datetime(kev["date_added"])
    kev.attrs["catalog_version"] = payload.get("catalogVersion")
    kev.attrs["released"] = payload.get("dateReleased")
    return kev


def build_truth(scoreboard: pd.DataFrame, kev: pd.DataFrame, cutoff: pd.Timestamp):
    """Positives: KEV additions after the row's snapshot month end, up to cutoff."""
    sb = scoreboard.copy()
    sb["month_end"] = sb["snapshot_month"].map(
        lambda m: pd.Period(str(m), freq="M").end_time.normalize()
    )
    merged = sb.merge(kev, on="cve_id", how="inner")
    merged = merged[(merged["date_added"] > merged["month_end"])
                    & (merged["date_added"] <= cutoff)]
    return merged


def load_submission(path: Path) -> list[str]:
    df = pd.read_csv(path)
    if df.shape[1] != 1:
        raise SystemExit(f"{path}: expected exactly one column, found {df.shape[1]}")
    ids = df.iloc[:, 0].astype(str).str.strip().tolist()
    return ids


def score(ids: list[str], positives: set[str], pool: set[str]) -> dict:
    in_pool = [c for c in ids if c in pool]
    hits = [c for c in ids if c in positives]
    out = {
        "rows": len(ids),
        "unique": len(set(ids)),
        "valid_in_scoreboard": len(in_pool),
        "invalid": sorted(set(ids) - pool)[:10],
        "hits_at": {k: sum(1 for c in ids[:k] if c in positives) for k in KS},
        "hit_ids": hits,
    }
    return out


def paired_bootstrap(a: list[str], b: list[str], positives: set[str],
                     n: int = 5000, seed: int = 0) -> dict:
    """Percentile interval for hits(A) - hits(B) over resampled positives."""
    pos = np.array(sorted(positives))
    ma = np.isin(pos, np.array(a))
    mb = np.isin(pos, np.array(b))
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(pos), size=(n, len(pos)))
    diffs = ma[idx].sum(axis=1) - mb[idx].sum(axis=1)
    return {
        "point": int(ma.sum() - mb.sum()),
        "lo": int(np.percentile(diffs, 2.5)),
        "hi": int(np.percentile(diffs, 97.5)),
        "p_not_better": float((diffs <= 0).mean()),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("submissions", nargs="+", type=Path)
    ap.add_argument("--names", default=None, help="comma-separated labels, same order")
    ap.add_argument("--scoreboard", type=Path, default=DEFAULT_SCOREBOARD)
    ap.add_argument("--kev", type=Path, default=DEFAULT_KEV)
    ap.add_argument("--cutoff", default="2026-11-04",
                    help="last KEV date counted (default matches the benchmark's 4 Nov 2026)")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    cutoff = pd.Timestamp(args.cutoff)
    scoreboard = pd.read_csv(args.scoreboard)
    kev = load_kev(args.kev)
    truth = build_truth(scoreboard, kev, cutoff)
    positives = set(truth["cve_id"])
    pool = set(scoreboard["cve_id"])

    names = (args.names.split(",") if args.names
             else [p.stem for p in args.submissions])
    lists = [load_submission(p) for p in args.submissions]
    results = {name: score(ids, positives, pool) for name, ids in zip(names, lists)}

    print(f"KEV catalogue {kev.attrs['catalog_version']} (released {kev.attrs['released']})")
    print(f"Cutoff {cutoff.date()} | scoreboard {len(pool):,} CVEs | "
          f"positives {len(positives)} ({len(positives) / len(pool):.3%})")
    print()
    header = f"{'submission':<22}{'valid':>7}" + "".join(f"{'@' + str(k):>7}" for k in KS)
    print(header)
    print("-" * len(header))
    for name, r in results.items():
        line = f"{name:<22}{r['valid_in_scoreboard']:>7}"
        line += "".join(f"{r['hits_at'][k]:>7}" for k in KS)
        print(line)

    print()
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = results[names[i]], results[names[j]]
            both = set(a["hit_ids"]) & set(b["hit_ids"])
            only_a = set(a["hit_ids"]) - set(b["hit_ids"])
            only_b = set(b["hit_ids"]) - set(a["hit_ids"])
            boot = paired_bootstrap(a["hit_ids"], b["hit_ids"], positives)
            overlap = len(set(lists[i]) & set(lists[j])) / 500
            print(f"{names[i]} vs {names[j]}: shared hits {len(both)}, "
                  f"only {names[i]} {len(only_a)}, only {names[j]} {len(only_b)}")
            print(f"  list overlap {overlap:.1%} of 500 | "
                  f"difference {boot['point']:+d} "
                  f"(95% CI {boot['lo']:+d} to {boot['hi']:+d}, "
                  f"P({names[i]} not better) {boot['p_not_better']:.2f})")
            if only_a:
                print(f"  unique to {names[i]}: {', '.join(sorted(only_a)[:8])}")
            if only_b:
                print(f"  unique to {names[j]}: {', '.join(sorted(only_b)[:8])}")

    by_month = (truth.assign(month=truth["snapshot_month"].astype(str))
                .groupby("month")["cve_id"].apply(set).to_dict())
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "method": "positive = KEV dateAdded strictly after snapshot_month end, on/before cutoff",
        "kev_catalog_version": kev.attrs["catalog_version"],
        "kev_released": kev.attrs["released"],
        "cutoff": str(cutoff.date()),
        "pool_size": len(pool),
        "positives": len(positives),
        "positive_by_month": {k: len(v) for k, v in sorted(by_month.items())},
        "submissions": {
            name: {k: v for k, v in r.items() if k != "hit_ids"}
            | {"hits_by_month": {m: len(set(ids) & s) for m, s in sorted(by_month.items())}}
            for (name, r), ids in zip(results.items(), lists)
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nwrote {args.out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
