"""
validate_outputs.py - end-to-end checks. Run after prepare_data.py and model.py.

    python validate_outputs.py --data-dir data --out-dir outputs

Prints PASS/FAIL per check and exits with code 1 if anything fails.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from prepare_data import BANNED_COLUMNS, FEATURE_COLUMNS, LABEL_CUTOFF

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data-dir", default="data")
    p.add_argument("--out-dir", default="outputs")
    p.add_argument("--skip-repro", action="store_true", help="skip re-running model.py")
    a = p.parse_args()
    data_dir, out = Path(a.data_dir), Path(a.out_dir)

    # --- files exist
    files = ["train.csv", "predict_2026.csv", "ranked_2026.csv", "top500.csv", "validation_results.json"]
    for f in files:
        check(f"outputs/{f} exists", (out / f).exists())
    for f in ["vulnerabilities.csv", "known_exploited.csv", "scoreboard_2026.csv",
              "exploit_signals_2024.csv", "exploit_signals_2025.csv"]:
        check(f"data/{f} exists", (data_dir / f).exists())
    if not all(results):
        sys.exit(1)

    train = pd.read_csv(out / "train.csv", dtype={"cve_id": str, "snapshot_month": str})
    pred = pd.read_csv(out / "predict_2026.csv", dtype={"cve_id": str, "snapshot_month": str})
    ranked = pd.read_csv(out / "ranked_2026.csv", dtype={"cve_id": str})
    top = pd.read_csv(out / "top500.csv", dtype=str)
    sb = pd.read_csv(data_dir / "scoreboard_2026.csv", dtype={"cve_id": str})
    kev = pd.read_csv(data_dir / "known_exploited.csv", usecols=["cve_id", "date_added"], dtype=str)

    # --- data checks
    check("predict has 72,670 rows", len(pred) == 72_670, str(len(pred)))
    check("predict cve_id unique", not pred.cve_id.duplicated().any())
    check("train cve_id unique", not train.cve_id.duplicated().any())
    check("predict IDs == scoreboard IDs", set(pred.cve_id) == set(sb.cve_id))
    check("no label in predict", "label" not in pred.columns and "label_window_days" not in pred.columns)
    check("feature columns identical in train and predict",
          [c for c in train.columns if c in FEATURE_COLUMNS] == [c for c in pred.columns if c in FEATURE_COLUMNS] == FEATURE_COLUMNS)
    check("no banned columns", not (BANNED_COLUMNS & (set(train.columns) | set(pred.columns))))
    check("no blanks in features", not train[FEATURE_COLUMNS].isna().any().any() and not pred[FEATURE_COLUMNS].isna().any().any())
    for df, name in ((train, "train"), (pred, "predict")):
        pub, cut = pd.to_datetime(df.published), pd.to_datetime(df.snapshot_end)
        check(f"{name}: cutoff on/after publish date", bool((cut >= pub).all()))
        check(f"{name}: snapshot_end is last day of snapshot_month",
              bool((cut.dt.strftime("%Y-%m") == df.snapshot_month).all() and (cut.dt.is_month_end).all()))
    check("train cutoffs before label cutoff", bool((pd.to_datetime(train.snapshot_end) < LABEL_CUTOFF).all()))

    # Re-derive every label from the raw KEV file and compare
    kev["date_added"] = pd.to_datetime(kev.date_added)
    m = train[["cve_id", "snapshot_end", "label"]].merge(kev, on="cve_id", how="left")
    cut = pd.to_datetime(m.snapshot_end)
    expected = ((m.date_added > cut) & (m.date_added <= LABEL_CUTOFF)).astype(int)
    check("labels match the documented KEV rule", bool((expected == m.label).all()),
          f"{int(train.label.sum())} positives")
    check("no training CVE was already on KEV at its cutoff", not bool((m.date_added <= cut).any()))

    # --- model checks
    rep = json.loads((out / "validation_results.json").read_text(encoding="utf-8"))
    check("validation results saved", "selected_model" in rep, rep.get("selected_model", ""))
    check("label not used as a feature", "label" not in rep.get("features_used", []) and "label" not in FEATURE_COLUMNS)
    check("risk scores finite", bool(np.isfinite(ranked.risk_score).all()))

    # --- submission checks
    check("ranked_2026.csv has 72,670 rows", len(ranked) == 72_670, str(len(ranked)))
    check("ranked cve_id unique", not ranked.cve_id.duplicated().any())
    check("ranks are 1..72,670 in order", bool((ranked["rank"].to_numpy() == np.arange(1, len(ranked) + 1)).all()))
    check("top500.csv has exactly 500 rows", len(top) == 500, str(len(top)))
    check("top500.csv has only the cve_id column", list(top.columns) == ["cve_id"], str(list(top.columns)))
    check("top500.csv has no duplicates", not top.cve_id.duplicated().any())
    check("every top500 CVE is in scoreboard_2026.csv", set(top.cve_id) <= set(sb.cve_id))
    check("top500 == first 500 of ranked_2026", list(top.cve_id) == list(ranked.cve_id.head(500)))

    # --- reproducibility: run model.py again into a temp folder, compare top500
    if not a.skip_repro:
        tmp = out / "_repro_check"
        tmp.mkdir(exist_ok=True)
        try:
            for f in ("train.csv", "predict_2026.csv"):
                shutil.copyfile(out / f, tmp / f)
            model_script = Path(__file__).resolve().parent / "model.py"
            run = subprocess.run([sys.executable, str(model_script), "--out-dir", str(tmp)],
                                 capture_output=True, text=True)
            if run.returncode != 0:
                check("re-running model.py succeeds", False, run.stderr.strip()[-300:])
            else:
                again = pd.read_csv(tmp / "top500.csv", dtype=str)
                check("re-running model.py gives the same top500", list(again.cve_id) == list(top.cve_id))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)  # always clean up, even if the run failed

    print()
    if all(results):
        print(f"ALL CHECKS PASSED ({len(results)} checks)")
    else:
        print(f"{results.count(False)} CHECK(S) FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
