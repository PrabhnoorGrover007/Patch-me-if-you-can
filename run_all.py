"""Reproduce every artefact from the raw CSVs in one command.

    python run_all.py               # full pipeline incl. Granite embeddings
    python run_all.py --skip-granite

Stages are separate modules so they can also be run individually.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STAGES = [
    ("prepare_data", ["-m", "pipeline.prepare_data"], "raw CSV -> parquet"),
    ("features", ["-m", "pipeline.features"], "snapshot-aligned feature tables"),
    ("granite", ["-m", "models.granite_embed"], "IBM Granite description embeddings"),
    ("discoveries", ["-m", "pipeline.discoveries"], "statistical discovery report"),
    ("train", ["-m", "models.train"], "model selection + fit"),
    ("predict", ["-m", "models.predict"], "top500.csv + ranked tables"),
    ("audit", ["-m", "pipeline.audit"], "feature availability audit"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-granite", action="store_true", help="skip the slow embedding stage")
    args = ap.parse_args()

    failures = []
    for name, cmd, blurb in STAGES:
        if name == "granite" and args.skip_granite:
            print(f"[run_all] skip {name}")
            continue
        t0 = time.time()
        print(f"\n[run_all] === {name}: {blurb} ===", flush=True)
        proc = subprocess.run([sys.executable, *cmd], cwd=ROOT)
        elapsed = time.time() - t0
        if proc.returncode != 0:
            failures.append(name)
            print(f"[run_all] FAILED {name} after {elapsed:.1f}s", flush=True)
        else:
            print(f"[run_all] ok {name} in {elapsed:.1f}s", flush=True)

    if failures:
        print(f"\n[run_all] {len(failures)} stage(s) failed: {failures}")
        return 1
    print("\n[run_all] complete. Submission: top500.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
