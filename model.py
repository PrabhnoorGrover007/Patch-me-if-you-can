"""
model.py - train a ranking model on historical CVEs, check it on a later period,
then score and rank the 72,670 scoreboard CVEs.

    in : outputs/train.csv, outputs/predict_2026.csv   (from prepare_data.py)
    out: outputs/validation_results.json
         outputs/ranked_2026.csv   (all 72,670 rows, for the dashboard)
         outputs/top500.csv        (submission: one column cve_id)

Steps
 1. Time-based check: train on 2024 cohorts, validate on 2025 cohorts (no random split).
 2. Compare LogisticRegression and HistGradientBoosting with simple baselines on the same
    2025 validation rows, using Hits@K (how many real KEV additions land in the top K).
 3. Retrain the better model on ALL training rows and rank the 2026 scoreboard.
 If training fails, fall back to a deterministic baseline ranking (clearly labelled).

Usage (PowerShell):
    python model.py
"""

import argparse
import json
import time
import traceback
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from prepare_data import FEATURE_COLUMNS

SEED = 42
VALIDATION_START = "2025-01"  # train on snapshot months before this, validate on/after
SCOREBOARD_ROWS = 72_670
TOP_N = 500
# Skewed count-like features get log1p before scaling (only matters for the linear model)
LOG_FEATURES = ["epss", "days_public_at_cutoff", "desc_length",
                "vendor_prior_kev_count", "assigner_prior_kev_count"]


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Data loading + schema check
# ---------------------------------------------------------------------------
def load_and_check(out_dir):
    train = pd.read_csv(out_dir / "train.csv", dtype={"cve_id": str, "snapshot_month": str})
    predict = pd.read_csv(out_dir / "predict_2026.csv", dtype={"cve_id": str, "snapshot_month": str})
    missing = [c for c in FEATURE_COLUMNS + ["label"] if c not in train.columns]
    missing += [c for c in FEATURE_COLUMNS if c not in predict.columns]
    if missing:
        raise SystemExit(f"Schema error, missing columns: {missing}")
    if "label" in predict.columns:
        raise SystemExit("predict_2026.csv must not contain a label column")
    if train[FEATURE_COLUMNS].isna().any().any() or predict[FEATURE_COLUMNS].isna().any().any():
        raise SystemExit("Blank values found in feature columns")
    log(f"train: {len(train):,} rows ({int(train.label.sum())} positives); predict: {len(predict):,} rows")
    return train, predict


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
def make_logistic():
    other = [c for c in FEATURE_COLUMNS if c not in LOG_FEATURES]
    prep = ColumnTransformer([
        ("log", Pipeline([("log1p", FunctionTransformer(np.log1p)), ("scale", StandardScaler())]), LOG_FEATURES),
        ("rest", StandardScaler(), other),
    ])
    clf = LogisticRegression(C=0.1, class_weight="balanced", max_iter=5000)
    return Pipeline([("prep", prep), ("clf", clf)])


def make_boosting():
    # Small, heavily regularised trees: we only have ~100 positives
    return HistGradientBoostingClassifier(
        max_iter=200, learning_rate=0.05, max_leaf_nodes=8, min_samples_leaf=40,
        l2_regularization=1.0, class_weight="balanced", random_state=SEED)


MODELS = {"logistic_regression": make_logistic, "hist_gradient_boosting": make_boosting}


# ---------------------------------------------------------------------------
# Baselines (no training needed). Higher value = higher rank.
# ---------------------------------------------------------------------------
def baseline_scores(df):
    eps = df["epss_pct_in_month"]
    return {
        "cvss_first": df["cvss_score"] + 1e-3 * eps,
        "epss_first": eps,
        "exploit_flags_then_epss": df["n_exploit_sources"] * 10 + eps,
        # Hand-made rule: exploit code + EPSS + vendor history + bug type (our fallback ranking)
        "heuristic_baseline": heuristic_score(df),
    }


def heuristic_score(df):
    return (3 * df["n_exploit_sources"].clip(upper=2)
            + 2 * df["epss_pct_in_month"]
            + np.log1p(df["vendor_prior_kev_count"]) + np.log1p(df["assigner_prior_kev_count"]) * 0.5
            + df[["kw_rce", "kw_command_injection", "kw_auth_bypass", "kw_unauthenticated",
                  "kw_edge_device", "kw_deserialization", "kw_path_traversal"]].sum(axis=1)
            + 3 * df["kw_exploited_in_wild"] - 2 * df["kw_wordpress"] - df["kw_xss"])


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def hits_at_k(y, score, k):
    order = np.argsort(-np.asarray(score, dtype=float), kind="stable")
    return int(np.asarray(y)[order[:k]].sum())


def evaluate(y, score, k_values):
    out = {f"hits_at_{k}": hits_at_k(y, score, k) for k in k_values}
    for k in k_values:
        out[f"precision_at_{k}"] = round(out[f"hits_at_{k}"] / k, 4)
        out[f"recall_at_{k}"] = round(out[f"hits_at_{k}"] / max(int(np.sum(y)), 1), 4)
    out["average_precision"] = round(float(average_precision_score(y, score)), 4)
    out["roc_auc"] = round(float(roc_auc_score(y, score)), 4)
    return out


# ---------------------------------------------------------------------------
# Explanations for the dashboard (plain-English factors, independent of Granite)
# ---------------------------------------------------------------------------
def risk_factors(row):
    f = []
    if row.kw_exploited_in_wild: f.append("vendor says it may already be exploited")
    if row.metasploit: f.append("Metasploit module exists")
    if row.exploitdb: f.append("Exploit-DB entry exists")
    if row.nuclei: f.append("Nuclei scanner template exists")
    if row.poc_github: f.append("public proof-of-concept on GitHub")
    if row.epss_pct_in_month >= 0.95: f.append(f"EPSS in top {max(1, round((1 - row.epss_pct_in_month) * 100))}% of its month")
    if row.vendor_prior_kev_count >= 5: f.append(f"vendor has {row.vendor_prior_kev_count} past KEV entries")
    elif row.assigner_prior_kev_count >= 5: f.append(f"assigning vendor has {row.assigner_prior_kev_count} past KEV entries")
    if row.kw_rce or row.kw_command_injection: f.append("remote code / command execution")
    if row.kw_auth_bypass or row.kw_unauthenticated: f.append("no login needed / auth bypass")
    if row.kw_edge_device: f.append("internet-facing device (VPN, firewall, gateway)")
    if row.kw_memory_corruption: f.append("memory corruption")
    return "; ".join(f[:4]) if f else "no strong signal"


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def time_based_validation(train):
    fit_part = train[train["snapshot_month"] < VALIDATION_START]
    val_part = train[train["snapshot_month"] >= VALIDATION_START]
    # Validation has fewer rows than the scoreboard, so also report a proportional cutoff
    k_scaled = round(TOP_N * len(val_part) / SCOREBOARD_ROWS)
    k_values = sorted({k_scaled, TOP_N})
    y_val = val_part["label"].to_numpy()

    results = {"models": {}, "baselines": {}}
    for name, factory in MODELS.items():
        model = factory().fit(fit_part[FEATURE_COLUMNS], fit_part["label"])
        score = model.predict_proba(val_part[FEATURE_COLUMNS])[:, 1]
        results["models"][name] = evaluate(y_val, score, k_values)
        log(f"{name:24s} {results['models'][name]}")
    for name, score in baseline_scores(val_part).items():
        results["baselines"][name] = evaluate(y_val, score.to_numpy(), k_values)
        log(f"{name:24s} {results['baselines'][name]}")

    info = {
        "train_period": f"{fit_part.snapshot_month.min()} to {fit_part.snapshot_month.max()}",
        "validation_period": f"{val_part.snapshot_month.min()} to {val_part.snapshot_month.max()}",
        "train_rows": len(fit_part), "train_positives": int(fit_part.label.sum()),
        "validation_rows": len(val_part), "validation_positives": int(y_val.sum()),
        "k_scaled_explanation": (f"Validation has {len(val_part):,} rows vs {SCOREBOARD_ROWS:,} in the scoreboard, "
                                 f"so top {k_scaled} is the same share (0.69%) as top 500 of the scoreboard."),
        "k_scaled": k_scaled,
    }
    return info, results


def pick_model(results, k):
    key = f"hits_at_{k}"
    # Higher Hits@K wins; ties broken by average precision; then prefer the simpler model
    ranked = sorted(results["models"].items(),
                    key=lambda kv: (kv[1][key], kv[1]["average_precision"], kv[0] == "logistic_regression"),
                    reverse=True)
    return ranked[0][0]


def build_ranking(predict, score, method):
    out = predict.copy()
    out["risk_score"] = np.round(score, 8)
    # Deterministic tie-breaks: score, then EPSS percentile, then CVE ID
    out = out.sort_values(["risk_score", "epss_pct_in_month", "cve_id"],
                          ascending=[False, False, True]).reset_index(drop=True)
    out["rank"] = np.arange(1, len(out) + 1)
    out["top_risk_factors"] = [risk_factors(r) for r in out.itertuples()]
    out["scoring_method"] = method
    cols = ["rank", "cve_id", "risk_score", "top_risk_factors", "published", "snapshot_month",
            "epss", "epss_pct_in_month", "exploitdb", "metasploit", "nuclei", "poc_github",
            "vendor_prior_kev_count", "assigner_prior_kev_count", "kw_exploited_in_wild",
            "kw_rce", "kw_auth_bypass", "kw_edge_device", "scoring_method", "description"]
    return out[cols]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="outputs")
    out_dir = Path(parser.parse_args().out_dir)

    train, predict = load_and_check(out_dir)
    report = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
              "label_rule": "1 if added to CISA KEV after the end of snapshot_month and on/before 2025-12-31",
              "features_used": FEATURE_COLUMNS}

    try:
        info, results = time_based_validation(train)
        best = pick_model(results, info["k_scaled"])
        log(f"selected model: {best}")
        final = MODELS[best]().fit(train[FEATURE_COLUMNS], train["label"])  # retrain on all history
        score = final.predict_proba(predict[FEATURE_COLUMNS])[:, 1]
        method = best
        report.update(info)
        report["validation"] = results
        report["selected_model"] = best
        report["final_model_trained_on"] = f"all {len(train):,} training rows ({int(train.label.sum())} positives)"
    except Exception:
        traceback.print_exc()
        log("MODEL TRAINING FAILED - using the deterministic heuristic baseline instead")
        score = heuristic_score(predict).to_numpy()
        method = "heuristic_baseline (not a trained ML model)"
        report["selected_model"] = method

    if not np.isfinite(score).all():
        raise SystemExit("Non-finite risk scores")

    ranked = build_ranking(predict, score, method)
    ranked.to_csv(out_dir / "ranked_2026.csv", index=False)
    ranked[["cve_id"]].head(TOP_N).to_csv(out_dir / "top500.csv", index=False)

    report["scoreboard_rows_scored"] = len(ranked)
    report["notes"] = [
        "risk_score is a ranking score, not a calibrated probability.",
        "Validation positives are few, so Hits@K differences of 1-3 are within noise.",
        "2025 validation outcomes are KEV additions through 2025-12-31 only; late-2025 cohorts are under-labelled.",
        "Training labels for 2024 cohorts were observed through 2025-12-31, overlapping the validation period in time.",
        "Description and CVSS come from today's NIST data; their availability at each cutoff cannot be proven.",
        "Validation is historical. It does not show how we score against the official 2026 benchmark.",
    ]
    (out_dir / "validation_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    log(f"wrote ranked_2026.csv ({len(ranked):,} rows), top500.csv, validation_results.json")


if __name__ == "__main__":
    main()
