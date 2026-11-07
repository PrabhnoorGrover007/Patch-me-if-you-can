"""Data + ML tests. These run against the real artefacts, not mocks."""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
DATA = ROOT / "data"

FORBIDDEN = {"nvd_status", "n_references", "n_affected_cpes", "last_modified", "has_cvss3"}
FEATURES = json.loads((ART / "feature_meta.json").read_text())["features"] if (ART / "feature_meta.json").exists() else []


def test_source_files_present():
    for name in ["vulnerabilities.csv", "affected_products.csv", "references.csv", "known_exploited.csv",
                 "exploit_signals_2024.csv", "exploit_signals_2025.csv", "weakness_types.csv",
                 "scoreboard_2026.csv"]:
        assert (DATA / name).exists(), f"missing source file {name}"


def test_scoreboard_size_and_filter():
    sb = pd.read_parquet(ART / "scoreboard.parquet")
    assert len(sb) == 72_670
    assert sb["cve_id"].is_unique
    assert sb["published"].between("2026-01-01", "2026-09-30").all()
    expected_end = pd.to_datetime(sb["snapshot_month"] + "-01") + pd.offsets.MonthEnd(0)
    assert (sb["snapshot_end"] == expected_end).all()


def test_kev_never_used_as_feature():
    train = pd.read_parquet(ART / "train.parquet")
    for col in FORBIDDEN:
        assert col not in train.columns, f"leak-prone column {col} present in model table"


def test_labels_only_count_future_additions():
    train = pd.read_parquet(ART / "train.parquet")
    pos = train[train["label_any"] == 1]
    assert (pos["days_to_kev"] > 0).all(), "a positive label was added before/at the snapshot"
    neg = train[(train["label_any"] == 0) & train["days_to_kev"].notna()]
    assert (neg["days_to_kev"] <= 0).all()


def test_train_predict_feature_parity():
    train = pd.read_parquet(ART / "train.parquet")
    predict = pd.read_parquet(ART / "predict.parquet")
    assert len(predict) == 72_670
    missing_train = [f for f in FEATURES if f not in train.columns]
    missing_pred = [f for f in FEATURES if f not in predict.columns]
    assert not missing_train, f"features missing from train: {missing_train}"
    assert not missing_pred, f"features missing from predict: {missing_pred}"
    for f in FEATURES:
        assert str(train[f].dtype) == str(predict[f].dtype), f"dtype mismatch on {f}"


def test_granite_features_are_asof():
    path = ART / "granite_features.parquet"
    if not path.exists():
        pytest.skip("Granite stage not run")
    g = pd.read_parquet(path)
    assert g["cve_id"].is_unique
    assert g["split"].isin(["train", "predict"]).all()
    vals = g["granite_knn_max"].dropna()
    assert len(vals) > 0, "granite feature column is entirely missing"
    assert np.isfinite(vals).all(), "non-finite cosine similarity"
    # float32 matmul on bf16-derived vectors can drift a few thousandths past 1.0
    assert float(vals.max()) <= 1.02 and float(vals.min()) >= -1.02, "cosine similarity out of range"


def test_top500_format():
    p = ROOT / "top500.csv"
    if not p.exists():
        pytest.skip("submission not generated yet")
    lines = p.read_text().strip().splitlines()
    assert lines[0].strip() == "cve_id", "top500.csv must have exactly one column named cve_id"
    ids = lines[1:]
    assert len(ids) == 500
    assert len(set(ids)) == 500
    board = set(pd.read_csv(DATA / "scoreboard_2026.csv", usecols=["cve_id"])["cve_id"])
    assert set(ids) <= board, "top500.csv contains ids outside the 2026 scoreboard"


def test_ranked_table_integrity():
    df = pd.read_parquet(ART / "ranked_2026.parquet")
    assert len(df) == 72_670
    assert df["cve_id"].is_unique
    assert df["rank"].is_unique and df["rank"].min() == 1 and df["rank"].max() == len(df)
    assert df["risk_score"].between(0, 1).all()
    assert df["risk_score"].notna().all()


def test_model_is_deterministic_and_loadable():
    path = ART / "model.joblib"
    if not path.exists():
        pytest.skip("model not trained")
    bundle = joblib.load(path)
    predict = pd.read_parquet(ART / "predict.parquet").head(200)
    gp = ART / "granite_features.parquet"
    if gp.exists():  # granite columns are merged at load time, not stored in predict.parquet
        gf = pd.read_parquet(gp)
        predict = predict.merge(
            gf[gf["split"] == "predict"][["cve_id", "granite_knn_max", "granite_knn_mean5"]],
            on="cve_id", how="left")
    for name, model in bundle["models"].items():
        feats = bundle["feature_sets"][name]
        a = model.predict_proba(predict[feats])[:, 1]
        b = model.predict_proba(predict[feats])[:, 1]
        assert np.allclose(a, b), f"{name} is not deterministic"
        assert np.isfinite(a).all()


def test_discoveries_have_intervals():
    d = json.loads((ART / "discoveries.json").read_text())
    assert len(d["discoveries"]) >= 6
    with_ci = []
    for item in d["discoveries"]:
        assert item["finding"]
        assert item["n"] > 0
        chart = item.get("chart") or {}
        if chart.get("ci_low"):
            with_ci.append(item)
            assert len(chart["ci_low"]) == len(chart["y"]) == len(chart["ci_high"]), \
                f"{item['id']}: CI length mismatch"
            assert all(lo <= v <= hi for lo, v, hi in zip(chart["ci_low"], chart["y"], chart["ci_high"]))
    assert len(with_ci) >= 6, "too few discoveries carry confidence intervals"
