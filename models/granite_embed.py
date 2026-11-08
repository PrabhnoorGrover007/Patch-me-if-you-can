"""IBM Granite embeddings of CVE descriptions -> leakage-safe similarity features.

Uses `ibm-granite/granite-embedding-30m-english` through sentence-transformers (CPU).
For every candidate we measure how semantically close its description is to the KEV entries
that were **already published on KEV at that row's snapshot month end**. The reference set is
therefore nested by month and never contains a future addition, so the feature cannot leak
the label.

Outputs artifacts/granite_features.parquet and artifacts/granite_meta.json
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts"
MODEL_NAME = "ibm-granite/granite-embedding-30m-english"
BATCH = 64


def log(msg: str) -> None:
    print(f"[granite] {msg}", flush=True)


def embed(texts: list[str], model) -> np.ndarray:
    t0 = time.time()
    emb = model.encode(texts, batch_size=BATCH, normalize_embeddings=True,
                       show_progress_bar=False, convert_to_numpy=True)
    log(f"embedded {len(texts):,} texts in {time.time() - t0:.1f}s ({len(texts) / max(time.time() - t0, 1e-9):.0f}/s)")
    return emb.astype("float32")


def knn_features(rows: pd.DataFrame, emb: np.ndarray, kev: pd.DataFrame,
                 kev_emb: np.ndarray, label: str) -> pd.DataFrame:
    """max / mean-of-top-5 cosine similarity to the KEV entries available at snapshot time."""
    kev = kev.reset_index(drop=True)
    dates = kev["date_added"].to_numpy()
    out = pd.DataFrame({"cve_id": rows["cve_id"].to_numpy(),
                        "granite_knn_max": np.nan,
                        "granite_knn_mean5": np.nan})
    for month, idx in rows.groupby("snapshot_month").indices.items():
        end = pd.Timestamp(month + "-01") + pd.offsets.MonthEnd(0)
        mask = dates <= np.datetime64(end)
        if mask.sum() == 0:
            continue
        ref = kev_emb[mask]
        sims = np.clip(emb[idx] @ ref.T, -1.0, 1.0)
        k = min(5, sims.shape[1])
        top = np.partition(sims, -k, axis=1)[:, -k:]
        out.loc[out.index[idx], "granite_knn_max"] = sims.max(axis=1)
        out.loc[out.index[idx], "granite_knn_mean5"] = top.mean(axis=1)
        log(f"{label} {month}: {len(idx):,} rows vs {int(mask.sum())} prior KEV descriptions")
    return out


def main() -> None:
    from sentence_transformers import SentenceTransformer

    t0 = time.time()
    log(f"loading {MODEL_NAME}")
    model = SentenceTransformer(MODEL_NAME, device="cpu")
    log(f"loaded in {time.time() - t0:.1f}s, dim={model.get_sentence_embedding_dimension()}")

    vuln = pd.read_parquet(ART / "vulnerabilities.parquet", columns=["cve_id", "description"])
    desc = dict(zip(vuln["cve_id"], vuln["description"].fillna("")))
    kev = pd.read_parquet(ART / "kev.parquet")[["cve_id", "date_added"]].dropna()
    kev = kev.drop_duplicates("cve_id")

    kev_texts = [desc.get(c, "") or "unknown vulnerability" for c in kev["cve_id"]]
    kev_emb = embed(kev_texts, model)

    train = pd.read_parquet(ART / "train.parquet", columns=["cve_id", "snapshot_month", "description"])
    predict = pd.read_parquet(ART / "predict.parquet", columns=["cve_id", "snapshot_month", "description"])

    tr_emb = embed(train["description"].fillna("").tolist(), model)
    pr_emb = embed(predict["description"].fillna("").tolist(), model)

    tr_feat = knn_features(train, tr_emb, kev, kev_emb, "train")
    pr_feat = knn_features(predict, pr_emb, kev, kev_emb, "predict")
    tr_feat["split"] = "train"
    pr_feat["split"] = "predict"
    allf = pd.concat([tr_feat, pr_feat], ignore_index=True)
    allf.to_parquet(ART / "granite_features.parquet", index=False)

    np.save(ART / "granite_embed_2026.npy", pr_emb)
    pd.DataFrame({"cve_id": predict["cve_id"], "row": np.arange(len(predict))}).to_parquet(
        ART / "granite_embed_index.parquet", index=False)

    meta = {
        "model": MODEL_NAME,
        "dim": int(model.get_sentence_embedding_dimension()),
        "train_rows": int(len(train)),
        "predict_rows": int(len(predict)),
        "kev_reference_rows": int(len(kev)),
        "train_max_sim_mean": float(tr_feat["granite_knn_max"].mean()),
        "predict_max_sim_mean": float(pr_feat["granite_knn_max"].mean()),
        "seconds": round(time.time() - t0, 1),
    }
    (ART / "granite_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    log(f"done: {meta}")


if __name__ == "__main__":
    main()
