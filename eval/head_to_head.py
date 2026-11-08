"""Head-to-head on the same Jan-Sep 2025 window, using his own code and features."""
import json, sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
HIS = ROOT / ".tmp-remote" / "repo"
sys.path.insert(0, str(HIS))
from model import MODELS, FEATURE_COLUMNS, baseline_scores  # noqa: E402


def hits(y, s, k):
    order = np.argsort(-np.asarray(s, dtype=float), kind="stable")
    return int(np.asarray(y)[order[:k]].sum())


train = pd.read_csv(HIS / "out_run" / "train.csv", dtype={"cve_id": str, "snapshot_month": str})
fit = train[train.snapshot_month < "2025-01"]
val = train[(train.snapshot_month >= "2025-01") & (train.snapshot_month <= "2025-09")]
y = val.label.to_numpy()
print(f"fit {len(fit):,} rows / {int(fit.label.sum())} positives | "
      f"val {len(val):,} rows / {int(y.sum())} positives")

scores = {}
for name, factory in MODELS.items():
    model = factory().fit(fit[FEATURE_COLUMNS], fit.label)
    scores[name] = model.predict_proba(val[FEATURE_COLUMNS])[:, 1]
for name, s in baseline_scores(val).items():
    scores[name] = s.to_numpy()

results = {}
print(f"{'ranker':<26}{'@50':>5}{'@100':>6}{'@274':>6}{'@500':>6}{'P@50':>7}{'AP':>8}{'AUC':>7}")
for name, s in scores.items():
    r = {"hits@50": hits(y, s, 50), "hits@100": hits(y, s, 100),
         "hits@274": hits(y, s, 274), "hits@500": hits(y, s, 500),
         "p@50": round(hits(y, s, 50) / 50, 3),
         "ap": round(float(average_precision_score(y, s)), 4),
         "auc": round(float(roc_auc_score(y, s)), 4)}
    results[name] = r
    print(f"{name:<26}{r['hits@50']:>5}{r['hits@100']:>6}{r['hits@274']:>6}"
          f"{r['hits@500']:>6}{r['p@50']:>7}{r['ap']:>8}{r['auc']:>7}")

(ROOT / "artifacts" / "head_to_head_2025.json").write_text(json.dumps({
    "window": "2025-01..2025-09", "rows": len(val), "positives": int(y.sum()),
    "train_rows": len(fit), "train_positives": int(fit.label.sum()),
    "results": results}, indent=2), encoding="utf-8")
