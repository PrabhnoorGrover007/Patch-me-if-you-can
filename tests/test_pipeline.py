"""Unit tests for the pipeline helpers. They use tiny hand-made tables, so no raw data is needed.

Run from the repo root (PowerShell):
    python -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import prepare_data as pdp  # noqa: E402
from model import hits_at_k  # noqa: E402


class LabelRuleTest(unittest.TestCase):
    def test_label_needs_kev_after_cutoff_and_before_label_cutoff(self):
        cutoff = pd.Series(pd.to_datetime(["2024-03-31"] * 4))
        added = pd.Series(pd.to_datetime(["2024-03-31", "2024-04-01", "2025-12-31", None]))
        # on the cutoff day -> already known, 0; day after -> 1; last KEV day -> 1; never -> 0
        self.assertEqual(pdp.make_label(added, cutoff).tolist(), [0, 1, 1, 0])

    def test_month_end_is_last_calendar_day(self):
        ends = pdp.month_end(pd.Series(["2024-02", "2025-03", "2025-12"]))
        self.assertEqual([d.strftime("%Y-%m-%d") for d in ends], ["2024-02-29", "2025-03-31", "2025-12-31"])


class PointInTimeTest(unittest.TestCase):
    def test_prior_count_only_counts_strictly_earlier_kev_additions(self):
        dates = {"acme": np.array(pd.to_datetime(["2024-01-15", "2024-03-01", "2024-05-20"]).values)}
        cutoffs = pd.to_datetime(["2024-01-01", "2024-03-01", "2024-06-01"]).values
        out = pdp.prior_count(dates, ["acme", "acme", "acme"], cutoffs)
        self.assertEqual(out.tolist(), [0, 1, 3])  # an addition ON the month start is not counted

    def test_unknown_key_counts_zero(self):
        out = pdp.prior_count({}, ["nobody"], pd.to_datetime(["2024-01-01"]).values)
        self.assertEqual(out.tolist(), [0])


class FeatureTest(unittest.TestCase):
    def test_keyword_flags(self):
        df = pd.DataFrame({"description": [
            "Unauthenticated remote code execution in the SSL VPN gateway.",
            "Stored cross-site scripting in the Foo plugin for WordPress.",
            None,
        ]})
        df = pdp.add_keyword_features(df)
        self.assertEqual(df.loc[0, ["kw_rce", "kw_unauthenticated", "kw_edge_device", "kw_xss"]].tolist(), [1, 1, 1, 0])
        self.assertEqual(df.loc[1, ["kw_xss", "kw_wordpress", "kw_rce"]].tolist(), [1, 1, 0])
        self.assertEqual(df.loc[2, "desc_length"], 0)

    def test_cvss_falls_back_to_v4_then_constant_without_missing_flag(self):
        df = pd.DataFrame({
            "cvss3_score": ["9.8", None, None],
            "cvss4_score": [None, "8.7", None],
            "attack_vector": ["NETWORK", None, None],
            "privileges_required": ["NONE", None, None],
            "user_interaction": ["REQUIRED", None, None],
            "cvss4_vector": [None, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N", None],
        })
        df = pdp.add_cvss_features(df)
        self.assertEqual(df["cvss_score"].tolist(), [9.8, 8.7, pdp.CVSS_FILL_VALUE])
        self.assertEqual(df["cvss_network"].tolist(), [1, 1, 0])
        self.assertEqual(df["cvss_no_user_interaction"].tolist(), [0, 1, 0])
        self.assertFalse(any("missing" in c for c in df.columns if c.startswith("cvss")))

    def test_epss_percentile_is_within_month_and_missing_is_zero(self):
        df = pd.DataFrame({
            "snapshot_month": ["2024-05", "2024-05", "2025-05", "2025-05", "2025-05"],
            "epss": [0.001, 0.002, 0.01, 0.02, np.nan],
            "published": pd.to_datetime(["2024-05-01"] * 2 + ["2025-05-01"] * 3),
            "snapshot_end": pd.to_datetime(["2024-05-31"] * 2 + ["2025-05-31"] * 3),
            **{c: [0, 1, 0, 0, None] for c in pdp.FLAG_COLUMNS},
        })
        df = pdp.add_signal_features(df)
        self.assertEqual(df["epss_pct_in_month"].tolist(), [0.5, 1.0, 0.5, 1.0, 0.0])
        self.assertEqual(df["epss_missing"].tolist(), [0, 0, 0, 0, 1])
        self.assertEqual(df["epss_v4"].tolist(), [0, 0, 1, 1, 1])
        self.assertEqual(df["n_exploit_sources"].tolist(), [0, 4, 0, 0, 0])

    def test_no_banned_column_is_a_feature(self):
        self.assertFalse(pdp.BANNED_COLUMNS & set(pdp.FEATURE_COLUMNS))
        self.assertNotIn("label", pdp.FEATURE_COLUMNS)


class MetricTest(unittest.TestCase):
    def test_hits_at_k(self):
        y = [0, 1, 0, 1, 1]
        score = [0.9, 0.8, 0.7, 0.1, 0.2]
        self.assertEqual(hits_at_k(y, score, 2), 1)
        self.assertEqual(hits_at_k(y, score, 5), 3)


if __name__ == "__main__":
    unittest.main()
