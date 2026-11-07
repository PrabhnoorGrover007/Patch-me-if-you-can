"""API tests against the real FastAPI app and the real artefacts."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["rows"] == 72_670


def test_overview_shape():
    r = client.get("/api/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["analyzed"] == 72_670
    assert len(body["risk_distribution"]) == 20
    assert body["headline_model"], "no held-out model result available"


def test_vulnerabilities_pagination_and_filters():
    r = client.get("/api/vulnerabilities?page=1&size=10")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 72_670 and len(body["items"]) == 10
    ranks = [i["rank"] for i in body["items"]]
    assert ranks == sorted(ranks)

    r2 = client.get("/api/vulnerabilities?severity=CRITICAL&size=5")
    assert r2.status_code == 200
    assert all(i["cvss3_severity"] == "CRITICAL" for i in r2.json()["items"])

    r3 = client.get("/api/vulnerabilities?min_epss=0.5&size=5")
    assert all((i["epss_score"] or 0) >= 0.5 for i in r3.json()["items"])


def test_invalid_query_parameters_rejected():
    assert client.get("/api/vulnerabilities?page=0").status_code == 422
    assert client.get("/api/vulnerabilities?size=9999").status_code == 422
    assert client.get("/api/vulnerabilities?sort=drop_table").status_code == 422


def test_vulnerability_detail_and_missing_id():
    first = client.get("/api/vulnerabilities?size=1").json()["items"][0]["cve_id"]
    r = client.get(f"/api/vulnerabilities/{first}")
    assert r.status_code == 200
    body = r.json()
    assert body["cve_id"] == first
    assert body["description"]
    assert body["remediation_priority"]

    assert client.get("/api/vulnerabilities/CVE-1999-9999").status_code == 404


def test_model_performance_and_discoveries():
    r = client.get("/api/model/performance")
    assert r.status_code == 200
    rows = r.json()["heldout_2025"]["rows"]
    names = {row["model"] for row in rows}
    assert {"poc_then_epss", "final_blend"} <= names

    d = client.get("/api/discoveries")
    assert d.status_code == 200
    assert len(d.json()["discoveries"]) >= 6


def test_explanations_fallback_is_grounded():
    first = client.get("/api/vulnerabilities?size=1").json()["items"][0]["cve_id"]
    r = client.get(f"/api/explanations/{first}")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] in {"granite", "deterministic"}
    assert body.get("summary") or body.get("why_it_matters")


def test_export_and_top500():
    r = client.get("/api/export?limit=50")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert len(r.text.strip().splitlines()) == 51

    t = client.get("/api/top500")
    assert t.status_code == 200
    lines = t.text.strip().splitlines()
    assert lines[0] == "cve_id" and len(lines) == 501
