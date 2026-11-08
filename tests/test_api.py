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
    assert body["product"] == "PATCH ME IF YOU CAN"
    assert body["status"] in {"ok", "degraded"}
    assert body["rows"] == 72_670


def test_dashboard_carries_500_real_records():
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    body = r.json()
    assert len(body["cves"]) == 500
    first = body["cves"][0]
    assert first["rank"] == 1
    assert first["cveId"] == "CVE-2026-2699"
    assert first["priorityScore"] == 100.0
    assert 0 <= first["riskProbability"] <= 1
    assert first["products"]
    assert body["meta"]["cohort"] == 500
    assert body["meta"]["universe"] == 72_670
    assert body["meta"]["validation"]["hitsAt500"] == 22


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
    assert body["technical"]["n_exploit_sources"] is not None

    assert client.get("/api/vulnerabilities/CVE-1999-9999").status_code == 404


def test_model_performance_and_discoveries():
    r = client.get("/api/model/performance")
    assert r.status_code == 200
    rows = r.json()["heldout_2025"]["rows"]
    names = {row["model"] for row in rows}
    assert {"poc_then_epss", "final_blend"} <= names

    assert r.json()["granite_ablation"]["pool"]

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
    # The download must be byte-identical to the on-disk submission (CRLF included).
    assert t.content == (ROOT / "top500.csv").read_bytes()


def test_similar_timeline_and_products():
    first = client.get("/api/vulnerabilities?size=1").json()["items"][0]["cve_id"]
    sim = client.get(f"/api/vulnerabilities/{first}/similar?limit=5")
    assert sim.status_code == 200
    body = sim.json()
    assert body["items"] and all(i["cve_id"] != first for i in body["items"])
    assert all(-1.001 <= i["similarity"] <= 1.001 for i in body["items"])

    tl = client.get(f"/api/vulnerabilities/{first}/timeline")
    assert tl.status_code == 200
    assert tl.json()["cve_id"] == first

    products = client.get("/api/products?q=microsoft&size=5")
    assert products.status_code == 200
    assert products.json()["items"]
    pid = products.json()["items"][0]["product_id"]
    pv = client.get(f"/api/products/{pid}/vulnerabilities?size=5")
    assert pv.status_code == 200
    assert pv.json()["product_id"] == pid


def test_patch_optimizer():
    r = client.post("/api/patch-optimizer", json={"budget": 20})
    assert r.status_code == 200
    body = r.json()
    assert body["budget"] == 20
    assert set(body["strategies"]) == {"cvss", "epss", "exploit_then_epss", "model"}
    for strategy in body["strategies"].values():
        assert strategy["count"] == 20
        assert len(strategy["items"]) == 20
    assert body["overlap"]["model"]["model"] == 20


def test_granite_analysis_and_chat():
    first = client.get("/api/vulnerabilities?size=1").json()["items"][0]["cve_id"]
    r = client.post("/api/granite/analyze", json={"cve_id": first})
    assert r.status_code == 200
    body = r.json()
    assert body["generative_model"] is None
    assert body["extracted"]["method"]
    assert body["analogs"]
    assert body["verified"]["cvss3_score"] is not None

    chat = client.post("/api/granite/chat", json={"question": f"Why is {first} ranked here?"})
    assert chat.status_code == 200
    answer = chat.json()
    assert answer["source"] == "grounded-retrieval"
    assert first in answer["answer"]
    assert answer["generative_model"] is None
