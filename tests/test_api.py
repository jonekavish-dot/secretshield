"""Tests for the SecretShield web service.

Covers T-6 (token required), T-8 (Scan now) and the storage path.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

TOKEN = "sshield_" + "a" * 32
FAKE_AWS_KEY = "AKIA4SHIELDDEMO7QZXK"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("INGEST_TOKEN", TOKEN)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("LOG_PATH", str(tmp_path / "test.log"))

    from app import db, main
    importlib.reload(db)
    importlib.reload(main)
    with TestClient(main.app) as test_client:
        yield test_client


def report_body(**overrides):
    body = {
        "repo": "team/secretshield",
        "commit": "a1b2c3d4e5f6",
        "branch": "main",
        "findings": [
            {
                "file": "src/config.py",
                "line": 12,
                "rule": "aws-access-key",
                "severity": "Critical",
                "redacted_value": "AKIA************MPLE",
                "remediation": "Rotate the key in AWS IAM.",
            }
        ],
    }
    body.update(overrides)
    return body


# --- health -----------------------------------------------------------------

def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_dashboard_is_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "SecretShield" in res.text


# --- T-6: the ingest endpoint needs a valid token ---------------------------

def test_report_without_a_token_is_rejected(client):
    res = client.post("/api/reports", json=report_body())
    assert res.status_code == 401


def test_report_with_a_wrong_token_is_rejected(client):
    res = client.post("/api/reports", json=report_body(), headers={"X-Ingest-Token": "wrong"})
    assert res.status_code == 401


def test_report_with_the_right_token_is_stored(client):
    res = client.post("/api/reports", json=report_body(), headers={"X-Ingest-Token": TOKEN})
    assert res.status_code == 201
    body = res.json()
    assert body["status"] == "FAIL"
    assert body["findings"] == 1
    assert body["scan_id"] >= 1


def test_a_clean_report_is_stored_as_pass(client):
    res = client.post(
        "/api/reports", json=report_body(findings=[]), headers={"X-Ingest-Token": TOKEN}
    )
    assert res.status_code == 201
    assert res.json()["status"] == "PASS"


# --- storage and listing ----------------------------------------------------

def test_reports_are_listed_newest_first(client):
    client.post("/api/reports", json=report_body(commit="aaa111"), headers={"X-Ingest-Token": TOKEN})
    client.post(
        "/api/reports",
        json=report_body(commit="bbb222", findings=[]),
        headers={"X-Ingest-Token": TOKEN},
    )
    reports = client.get("/api/reports").json()
    assert len(reports) == 2
    assert reports[0]["commit_sha"] == "bbb222"
    assert reports[1]["findings"][0]["rule"] == "aws-access-key"


def test_an_unmasked_value_is_remasked_before_storage(client):
    """A client that sends a raw secret must not get it stored."""
    body = report_body()
    body["findings"][0]["redacted_value"] = FAKE_AWS_KEY
    client.post("/api/reports", json=body, headers={"X-Ingest-Token": TOKEN})
    stored = client.get("/api/reports").json()[0]["findings"][0]["redacted_value"]
    assert stored != FAKE_AWS_KEY
    assert "*" in stored


def test_an_unknown_severity_falls_back_to_high(client):
    body = report_body()
    body["findings"][0]["severity"] = "Bogus"
    client.post("/api/reports", json=body, headers={"X-Ingest-Token": TOKEN})
    assert client.get("/api/reports").json()[0]["findings"][0]["severity"] == "High"


# --- T-8: Scan now ----------------------------------------------------------

def test_scan_now_detects_a_dummy_key(client):
    res = client.post("/api/scan", json={"text": f'KEY = "{FAKE_AWS_KEY}"'})
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "FAIL"
    assert body["findings"][0]["rule"] == "aws-access-key"
    assert FAKE_AWS_KEY not in res.text


def test_scan_now_passes_clean_text(client):
    res = client.post("/api/scan", json={"text": 'import os\nKEY = os.environ["KEY"]'})
    assert res.json() == {"status": "PASS", "findings": []}


def test_scan_now_needs_no_token(client):
    assert client.post("/api/scan", json={"text": "hello"}).status_code == 200


def test_scan_now_does_not_store_anything(client):
    client.post("/api/scan", json={"text": f'KEY = "{FAKE_AWS_KEY}"'})
    assert client.get("/api/reports").json() == []


def test_scan_now_is_not_cached(client):
    res = client.post("/api/scan", json={"text": "hello"})
    assert res.headers.get("cache-control") == "no-store"
