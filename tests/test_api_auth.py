from fastapi.testclient import TestClient
from pathlib import Path

import pytest

import api


def test_health_no_auth_required():
    client = TestClient(api.app)
    response = client.get("/health")
    assert response.status_code == 200


def test_api_key_required_when_configured(monkeypatch):
    monkeypatch.setenv("KERAUNOS_API_KEY", "secret-key")
    client = TestClient(api.app)
    response = client.get("/runs")
    assert response.status_code == 401


def test_api_key_allows_when_provided(monkeypatch):
    monkeypatch.setenv("KERAUNOS_API_KEY", "secret-key")
    client = TestClient(api.app)
    response = client.get("/runs", headers={"X-API-Key": "secret-key"})
    assert response.status_code == 200


def test_data_endpoint_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("KERAUNOS_API_KEY", "secret-key")
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    report_path = data_dir / "report_test_auth.html"
    report_path.write_text("<html>ok</html>", encoding="utf-8")
    try:
        client = TestClient(api.app)
        response = client.get(f"/data/{report_path.name}")
        assert response.status_code == 401
    finally:
        report_path.unlink(missing_ok=True)


def test_data_endpoint_rejects_invalid_filename(monkeypatch):
    monkeypatch.delenv("KERAUNOS_API_KEY", raising=False)
    client = TestClient(api.app)
    response = client.get("/data/not_a_report.txt")
    assert response.status_code == 400


def test_websocket_requires_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("KERAUNOS_API_KEY", "secret-key")
    client = TestClient(api.app)

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/some-run-id"):
            pass


def test_websocket_allows_api_key_query_when_configured(monkeypatch):
    monkeypatch.setenv("KERAUNOS_API_KEY", "secret-key")
    client = TestClient(api.app)
    with client.websocket_connect("/ws/some-run-id?x_api_key=secret-key"):
        pass


def test_modes_endpoint_lists_safe_modes():
    client = TestClient(api.app)
    response = client.get("/modes")
    assert response.status_code == 200
    items = response.json()["items"]
    ids = {item["id"] for item in items}
    assert {"system", "webapp", "ai_agent", "legacy"}.issubset(ids)
