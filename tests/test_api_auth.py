from fastapi.testclient import TestClient

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
