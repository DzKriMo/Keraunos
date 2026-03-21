from fastapi.testclient import TestClient
from pathlib import Path
from unittest.mock import patch

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


def test_llm_provider_switch_updates_runtime_config(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("KERAUNOS_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("KERAUNOS_LLM_MODEL", api._llm_presets["openrouter"]["model"])
    monkeypatch.setenv("KERAUNOS_LLM_URL", api._llm_presets["openrouter"]["url"])
    client = TestClient(api.app)

    response = client.post("/llm/provider", json={"provider": "ollama"})

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "ollama"
    assert body["model"] == "deepseek-r1:8b"
    assert body["url"] == api._llm_presets["ollama"]["url"]
    assert api.os.environ["KERAUNOS_LLM_PROVIDER"] == "ollama"
    assert api.os.environ["KERAUNOS_LLM_MODEL"] == "deepseek-r1:8b"


def test_llm_status_exposes_active_provider_and_presets(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("KERAUNOS_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("KERAUNOS_LLM_MODEL", "deepseek-r1:8b")
    monkeypatch.setenv("KERAUNOS_LLM_URL", api._llm_presets["ollama"]["url"])
    client = TestClient(api.app)

    with patch("api._fetch_ollama_models", return_value=[{"id": "deepseek-r1:8b", "label": "deepseek-r1:8b"}]):
        response = client.get("/llm/status")

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "ollama"
    assert isinstance(body["available_providers"], list)
    assert {item["id"] for item in body["available_providers"]} == {"openrouter", "ollama"}
    assert body["available_models"]["ollama"][0]["id"] == "deepseek-r1:8b"


def test_llm_models_endpoint_returns_ollama_models():
    client = TestClient(api.app)
    with patch("api._fetch_ollama_models", return_value=[{"id": "qwen2.5:7b", "label": "qwen2.5:7b"}]):
        response = client.get("/llm/models?provider=ollama")

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "ollama"
    assert body["items"][0]["id"] == "qwen2.5:7b"


def test_set_llm_model_updates_active_provider_model(monkeypatch):
    monkeypatch.setenv("KERAUNOS_LLM_PROVIDER", "ollama")
    client = TestClient(api.app)
    with patch("api._fetch_ollama_models", return_value=[{"id": "llama3.1:8b", "label": "llama3.1:8b"}]):
        response = client.post("/llm/model", json={"model": "llama3.1:8b"})

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "ollama"
    assert body["model"] == "llama3.1:8b"
    assert api.os.environ["KERAUNOS_LLM_MODEL"] == "llama3.1:8b"


def test_default_ollama_url_uses_localhost_outside_docker(monkeypatch):
    monkeypatch.delenv("KERAUNOS_OLLAMA_URL", raising=False)
    with patch("api.Path.exists", return_value=False):
        assert api._default_ollama_url() == "http://localhost:11434"


def test_default_ollama_url_uses_host_gateway_inside_docker(monkeypatch):
    monkeypatch.delenv("KERAUNOS_OLLAMA_URL", raising=False)
    with patch("api.Path.exists", return_value=True):
        assert api._default_ollama_url() == "http://host.docker.internal:11434"
