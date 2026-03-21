import time

from llm_interface import LLMInterface, OllamaBackend, OpenAICompatibleBackend, LLMRateLimitCooldown


def test_defaults_to_openrouter_when_api_key_present(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.delenv("KERAUNOS_LLM_PROVIDER", raising=False)
    llm = LLMInterface()
    assert llm.provider == "openrouter"
    assert llm.model == "stepfun/step-3.5-flash:free"
    assert isinstance(llm.backend, OpenAICompatibleBackend)


def test_uses_ollama_when_provider_selected(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("KERAUNOS_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("KERAUNOS_LLM_MODEL", "deepseek-r1:8b")
    llm = LLMInterface()
    assert llm.provider == "ollama"
    assert llm.model == "deepseek-r1:8b"
    assert isinstance(llm.backend, OllamaBackend)


def test_query_raises_when_provider_cooldown_active(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    llm = LLMInterface(
        provider="ollama",
        model="deepseek-r1:8b",
        backend=type("Backend", (), {"generate": lambda self, prompt, **kwargs: '{"type":"complete"}'})(),
    )
    llm.cooldown_until = time.time() + 60
    try:
        llm.query("next_action", {"available_tools": [], "history": [], "findings": []})
        assert False, "expected cooldown exception"
    except LLMRateLimitCooldown:
        assert True


def test_role_specific_model_env(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("KERAUNOS_REPORT_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("KERAUNOS_REPORT_LLM_MODEL", "report-model")
    llm = LLMInterface(role="report")
    assert llm.provider == "ollama"
    assert llm.model == "report-model"
