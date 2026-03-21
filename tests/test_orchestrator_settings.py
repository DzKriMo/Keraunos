from orchestrator import Orchestrator


class _DummyWrapper:
    def run(self, params):
        return {
            "seen_settings": params.get("__run_settings"),
            "seen_mode": params.get("__mode"),
            "seen_run_dir": params.get("__run_dir"),
        }


def test_execute_tool_injects_run_metadata(tmp_path):
    orchestrator = Orchestrator(
        target="http://localhost:3000",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
        mode="webapp",
        settings={"browser": {"headless": True}},
    )
    orchestrator.tool_factory.get_wrapper = lambda _: _DummyWrapper()
    result = orchestrator.execute_tool("web_interact", {"path": "/"})
    assert result["seen_settings"] == {"browser": {"headless": True}}
    assert result["seen_mode"] == "webapp"
    assert result["seen_run_dir"] == str(tmp_path)


def test_web_interact_params_are_normalized_for_local_models(tmp_path):
    orchestrator = Orchestrator(
        target="http://localhost:3000",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
        mode="webapp",
    )
    params = orchestrator._default_params_for_tool(
        "web_interact",
        {
            "url": "http://localhost:3000/account?id=2",
            "method": "POST",
            "payload": {"id": "2"},
            "browser": True,
        },
    )
    assert params["target"] == "http://localhost:3000"
    assert params["path"] == "/account?id=2"
    assert params["browser"] is False
