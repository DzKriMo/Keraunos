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
