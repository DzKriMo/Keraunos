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


def test_next_action_coercion_accepts_common_aliases(tmp_path):
    orchestrator = Orchestrator(
        target="http://localhost:3000",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
        mode="webapp",
    )
    action = orchestrator._normalize_next_action(
        {
            "action": "tool_use",
            "tool": "web_interact",
            "parameters": {"path": "/search", "method": "GET"},
        },
        {},
    )
    assert action["type"] == "tool"
    assert action["tool"] == "web_interact"
    assert action["params"]["path"] == "/search"


def test_webapp_redirects_early_nmap_into_web_discovery(tmp_path):
    orchestrator = Orchestrator(
        target="http://localhost:3000",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
        mode="webapp",
    )
    orchestrator.state = {
        "phase": "recon",
        "history": [
            {
                "tool": "web_interact",
                "params": {"path": "/", "method": "GET"},
                "result": {"status_code": 200},
            }
        ],
        "findings": [],
        "target": "http://localhost:3000",
        "scope": "",
    }
    action = orchestrator._normalize_next_action({"type": "tool", "tool": "nmap", "params": {"target": "localhost"}}, {})
    assert action["type"] == "tool"
    assert action["tool"] == "gobuster"


def test_webapp_redirects_homepage_browser_loops_into_next_unseen_route(tmp_path):
    orchestrator = Orchestrator(
        target="http://localhost:3000",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
        mode="webapp",
    )
    orchestrator.state = {
        "phase": "recon",
        "history": [
            {
                "tool": "web_interact",
                "params": {"path": "/", "method": "GET", "browser": True, "browser_action": "goto"},
                "result": {"status_code": 200},
            },
            {
                "tool": "web_interact",
                "params": {"path": "/", "method": "GET", "browser": True, "browser_action": "evaluate"},
                "result": {"status_code": 200},
            },
        ],
        "findings": [],
        "target": "http://localhost:3000",
        "scope": "",
    }
    action = orchestrator._normalize_next_action(
        {
            "type": "tool",
            "tool": "web_interact",
            "params": {"path": "/", "method": "GET", "browser": True, "browser_action": "evaluate"},
        },
        {},
    )
    assert action["type"] == "tool"
    assert action["tool"] == "web_interact"
    assert action["params"]["path"] == "/login"


def test_webapp_low_value_loop_does_not_redirect_first_homepage_visit(tmp_path):
    orchestrator = Orchestrator(
        target="http://localhost:3000",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
        mode="webapp",
    )
    orchestrator.state = {
        "phase": "recon",
        "history": [],
        "findings": [],
        "target": "http://localhost:3000",
        "scope": "",
    }
    action = orchestrator._normalize_next_action(
        {
            "type": "tool",
            "tool": "web_interact",
            "params": {"path": "/", "method": "GET", "browser": True, "browser_action": "goto"},
        },
        {},
    )
    assert action["type"] == "tool"
    assert action["tool"] == "web_interact"
    assert action["params"]["path"] == "/"
