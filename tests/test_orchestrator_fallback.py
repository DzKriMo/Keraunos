from orchestrator import Orchestrator


def _base_history_without_exploit_search():
    return [
        {"tool": "nmap", "result": {}},
        {"tool": "dns_enum", "result": {}},
        {"tool": "http_probe", "result": {}},
        {"tool": "sslscan", "result": {}},
        {"tool": "nikto", "result": {}},
        {"tool": "gobuster", "result": {}},
        {"tool": "ffuf", "result": {}},
        {"tool": "nuclei", "result": {}},
        {"tool": "wpscan", "result": {}},
        {"tool": "sqlmap", "result": {}},
        {"tool": "enum4linux", "result": {}},
        {"tool": "msf_auxiliary", "result": {}},
    ]


def test_fallback_does_not_crash_without_findings(tmp_path):
    orchestrator = Orchestrator(
        target="example.com",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
    )
    orchestrator.state = {
        "phase": "recon",
        "history": _base_history_without_exploit_search() + [
            {"tool": "searchsploit", "result": {}},
            {"tool": "metasploit_search", "result": {}},
        ],
        "findings": [],
        "target": "example.com",
        "scope": "",
    }

    action = orchestrator._fallback_action("next_action", {})
    assert action["type"] == "complete"


def test_fallback_uses_metasploit_search_tool_name(tmp_path):
    orchestrator = Orchestrator(
        target="example.com",
        scope="",
        data_dir=str(tmp_path),
        llm_enabled=False,
        require_user_confirmation=False,
    )
    orchestrator.state = {
        "phase": "recon",
        "history": _base_history_without_exploit_search(),
        "findings": [
            {"name": "SMB critical issue", "severity": "High", "evidence": "445/tcp"}
        ],
        "target": "example.com",
        "scope": "",
    }

    action = orchestrator._fallback_action("next_action", {})
    assert action["type"] == "tool"
    assert action["tool"] == "metasploit_search"
