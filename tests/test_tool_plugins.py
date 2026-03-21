from tool_wrappers import ToolWrapperFactory


def test_plugin_discovery_includes_core_tools():
    factory = ToolWrapperFactory()
    tools = factory.list_tools()
    # Original tools
    assert "nmap" in tools
    assert "http_probe" in tools
    assert "searchsploit" in tools
    assert "metasploit_search" in tools
    assert "wpscan" in tools
    assert "sqlmap" in tools


def test_plugin_discovery_includes_metasploit_suite():
    factory = ToolWrapperFactory()
    tools = factory.list_tools()
    assert "msf_exploit" in tools
    assert "msf_auxiliary" in tools
    assert "msf_payload" in tools
    assert "msf_session" in tools


def test_plugin_discovery_includes_extra_tools():
    factory = ToolWrapperFactory()
    tools = factory.list_tools()
    assert "nikto" in tools
    assert "gobuster" in tools
    assert "hydra" in tools
    assert "enum4linux" in tools
    assert "nuclei" in tools
    assert "ffuf" in tools
    assert "sslscan" in tools
    assert "dns_enum" in tools
    assert "web_interact" in tools
    assert "websocket_interact" in tools


def test_all_tools_have_risk_level():
    factory = ToolWrapperFactory()
    for tool_name in factory.list_tools():
        wrapper = factory.get_wrapper(tool_name)
        assert hasattr(wrapper, "risk_level"), f"{tool_name} missing risk_level"
        assert wrapper.risk_level in {"low", "medium", "high", "critical"}, (
            f"{tool_name} has invalid risk_level: {wrapper.risk_level}"
        )


def test_critical_tools_have_correct_risk():
    factory = ToolWrapperFactory()
    critical_tools = {"msf_exploit", "msf_payload", "msf_session", "hydra"}
    for tool_name in critical_tools:
        wrapper = factory.get_wrapper(tool_name)
        assert wrapper.risk_level == "critical", (
            f"{tool_name} should be critical-risk but is {wrapper.risk_level}"
        )


def test_total_tool_count():
    factory = ToolWrapperFactory()
    tools = factory.list_tools()
    assert len(tools) >= 18, f"Expected at least 18 tools, got {len(tools)}: {tools}"
