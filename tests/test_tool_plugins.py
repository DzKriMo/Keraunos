from tool_wrappers import ToolWrapperFactory


def test_plugin_discovery_includes_core_tools():
    factory = ToolWrapperFactory()
    tools = factory.list_tools()
    assert "nmap" in tools
    assert "http_probe" in tools
    assert "searchsploit" in tools
    assert "wpscan" in tools
    assert "sqlmap" in tools
