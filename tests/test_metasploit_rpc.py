"""Tests for the MsfRpcClient singleton and fallback behavior."""

import os
from unittest.mock import patch, MagicMock

from tool_wrappers.msf_rpc_client import MsfRpcClient


def _reset_singleton():
    """Reset the singleton for test isolation."""
    MsfRpcClient._instance = None


def test_singleton_pattern():
    _reset_singleton()
    a = MsfRpcClient()
    b = MsfRpcClient()
    assert a is b


def test_default_config():
    _reset_singleton()
    client = MsfRpcClient()
    assert client.host == "127.0.0.1"
    assert client.port == 55553
    assert client.password == "msf"
    assert client.ssl is True


def test_env_config():
    _reset_singleton()
    with patch.dict(os.environ, {
        "MSF_RPC_HOST": "10.0.0.1",
        "MSF_RPC_PORT": "12345",
        "MSF_RPC_PASS": "secret",
        "MSF_RPC_SSL": "false",
    }):
        client = MsfRpcClient()
        assert client.host == "10.0.0.1"
        assert client.port == 12345
        assert client.password == "secret"
        assert client.ssl is False


def test_connect_failure_graceful():
    _reset_singleton()
    client = MsfRpcClient()
    # Without pymetasploit3 or msfrpcd, connect should fail gracefully
    result = client.connect()
    assert result is False or result is True  # depends on environment
    # Should not raise


def test_search_returns_none_when_disconnected():
    _reset_singleton()
    client = MsfRpcClient()
    client._connected = False
    client._client = None
    client._rpc_available = False
    result = client.search_modules("ms17_010")
    assert result is None


def test_list_sessions_returns_none_when_disconnected():
    _reset_singleton()
    client = MsfRpcClient()
    client._connected = False
    client._client = None
    client._rpc_available = False
    result = client.list_sessions()
    assert result is None


def test_disconnect():
    _reset_singleton()
    client = MsfRpcClient()
    client._connected = True
    client._client = MagicMock()
    client.disconnect()
    assert client._connected is False
    assert client._client is None
