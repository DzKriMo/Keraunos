"""Shared Metasploit RPC client with automatic CLI fallback.

Environment variables:
    MSF_RPC_HOST  – msfrpcd host (default: 127.0.0.1)
    MSF_RPC_PORT  – msfrpcd port (default: 55553)
    MSF_RPC_PASS  – msfrpcd password (default: msf)
    MSF_RPC_SSL   – use SSL (default: true)
"""

import os
import threading
import time


class MsfRpcClient:
    """Lazy-connecting, singleton-style RPC client for Metasploit Framework."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._client = None
                cls._instance._connected = False
                cls._instance._last_attempt = 0.0
                cls._instance._rpc_available = None  # tri-state: None=untested
            return cls._instance

    # ------------------------------------------------------------------ #
    # Configuration from environment
    # ------------------------------------------------------------------ #
    @property
    def host(self):
        return os.environ.get("MSF_RPC_HOST", "127.0.0.1")

    @property
    def port(self):
        return int(os.environ.get("MSF_RPC_PORT", "55553"))

    @property
    def password(self):
        return os.environ.get("MSF_RPC_PASS", "msf")

    @property
    def ssl(self):
        return os.environ.get("MSF_RPC_SSL", "true").lower() in ("true", "1", "yes")

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #
    def connect(self, force: bool = False) -> bool:
        """Attempt RPC connection. Returns True on success."""
        if self._connected and not force:
            return True

        # Rate-limit reconnection attempts to once per 30s
        now = time.monotonic()
        if not force and (now - self._last_attempt) < 30:
            return self._connected

        self._last_attempt = now
        try:
            from pymetasploit3.msfrpc import MsfRpcClient as _RpcClient

            self._client = _RpcClient(
                self.password,
                server=self.host,
                port=self.port,
                ssl=self.ssl,
            )
            self._connected = True
            self._rpc_available = True
            return True
        except Exception:
            self._client = None
            self._connected = False
            self._rpc_available = False
            return False

    @property
    def client(self):
        """Return the underlying pymetasploit3 client or None."""
        if not self._connected:
            self.connect()
        return self._client

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def rpc_available(self) -> bool:
        """True if RPC was reachable on last attempt, None if untested."""
        if self._rpc_available is None:
            self.connect()
        return bool(self._rpc_available)

    def disconnect(self):
        """Tear down the RPC session."""
        try:
            if self._client:
                self._client.logout()
        except Exception:
            pass
        self._client = None
        self._connected = False

    # ------------------------------------------------------------------ #
    # Convenience helpers used by plugins
    # ------------------------------------------------------------------ #
    def search_modules(self, query: str):
        """Search modules via RPC. Returns list of dicts."""
        if not self.client:
            return None  # caller should fall back to CLI
        try:
            results = self.client.modules.search(query)
            return [
                {
                    "type": m.get("type", ""),
                    "name": m.get("fullname", ""),
                    "rank": m.get("rank", ""),
                    "description": m.get("name", ""),
                    "date": m.get("disclosure_date", ""),
                }
                for m in results
            ]
        except Exception:
            return None

    def run_exploit(self, module_path: str, options: dict):
        """Configure and execute an exploit module. Returns job/session info."""
        if not self.client:
            return None
        exploit = self.client.modules.use("exploit", module_path)
        for key, value in options.items():
            exploit[key] = value
        result = exploit.execute()
        return result

    def run_auxiliary(self, module_path: str, options: dict):
        """Configure and execute an auxiliary module."""
        if not self.client:
            return None
        aux = self.client.modules.use("auxiliary", module_path)
        for key, value in options.items():
            aux[key] = value
        result = aux.execute()
        return result

    def list_sessions(self):
        """Return dict of active sessions."""
        if not self.client:
            return None
        return dict(self.client.sessions.list)

    def session_command(self, session_id: int, command: str):
        """Run a command on an existing session."""
        if not self.client:
            return None
        shell = self.client.sessions.session(str(session_id))
        shell.write(command)
        time.sleep(2)  # give the command time to execute
        return shell.read()
