from tool_wrappers.base import ToolWrapper
from tool_wrappers.msf_rpc_client import MsfRpcClient


class MsfAuxiliaryWrapper(ToolWrapper):
    """Run Metasploit auxiliary/scanner modules.

    Examples: auxiliary/scanner/smb/smb_version, auxiliary/scanner/ssh/ssh_version
    """

    tool_name = "msf_auxiliary"
    risk_level = "high"

    def run(self, params: dict) -> dict:
        module = params.get("module")
        if not module:
            raise ValueError("msf_auxiliary requires 'module' (e.g. auxiliary/scanner/portscan/tcp)")

        rhosts = params.get("rhosts")
        if not rhosts:
            raise ValueError("msf_auxiliary requires 'rhosts'")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")

        # Build options
        options = {"RHOSTS": rhosts}
        if params.get("rport"):
            options["RPORT"] = str(params["rport"])
        if params.get("threads"):
            options["THREADS"] = str(params["threads"])
        extra = params.get("options", {})
        if isinstance(extra, dict):
            options.update(extra)

        # Attempt RPC
        rpc = MsfRpcClient()
        rpc_result = rpc.run_auxiliary(module, options)

        if rpc_result is not None:
            return {
                "module": module,
                "source": "rpc",
                "job": rpc_result,
                "success": True,
            }

        # CLI fallback
        option_cmds = "; ".join(f"set {k} {v}" for k, v in options.items())
        aux_cmd = f"use {module}; {option_cmds}; run; exit -y"
        cmd = ["msfconsole", "-q", "-x", aux_cmd]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)

        return {
            "module": module,
            "source": "cli",
            "success": "completed" in stdout.lower() or "[+]" in stdout,
            "raw": stdout,
        }
