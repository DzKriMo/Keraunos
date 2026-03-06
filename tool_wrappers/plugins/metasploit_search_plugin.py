import re

from tool_wrappers.base import ToolWrapper
from tool_wrappers.msf_rpc_client import MsfRpcClient


class MetasploitSearchWrapper(ToolWrapper):
    """Search Metasploit modules via RPC with CLI fallback."""

    tool_name = "metasploit_search"
    risk_level = "low"

    def run(self, params: dict) -> dict:
        query = params.get("query")
        if not query:
            raise ValueError("metasploit_search query is required")

        timeout = int(params.get("timeout", 120))
        stop_callback = params.get("__stop_callback")
        module_type = params.get("type")  # optional filter: exploit, auxiliary, post...

        # Attempt RPC first
        rpc = MsfRpcClient()
        rpc_results = rpc.search_modules(query)

        if rpc_results is not None:
            # Filter by type if requested
            if module_type:
                rpc_results = [m for m in rpc_results if m.get("type") == module_type]
            return {
                "query": query,
                "source": "rpc",
                "modules": rpc_results,
                "count": len(rpc_results),
            }

        # Fallback to CLI
        search_cmd = f"search {query}"
        if module_type:
            search_cmd = f"search type:{module_type} {query}"
        command = f"{search_cmd}; exit -y"
        cmd = ["msfconsole", "-q", "-x", command]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)

        modules = self._parse_console_output(stdout)
        return {
            "query": query,
            "source": "cli",
            "modules": modules,
            "count": len(modules),
            "raw": stdout,
        }

    def _parse_console_output(self, raw: str) -> list:
        """Parse msfconsole search output into structured module list."""
        modules = []
        for line in raw.splitlines():
            line = line.strip()
            # Module lines look like:  0  exploit/windows/smb/ms17_010  2017-03-14  great  ...
            match = re.match(
                r"^\d+\s+(exploit|auxiliary|post|payload|encoder|nop|evasion)/(\S+)\s+"
                r"(\d{4}-\d{2}-\d{2})?\s*(\w+)?\s+(.*)",
                line,
            )
            if match:
                modules.append(
                    {
                        "type": match.group(1),
                        "name": f"{match.group(1)}/{match.group(2)}",
                        "date": match.group(3) or "",
                        "rank": match.group(4) or "",
                        "description": match.group(5).strip(),
                    }
                )
        return modules
