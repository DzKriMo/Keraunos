import json

from tool_wrappers.base import ToolWrapper


class WPScanWrapper(ToolWrapper):
    tool_name = "wpscan"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        url = params.get("url")
        if not url:
            raise ValueError("wpscan url is required")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")

        cmd = [
            "wpscan",
            "--url",
            url,
            "--format",
            "json",
            "--no-update",
            "--random-user-agent",
        ]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = {}
        return {"result": parsed, "raw": stdout}
