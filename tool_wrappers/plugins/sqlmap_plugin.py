import re

from tool_wrappers.base import ToolWrapper


class SQLMapWrapper(ToolWrapper):
    tool_name = "sqlmap"
    risk_level = "high"

    def run(self, params: dict) -> dict:
        url = params.get("url")
        if not url:
            raise ValueError("sqlmap url is required")
        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")

        cmd = ["sqlmap", "-u", url, "--batch", "--banner"]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        vulnerable = "vulnerable" in stdout.lower()
        banner = re.search(r"banner:\s*(.+)", stdout, re.I)
        return {"vulnerable": vulnerable, "banner": banner.group(1) if banner else None, "raw": stdout}
