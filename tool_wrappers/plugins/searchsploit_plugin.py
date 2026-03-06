import json

from tool_wrappers.base import ToolWrapper


class SearchsploitWrapper(ToolWrapper):
    tool_name = "searchsploit"
    risk_level = "low"

    def run(self, params: dict) -> dict:
        timeout = int(params.get("timeout", 120))
        stop_callback = params.get("__stop_callback")
        query = params.get("query")
        cve = params.get("cve")
        nmap_xml = params.get("nmap_xml")

        if nmap_xml:
            cmd = ["searchsploit", "--nmap", nmap_xml, "-j"]
        elif cve:
            cmd = ["searchsploit", cve, "-j"]
        elif query:
            cmd = ["searchsploit", query, "-j"]
        else:
            raise ValueError("searchsploit requires one of: query, cve, nmap_xml")

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = {}
        return {"matches": parsed, "raw": stdout}
