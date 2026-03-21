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
            # If nmap_xml looks like raw XML (starts with <), save it to a temp file
            if nmap_xml.strip().startswith("<"):
                import tempfile
                import os
                with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                    f.write(nmap_xml)
                    temp_path = f.name
                cmd = ["searchsploit", "--nmap", temp_path, "-j"]
                stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
                try:
                    os.unlink(temp_path)
                except:
                    pass
            else:
                cmd = ["searchsploit", "--nmap", nmap_xml, "-j"]
                stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        elif cve:
            cmd = ["searchsploit", cve, "-j"]
            stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        elif query:
            cmd = ["searchsploit", query, "-j"]
            stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        else:
            raise ValueError("searchsploit requires one of: query, cve, nmap_xml")
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            parsed = {}
        return {"matches": parsed, "raw": stdout}
