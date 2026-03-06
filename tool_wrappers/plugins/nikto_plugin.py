import csv
import io
import re

from tool_wrappers.base import ToolWrapper


class NiktoWrapper(ToolWrapper):
    """Web server vulnerability scanner wrapping nikto."""

    tool_name = "nikto"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("nikto requires 'target'")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        port = params.get("port")
        ssl = params.get("ssl", False)
        tuning = params.get("tuning")  # e.g. "123bde" — nikto scan tuning

        cmd = ["nikto", "-h", target, "-Format", "csv", "-output", "-"]

        if port:
            cmd.extend(["-p", str(port)])
        if ssl:
            cmd.append("-ssl")
        if tuning:
            cmd.extend(["-Tuning", tuning])

        # Disable interactive prompts
        cmd.append("-nointeractive")

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        vulns = self._parse_csv(stdout)

        return {
            "target": target,
            "vulnerabilities": vulns,
            "count": len(vulns),
            "raw": stdout,
        }

    def _parse_csv(self, raw: str) -> list:
        """Parse nikto CSV output into structured findings."""
        vulns = []
        try:
            reader = csv.reader(io.StringIO(raw))
            for row in reader:
                if len(row) < 7 or row[0].startswith('"'):
                    continue
                vulns.append({
                    "host": row[0] if len(row) > 0 else "",
                    "ip": row[1] if len(row) > 1 else "",
                    "port": row[2] if len(row) > 2 else "",
                    "osvdb": row[3] if len(row) > 3 else "",
                    "method": row[4] if len(row) > 4 else "",
                    "uri": row[5] if len(row) > 5 else "",
                    "description": row[6] if len(row) > 6 else "",
                })
        except Exception:
            # Fallback: return lines with OSVDB or vulnerability indicators
            for line in raw.splitlines():
                if "OSVDB" in line or "+ " in line:
                    vulns.append({"description": line.strip()})
        return vulns
