import json

from tool_wrappers.base import ToolWrapper


class NucleiWrapper(ToolWrapper):
    """Template-based vulnerability scanner via ProjectDiscovery Nuclei."""

    tool_name = "nuclei"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("nuclei requires 'target'")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        severity = params.get("severity")  # e.g. "critical,high"
        tags = params.get("tags")  # e.g. "cve,rce"
        templates = params.get("templates")  # specific template path
        rate_limit = params.get("rate_limit", 150)

        cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-rl", str(rate_limit)]

        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        if templates:
            cmd.extend(["-t", templates])

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        findings = self._parse_jsonl(stdout)

        return {
            "target": target,
            "findings": findings,
            "count": len(findings),
            "raw": stdout,
        }

    def _parse_jsonl(self, raw: str) -> list:
        """Parse nuclei JSONL output into structured findings."""
        findings = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                findings.append({
                    "template_id": entry.get("template-id", ""),
                    "name": entry.get("info", {}).get("name", ""),
                    "severity": entry.get("info", {}).get("severity", ""),
                    "description": entry.get("info", {}).get("description", ""),
                    "tags": entry.get("info", {}).get("tags", []),
                    "reference": entry.get("info", {}).get("reference", []),
                    "matched_at": entry.get("matched-at", ""),
                    "matcher_name": entry.get("matcher-name", ""),
                    "type": entry.get("type", ""),
                    "curl_command": entry.get("curl-command", ""),
                    "extracted_results": entry.get("extracted-results", []),
                    "cvss_score": entry.get("info", {}).get("classification", {}).get("cvss-score", ""),
                    "cve_id": entry.get("info", {}).get("classification", {}).get("cve-id", []),
                })
            except json.JSONDecodeError:
                continue
        return findings
