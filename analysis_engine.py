from typing import Any, Dict, List


class AnalysisEngine:
    def derive_findings(self, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for event in history:
            tool = event.get("tool")
            result = event.get("result", {})
            if tool == "nmap":
                findings.extend(self._from_nmap(result))
            elif tool == "sqlmap":
                findings.extend(self._from_sqlmap(event.get("params", {}), result))
            elif tool == "http_probe":
                findings.extend(self._from_http_probe(result))
            elif tool == "wpscan":
                findings.extend(self._from_wpscan(result))
            elif tool == "searchsploit":
                findings.extend(self._from_searchsploit(result))
        return self._dedupe(findings)

    def _from_nmap(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        ports = result.get("ports", [])
        for item in ports:
            port = str(item.get("port", ""))
            service = str(item.get("service", "unknown"))
            severity = "Medium"
            if port.startswith(("21/", "23/", "445/")):
                severity = "High"
            if port.startswith(("22/", "3389/")):
                severity = "Low"
            findings.append(
                {
                    "name": f"Exposed service: {service} on {port}",
                    "severity": severity,
                    "description": f"Network scan detected {service} exposed on {port}.",
                    "evidence": f"nmap reported open port {port} ({service}).",
                    "remediation": "Restrict service exposure via firewall, ACLs, or service hardening.",
                }
            )
        return findings

    def _from_sqlmap(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        url = params.get("url", "unknown")
        banner = result.get("banner") or "No DB banner extracted"
        return [
            {
                "name": "Possible SQL Injection",
                "severity": "High",
                "description": "sqlmap reported indicators of SQL injection vulnerability.",
                "evidence": f"Target: {url}. Banner: {banner}.",
                "remediation": "Use parameterized queries, strict input validation, and WAF protections.",
            }
        ]

    def _dedupe(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for finding in findings:
            key = (finding.get("name"), finding.get("evidence"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _from_http_probe(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        status = int(result.get("status_code", 0))
        hsts = result.get("hsts")
        server = result.get("server")
        powered = result.get("x_powered_by")
        final_url = str(result.get("final_url", ""))
        original_url = str(result.get("url", ""))

        if original_url.startswith("http://") and final_url.startswith("http://"):
            findings.append(
                {
                    "name": "HTTP without HTTPS redirect",
                    "severity": "Medium",
                    "description": "Web endpoint appears to serve traffic over HTTP without redirect to HTTPS.",
                    "evidence": f"Requested {original_url}, final URL {final_url}, status {status}.",
                    "remediation": "Enforce HTTPS and add permanent HTTP->HTTPS redirects.",
                }
            )
        if final_url.startswith("https://") and not hsts:
            findings.append(
                {
                    "name": "Missing HSTS header",
                    "severity": "Low",
                    "description": "HTTPS endpoint does not advertise Strict-Transport-Security.",
                    "evidence": f"No HSTS header on {final_url}.",
                    "remediation": "Add Strict-Transport-Security with appropriate max-age and includeSubDomains.",
                }
            )
        if server:
            findings.append(
                {
                    "name": "Server banner disclosure",
                    "severity": "Low",
                    "description": "Server technology banner is exposed in HTTP response headers.",
                    "evidence": f"Server header: {server}",
                    "remediation": "Reduce information disclosure in server headers where feasible.",
                }
            )
        if powered:
            findings.append(
                {
                    "name": "X-Powered-By header disclosure",
                    "severity": "Low",
                    "description": "Application framework information is exposed in response headers.",
                    "evidence": f"X-Powered-By: {powered}",
                    "remediation": "Remove or obfuscate framework-identifying response headers.",
                }
            )
        return findings

    def _from_wpscan(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        data = result.get("result", {})
        version = data.get("version", {})
        if version.get("status") == "insecure":
            findings.append(
                {
                    "name": "Insecure WordPress version",
                    "severity": "High",
                    "description": "WPScan reports an insecure WordPress core version.",
                    "evidence": f"Detected version: {version.get('number', 'unknown')}",
                    "remediation": "Upgrade WordPress core to the latest secure version.",
                }
            )
        for plugin_name, plugin in (data.get("plugins") or {}).items():
            vulns = plugin.get("vulnerabilities") or []
            if not vulns:
                continue
            findings.append(
                {
                    "name": f"Vulnerable WordPress plugin: {plugin_name}",
                    "severity": "High",
                    "description": "WPScan reported known vulnerabilities in a detected plugin.",
                    "evidence": f"Plugin {plugin_name} vulnerability count: {len(vulns)}.",
                    "remediation": "Update or remove vulnerable plugin versions and harden plugin management.",
                }
            )
        return findings

    def _from_searchsploit(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = result.get("matches", {})
        exploits = (data.get("RESULTS_EXPLOIT") or [])
        shellcodes = (data.get("RESULTS_SHELLCODE") or [])
        total = len(exploits) + len(shellcodes)
        if total == 0:
            return []
        return [
            {
                "name": "Public exploit references found",
                "severity": "Medium",
                "description": "Exploit-DB correlation found public exploit references related to discovered services/software.",
                "evidence": f"searchsploit returned {total} references.",
                "remediation": "Prioritize patching and compensating controls for software with public exploit references.",
            }
        ]
