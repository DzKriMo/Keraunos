from typing import Any, Dict, List
from urllib.parse import urlparse


class AnalysisEngine:
    """Deterministic finding extractor for all tool outputs."""

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def derive_findings(self, history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for event in history:
            tool = event.get("tool")
            result = event.get("result", {})
            params = event.get("params", {})
            handler = self._handlers.get(tool)
            if handler:
                derived = handler(self, params, result)
                findings.extend(self._normalize_findings(derived, tool, params, result))
        return self._dedupe(findings)

    # ------------------------------------------------------------------ #
    # Tool handler registry
    # ------------------------------------------------------------------ #
    _handlers: Dict[str, Any] = {}  # populated below

    # ------------------------------------------------------------------ #
    # Nmap
    # ------------------------------------------------------------------ #
    def _from_nmap(self, params: Dict, result: Dict) -> List[Dict]:
        findings = []
        for item in result.get("ports", []):
            port = str(item.get("port", ""))
            service = str(item.get("service", "unknown"))
            severity = "Medium"
            if port.startswith(("21/", "23/", "445/")):
                severity = "High"
            if port.startswith(("22/", "3389/")):
                severity = "Low"
            findings.append({
                "name": f"Exposed service: {service} on {port}",
                "severity": severity,
                "description": f"Network scan detected {service} exposed on {port}.",
                "evidence": f"nmap reported open port {port} ({service}).",
                "remediation": "Restrict service exposure via firewall, ACLs, or service hardening.",
            })
        return findings

    # ------------------------------------------------------------------ #
    # SQLMap
    # ------------------------------------------------------------------ #
    def _from_sqlmap(self, params: Dict, result: Dict) -> List[Dict]:
        if not result.get("vulnerable"):
            return []
        url = params.get("url", "unknown")
        banner = result.get("banner") or "No DB banner extracted"
        return [{
            "name": "Possible SQL Injection",
            "severity": "High",
            "description": "sqlmap reported indicators of SQL injection vulnerability.",
            "evidence": f"Target: {url}. Banner: {banner}.",
            "remediation": "Use parameterized queries, strict input validation, and WAF protections.",
        }]

    # ------------------------------------------------------------------ #
    # HTTP Probe
    # ------------------------------------------------------------------ #
    def _from_http_probe(self, params: Dict, result: Dict) -> List[Dict]:
        findings = []
        status = int(result.get("status_code", 0))
        hsts = result.get("hsts")
        server = result.get("server")
        powered = result.get("x_powered_by")
        final_url = str(result.get("final_url", ""))
        original_url = str(result.get("url", ""))

        if original_url.startswith("http://") and final_url.startswith("http://"):
            findings.append({
                "name": "HTTP without HTTPS redirect",
                "severity": "Medium",
                "description": "Web endpoint appears to serve traffic over HTTP without redirect to HTTPS.",
                "evidence": f"Requested {original_url}, final URL {final_url}, status {status}.",
                "remediation": "Enforce HTTPS and add permanent HTTP->HTTPS redirects.",
            })
        if final_url.startswith("https://") and not hsts:
            findings.append({
                "name": "Missing HSTS header",
                "severity": "Low",
                "description": "HTTPS endpoint does not advertise Strict-Transport-Security.",
                "evidence": f"No HSTS header on {final_url}.",
                "remediation": "Add Strict-Transport-Security with appropriate max-age and includeSubDomains.",
            })
        if server:
            findings.append({
                "name": "Server banner disclosure",
                "severity": "Low",
                "description": "Server technology banner is exposed in HTTP response headers.",
                "evidence": f"Server header: {server}",
                "remediation": "Reduce information disclosure in server headers where feasible.",
            })
        if powered:
            findings.append({
                "name": "X-Powered-By header disclosure",
                "severity": "Low",
                "description": "Application framework information is exposed in response headers.",
                "evidence": f"X-Powered-By: {powered}",
                "remediation": "Remove or obfuscate framework-identifying response headers.",
            })
        return findings

    # ------------------------------------------------------------------ #
    # Web Interact
    # ------------------------------------------------------------------ #
    def _from_web_interact(self, params: Dict, result: Dict) -> List[Dict]:
        findings = []
        body = str(result.get("response_preview", "") or "").lower()
        final_url = str(result.get("full_url") or result.get("url") or "")
        status = int(result.get("status_code", 0) or 0)
        headers = {str(k).lower(): str(v) for k, v in (result.get("headers") or {}).items()}
        payload = params.get("payload") or {}
        parsed_url = urlparse(final_url) if final_url else None
        path = parsed_url.path if parsed_url else ""
        cookie_header = headers.get("set-cookie", "")
        payload_text = " ".join(str(value) for value in payload.values()).lower()

        if cookie_header and "httponly" not in cookie_header.lower():
            cookie_name = cookie_header.split("=", 1)[0].strip() or "session"
            findings.append({
                "name": "Session cookie missing HttpOnly",
                "severity": "Medium",
                "description": "A browser-facing response set a cookie without the HttpOnly attribute.",
                "affected_resource": final_url or path or "/",
                "evidence": f"{cookie_name} cookie set by {final_url or '/'} without HttpOnly.",
                "remediation": "Set HttpOnly on session cookies to reduce XSS impact.",
                "fingerprint": f"cookie_httponly:{cookie_name}",
            })
        sql_error_tokens = ["sql syntax", "unterminated", "near \"union\"", "database error", "sqlite error", "mysql error", "postgresql", "odbc", "sqlstate"]
        search_like_path = any(token in path.lower() for token in ["/search", "/find", "/query", "/lookup"])
        injection_payload = any(marker in payload_text for marker in ["union", "select", " or ", "'--", "\"--", "1=1", "sleep(", "benchmark("])
        if any(token in body for token in sql_error_tokens) and (
            search_like_path
            or injection_payload
        ):
            findings.append({
                "name": "Potential SQL injection indicator",
                "severity": "High",
                "description": "Application response included SQL error-style content after crafted input.",
                "evidence": f"{final_url} returned SQL-like error text.",
                "remediation": "Use parameterized queries and normalize error handling.",
                "affected_resource": final_url,
                "fingerprint": f"sqli_indicator:{path or final_url}",
            })
        result_set_markers = [
            "<table", "<tr", "<td", "\"items\":", "\"results\":", "\"rows\":", "\"data\":", "records found", "showing results", "result count"
        ]
        identity_markers = [
            "email", "username", "user_id", "full_name", "first_name", "last_name", "account", "profile", "customer", "order"
        ]
        if search_like_path and any(marker in payload_text for marker in ["' or '1'='1", "\" or \"1\"=\"1", "union", "1=1", "' or 1=1", "\" or 1=1"]):
            if any(marker in body for marker in result_set_markers) and any(marker in body for marker in identity_markers):
                findings.append({
                    "name": "Potential SQL injection indicator",
                    "severity": "High",
                    "description": "Crafted search input appears to alter backend query behavior and disclose additional records.",
                    "evidence": f"{final_url} returned multiple account records after injection-style input.",
                    "remediation": "Use parameterized queries and server-side allowlists for search behavior.",
                    "affected_resource": final_url,
                    "fingerprint": f"sqli_indicator:{path or final_url}",
                })
        object_like_path = any(token in path.lower() for token in ["/account", "/profile", "/user", "/member", "/customer", "/order", "/invoice"])
        id_value = params.get("payload", {}).get("id") or params.get("payload", {}).get("user_id") or ""
        if object_like_path and status == 200:
            if any(token in body for token in ["email", "username", "account", "profile", "customer", "order", "invoice", "user id", "member"]) and id_value:
                findings.append({
                    "name": "Potential IDOR on object endpoint",
                    "severity": "High",
                    "description": "Direct object reference appears to expose account data by identifier.",
                    "evidence": f"{final_url} returned account-like data for id={id_value}.",
                    "remediation": "Enforce per-object authorization on account lookups.",
                    "affected_resource": final_url,
                    "fingerprint": f"idor_object:{path or final_url}",
                })
        explicit_authz_failure = any(marker in body for marker in ["authorization is not enforced", "access control missing", "no authorization", "insecure direct object reference"])
        if explicit_authz_failure:
            findings.append({
                "name": "Potential IDOR on object endpoint",
                "severity": "High",
                "description": "Response content indicates missing authorization checks on object access.",
                "evidence": final_url,
                "remediation": "Enforce per-object authorization on object lookups.",
                "affected_resource": final_url,
                "fingerprint": f"idor_object:{path or final_url}",
            })
        if any(token in body for token in ["root:x:", "module.exports", "express()", "const app"]) or "../" in final_url:
            findings.append({
                "name": "Potential arbitrary file read",
                "severity": "High",
                "description": "Response content suggests local file disclosure through path traversal or direct file read.",
                "evidence": final_url,
                "remediation": "Restrict file access to an allowlist and normalize paths before use.",
                "affected_resource": final_url,
                "fingerprint": f"file_read:{path or final_url}",
            })
        target_url = str(payload.get("url") or payload.get("uri") or "").lower()
        internal_targets = ["127.0.0.1", "localhost", "169.254.", "metadata", "internal", ".local", ".internal", "0.0.0.0"]
        ssrf_like_path = any(token in path.lower() for token in ["/fetch", "/proxy", "/url", "/webhook", "/import", "/crawl"])
        fetched_internal = ssrf_like_path and target_url and any(host in target_url for host in internal_targets)
        internal_content = any(marker in body for marker in ["metadata", "instance-id", "internal service", "localhost", "127.0.0.1", "ami-id", "hostname"])
        if fetched_internal and internal_content:
            findings.append({
                "name": "Potential SSRF to internal service",
                "severity": "High",
                "description": "The application appears able to fetch internal-only service content.",
                "evidence": f"{final_url} fetched {target_url}.",
                "remediation": "Block server-side requests to internal networks and sensitive schemes.",
                "affected_resource": final_url,
                "fingerprint": f"ssrf:{path or final_url}",
            })
        command_like_path = any(token in path.lower() for token in ["/diagnostic", "/debug", "/exec", "/console", "/shell", "/ping", "/trace"])
        command_output_markers = ["uid=", "gid=", "root\n", "sh:", "bin/bash", "linux", "windows ip configuration", "command not found"]
        if any(marker in body for marker in command_output_markers) and command_like_path:
            findings.append({
                "name": "Potential command injection",
                "severity": "Critical",
                "description": "Diagnostics output suggests operating system command execution.",
                "evidence": f"{final_url} returned command-execution style output.",
                "remediation": "Remove shell invocation and use strict command allowlists.",
                "affected_resource": final_url,
                "fingerprint": f"command_injection:{path or final_url}",
            })
        content_like_path = any(token in path.lower() for token in ["/board", "/post", "/comment", "/message", "/article", "/feed"])
        if any(marker in body for marker in ["<script", "onerror=", "alert("]) and content_like_path:
            findings.append({
                "name": "Potential stored XSS",
                "severity": "High",
                "description": "Board content reflects active script-like payloads.",
                "evidence": final_url,
                "remediation": "Escape untrusted HTML and enable contextual output encoding.",
                "affected_resource": final_url,
                "fingerprint": f"stored_xss:{path or final_url}",
            })
        token_like_path = any(token_path in final_url for token_path in ["/api/token", "/token", "/jwt", "/oauth"])
        if token_like_path and any(token in body for token in ['"alg":"none"', '"alg": "none"', "unsigned", "bearer"]):
            findings.append({
                "name": "Potential unsigned bearer token",
                "severity": "High",
                "description": "Token issuance appears to permit unsigned or weakly validated bearer tokens.",
                "evidence": final_url,
                "remediation": "Require signed tokens with strict verification of algorithm, issuer, and audience.",
                "affected_resource": final_url,
                "fingerprint": f"unsigned_token:{path or final_url}",
            })
        if any(token in path.lower() for token in ["/template", "/render", "/preview", "/view"]) and any(marker in body for marker in ["49", "jinja", "template error", "rendered", "{{7*7}}", "twig", "freemarker"]):
            findings.append({
                "name": "Potential server-side template injection",
                "severity": "High",
                "description": "Template-like input appears to be evaluated on the server.",
                "evidence": final_url,
                "remediation": "Avoid rendering untrusted template syntax and isolate template context from user input.",
                "affected_resource": final_url,
                "fingerprint": f"ssti:{path or final_url}",
            })
        if any(token in path.lower() for token in ["/import", "/upload", "/restore", "/deserialize"]) and any(marker in body for marker in ["pickle", "deserialize", "deserializ", "__reduce__", "object restored"]):
            findings.append({
                "name": "Potential unsafe deserialization",
                "severity": "Critical",
                "description": "Import functionality appears to deserialize attacker-controlled content.",
                "evidence": final_url,
                "remediation": "Replace unsafe object deserialization with strict schema validation and safe parsers.",
                "affected_resource": final_url,
                "fingerprint": f"deserialization:{path or final_url}",
            })
        if any(token in path.lower() for token in ["/csrf", "/settings", "/profile", "/admin", "/account", "/checkout"]) and "<form" in body and not any(token in body for token in ["_csrf", "csrf_token", "csrfmiddlewaretoken"]):
            findings.append({
                "name": "Potential missing CSRF protection",
                "severity": "Medium",
                "description": "A state-changing workflow appears to be exposed without an anti-CSRF token.",
                "evidence": final_url,
                "remediation": "Require anti-CSRF tokens and same-site cookie protections for state-changing actions.",
                "affected_resource": final_url,
                "fingerprint": f"csrf:{path or final_url}",
            })
        if any(marker in body for marker in ["without csrf protection", "no csrf protection"]) and (
            path == "/" or any(marker in path.lower() for marker in ["/admin", "/settings", "/profile", "/campaign", "/missions", "/telemetry"])
        ):
            findings.append({
                "name": "Potential missing CSRF protection",
                "severity": "Medium",
                "description": "Application content advertises state-changing actions without anti-CSRF protection.",
                "evidence": final_url or path or "/",
                "remediation": "Require anti-CSRF tokens and same-site cookie protections for state-changing actions.",
                "affected_resource": final_url or path or "/",
                "fingerprint": f"csrf:{path or final_url or '/'}",
            })
        return findings

    # ------------------------------------------------------------------ #
    # WebSocket Interact
    # ------------------------------------------------------------------ #
    def _from_websocket_interact(self, params: Dict, result: Dict) -> List[Dict]:
        received = " ".join(str(item) for item in result.get("messages_received", []))
        if not received:
            return []
        if any(token in received.lower() for token in ["admin", "secret", "banner", "token", "maintenance"]):
            return [{
                "name": "Potential weak WebSocket authorization",
                "severity": "High",
                "description": "WebSocket interaction returned privileged or sensitive content after direct connection.",
                "evidence": received[:300],
                "remediation": "Apply server-side session authorization to WebSocket connection setup and actions.",
            }]
        return []

    # ------------------------------------------------------------------ #
    # WPScan
    # ------------------------------------------------------------------ #
    def _from_wpscan(self, params: Dict, result: Dict) -> List[Dict]:
        findings = []
        data = result.get("result", {})
        version = data.get("version", {})
        if version.get("status") == "insecure":
            findings.append({
                "name": "Insecure WordPress version",
                "severity": "High",
                "description": "WPScan reports an insecure WordPress core version.",
                "evidence": f"Detected version: {version.get('number', 'unknown')}",
                "remediation": "Upgrade WordPress core to the latest secure version.",
            })
        for plugin_name, plugin in (data.get("plugins") or {}).items():
            vulns = plugin.get("vulnerabilities") or []
            if not vulns:
                continue
            findings.append({
                "name": f"Vulnerable WordPress plugin: {plugin_name}",
                "severity": "High",
                "description": "WPScan reported known vulnerabilities in a detected plugin.",
                "evidence": f"Plugin {plugin_name} vulnerability count: {len(vulns)}.",
                "remediation": "Update or remove vulnerable plugin versions and harden plugin management.",
            })
        return findings

    # ------------------------------------------------------------------ #
    # Searchsploit
    # ------------------------------------------------------------------ #
    def _from_searchsploit(self, params: Dict, result: Dict) -> List[Dict]:
        data = result.get("matches", {})
        exploits = data.get("RESULTS_EXPLOIT") or []
        shellcodes = data.get("RESULTS_SHELLCODE") or []
        total = len(exploits) + len(shellcodes)
        if total == 0:
            return []
        return [{
            "name": "Public exploit references found",
            "severity": "Medium",
            "description": "Exploit-DB correlation found public exploit references related to discovered services/software.",
            "evidence": f"searchsploit returned {total} references.",
            "remediation": "Prioritize patching and compensating controls for software with public exploit references.",
        }]

    # ------------------------------------------------------------------ #
    # Metasploit Search
    # ------------------------------------------------------------------ #
    def _from_metasploit_search(self, params: Dict, result: Dict) -> List[Dict]:
        modules = result.get("modules", [])
        if not modules:
            # Fallback to raw text parsing
            raw = str(result.get("raw", ""))
            lines = [line for line in raw.splitlines() if "/" in line and "exploit/" in line]
            if not lines:
                return []
            count = len(lines)
        else:
            count = len([m for m in modules if m.get("type") == "exploit"])
        if count == 0:
            return []
        return [{
            "name": "Metasploit module references found",
            "severity": "Medium",
            "description": "Metasploit search returned exploit module references associated with discovered software/services.",
            "evidence": f"Metasploit exploit modules detected: {count}",
            "remediation": "Prioritize remediation for software with known exploit module coverage.",
        }]

    # ------------------------------------------------------------------ #
    # Metasploit Exploit
    # ------------------------------------------------------------------ #
    def _from_msf_exploit(self, params: Dict, result: Dict) -> List[Dict]:
        if not result.get("success"):
            return []
        module = result.get("module", "unknown")
        return [{
            "name": f"Successful exploitation: {module}",
            "severity": "Critical",
            "description": f"Metasploit exploit module '{module}' successfully opened a session on the target.",
            "evidence": f"Module: {module}. Sessions: {result.get('sessions_after', {})}",
            "remediation": "Immediately patch the exploited vulnerability. Investigate for signs of compromise.",
        }]

    # ------------------------------------------------------------------ #
    # Metasploit Auxiliary
    # ------------------------------------------------------------------ #
    def _from_msf_auxiliary(self, params: Dict, result: Dict) -> List[Dict]:
        module = result.get("module", params.get("module", "unknown"))
        raw = str(result.get("raw", ""))
        if "[+]" not in raw and not result.get("success"):
            return []
        return [{
            "name": f"Auxiliary scanner result: {module}",
            "severity": "Medium",
            "description": f"MSF auxiliary module '{module}' produced positive results.",
            "evidence": f"Module: {module}. Source: {result.get('source', 'unknown')}.",
            "remediation": "Review auxiliary output for exposed services and misconfigurations.",
        }]

    # ------------------------------------------------------------------ #
    # Nikto
    # ------------------------------------------------------------------ #
    def _from_nikto(self, params: Dict, result: Dict) -> List[Dict]:
        vulns = result.get("vulnerabilities", [])
        if not vulns:
            return []
        findings = []
        findings.append({
            "name": "Web server vulnerabilities detected (Nikto)",
            "severity": "Medium",
            "description": f"Nikto detected {len(vulns)} potential web server issues.",
            "evidence": f"Total findings: {len(vulns)}. Sample: {vulns[0].get('description', '')[:200]}",
            "remediation": "Review Nikto findings individually, patch outdated server software, and remove default pages.",
        })
        # Flag specific high-severity entries
        for vuln in vulns:
            desc = str(vuln.get("description", "")).lower()
            if any(kw in desc for kw in ["remote code", "rce", "file inclusion", "backdoor", "shell"]):
                findings.append({
                    "name": f"Critical Nikto finding: {vuln.get('description', '')[:80]}",
                    "severity": "High",
                    "description": vuln.get("description", ""),
                    "evidence": f"OSVDB: {vuln.get('osvdb', 'N/A')}. URI: {vuln.get('uri', '')}",
                    "remediation": "Immediately investigate and remediate this finding.",
                })
        return findings

    # ------------------------------------------------------------------ #
    # Gobuster
    # ------------------------------------------------------------------ #
    def _from_gobuster(self, params: Dict, result: Dict) -> List[Dict]:
        results = result.get("results", [])
        if not results:
            return []
        mode = result.get("mode", "dir")
        findings = []
        if mode == "dir":
            sensitive = [r for r in results if any(kw in r.get("path", "").lower()
                         for kw in ["/admin", "/backup", "/.git", "/.env", "/config", "/phpmyadmin",
                                    "/wp-admin", "/debug", "/test", "/swagger", "/api-docs"])]
            if sensitive:
                findings.append({
                    "name": "Sensitive directories discovered",
                    "severity": "High",
                    "description": f"Gobuster found {len(sensitive)} sensitive directory paths.",
                    "evidence": f"Paths: {', '.join(r.get('path', '') for r in sensitive[:10])}",
                    "remediation": "Restrict access to sensitive paths via authentication and ACLs.",
                })
            if len(results) > len(sensitive):
                findings.append({
                    "name": f"Directory enumeration: {len(results)} paths found",
                    "severity": "Low",
                    "description": "Gobuster directory brute-force discovered accessible paths.",
                    "evidence": f"Total: {len(results)} paths discovered.",
                    "remediation": "Review exposed directories and restrict unnecessary access.",
                })
        elif mode == "dns":
            findings.append({
                "name": f"Subdomain enumeration: {len(results)} subdomains found",
                "severity": "Low",
                "description": "Gobuster DNS brute-force discovered subdomains.",
                "evidence": f"Subdomains: {', '.join(r.get('subdomain', '') for r in results[:10])}",
                "remediation": "Audit exposed subdomains and restrict unused DNS entries.",
            })
        return findings

    # ------------------------------------------------------------------ #
    # Hydra
    # ------------------------------------------------------------------ #
    def _from_hydra(self, params: Dict, result: Dict) -> List[Dict]:
        creds = result.get("credentials", [])
        if not creds:
            return []
        return [{
            "name": f"Cracked credentials: {result.get('service', 'unknown')}",
            "severity": "Critical",
            "description": f"Hydra brute-force found {len(creds)} valid credential pair(s) for {result.get('service', '')}.",
            "evidence": f"Hosts: {', '.join(c.get('host', '') for c in creds[:5])}. Users: {', '.join(c.get('username', '') for c in creds[:5])}.",
            "remediation": "Enforce strong passwords, account lockout policies, and MFA.",
        }]

    # ------------------------------------------------------------------ #
    # Enum4linux
    # ------------------------------------------------------------------ #
    def _from_enum4linux(self, params: Dict, result: Dict) -> List[Dict]:
        data = result.get("data", {})
        findings = []
        shares = data.get("shares", {})
        if isinstance(shares, dict) and shares:
            findings.append({
                "name": "SMB shares enumerated",
                "severity": "Medium",
                "description": f"Enum4linux discovered {len(shares)} accessible SMB shares.",
                "evidence": f"Shares: {list(shares.keys()) if isinstance(shares, dict) else shares}",
                "remediation": "Restrict SMB share access, disable null sessions, and enforce authentication.",
            })
        elif isinstance(shares, list) and shares:
            findings.append({
                "name": "SMB shares enumerated",
                "severity": "Medium",
                "description": f"Enum4linux discovered {len(shares)} accessible SMB shares.",
                "evidence": f"Shares: {[s.get('name', '') for s in shares[:10]]}",
                "remediation": "Restrict SMB share access, disable null sessions, and enforce authentication.",
            })
        users = data.get("users", {})
        if users:
            user_count = len(users) if isinstance(users, (dict, list)) else 0
            if user_count > 0:
                findings.append({
                    "name": "User accounts enumerated via SMB",
                    "severity": "Medium",
                    "description": f"Enum4linux discovered {user_count} user accounts via null session.",
                    "evidence": f"User count: {user_count}",
                    "remediation": "Disable null SMB sessions and restrict user enumeration.",
                })
        return findings

    # ------------------------------------------------------------------ #
    # Nuclei
    # ------------------------------------------------------------------ #
    def _from_nuclei(self, params: Dict, result: Dict) -> List[Dict]:
        nuclei_findings = result.get("findings", [])
        if not nuclei_findings:
            return []
        findings = []
        severity_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Low"}
        for nf in nuclei_findings:
            sev = severity_map.get(str(nf.get("severity", "")).lower(), "Medium")
            cve_ids = nf.get("cve_id", [])
            cve_str = f" (CVE: {', '.join(cve_ids)})" if cve_ids else ""
            findings.append({
                "name": f"Nuclei: {nf.get('name', nf.get('template_id', 'unknown'))}{cve_str}",
                "severity": sev,
                "description": nf.get("description", nf.get("name", "")),
                "evidence": f"Matched at: {nf.get('matched_at', '')}. Template: {nf.get('template_id', '')}. CVSS: {nf.get('cvss_score', 'N/A')}.",
                "remediation": "Apply vendor patches or mitigations for the identified vulnerability.",
            })
        return findings

    # ------------------------------------------------------------------ #
    # FFUF
    # ------------------------------------------------------------------ #
    def _from_ffuf(self, params: Dict, result: Dict) -> List[Dict]:
        results = result.get("results", [])
        if not results:
            return []
        findings = []
        sensitive = [r for r in results if any(kw in str(r.get("input", "")).lower()
                     for kw in ["admin", "backup", ".git", ".env", "config", "debug", "secret", "token"])]
        if sensitive:
            findings.append({
                "name": "Sensitive endpoints discovered (FFUF)",
                "severity": "High",
                "description": f"FFUF fuzzing discovered {len(sensitive)} potentially sensitive endpoints.",
                "evidence": f"Endpoints: {', '.join(r.get('input', '') for r in sensitive[:10])}",
                "remediation": "Restrict access to sensitive endpoints via authentication and ACLs.",
            })
        findings.append({
            "name": f"Web fuzzing: {len(results)} responses found",
            "severity": "Low",
            "description": f"FFUF web fuzzing discovered {len(results)} responding endpoints.",
            "evidence": f"Total: {len(results)} endpoints. Status codes: {set(r.get('status', 0) for r in results)}",
            "remediation": "Review exposed endpoints and restrict unnecessary access.",
        })
        return findings

    # ------------------------------------------------------------------ #
    # SSLScan
    # ------------------------------------------------------------------ #
    def _from_sslscan(self, params: Dict, result: Dict) -> List[Dict]:
        data = result.get("data", {})
        vulns = data.get("vulnerabilities", [])
        findings = []
        for vuln in vulns:
            severity = "High" if "deprecated" in vuln.lower() or "expired" in vuln.lower() else "Medium"
            findings.append({
                "name": f"TLS/SSL issue: {vuln}",
                "severity": severity,
                "description": vuln,
                "evidence": f"Target: {result.get('target', '')}. sslscan detected the issue.",
                "remediation": "Update TLS configuration to disable weak protocols and ciphers.",
            })
        # Check certificate
        cert = data.get("certificate", {})
        if cert.get("expired"):
            findings.append({
                "name": "Expired SSL/TLS certificate",
                "severity": "High",
                "description": "The server's SSL/TLS certificate has expired.",
                "evidence": f"Not after: {cert.get('not_after', 'unknown')}",
                "remediation": "Renew the SSL/TLS certificate immediately.",
            })
        if cert.get("self_signed"):
            findings.append({
                "name": "Self-signed SSL/TLS certificate",
                "severity": "Medium",
                "description": "The server uses a self-signed certificate.",
                "evidence": f"Issuer: {cert.get('issuer', 'unknown')}",
                "remediation": "Replace with a certificate issued by a trusted CA.",
            })
        return findings

    # ------------------------------------------------------------------ #
    # DNS Enum
    # ------------------------------------------------------------------ #
    def _from_dns_enum(self, params: Dict, result: Dict) -> List[Dict]:
        records = result.get("records", [])
        if not records:
            return []
        # Check for zone transfer
        scan_type = result.get("type", "")
        if scan_type == "axfr" and records:
            return [{
                "name": "DNS zone transfer possible",
                "severity": "High",
                "description": "DNS zone transfer (AXFR) succeeded, exposing all DNS records.",
                "evidence": f"Records retrieved: {len(records)}",
                "remediation": "Restrict zone transfers to authorized secondary DNS servers only.",
            }]
        return [{
            "name": f"DNS enumeration: {len(records)} records found",
            "severity": "Low",
            "description": f"DNS reconnaissance discovered {len(records)} records for the target domain.",
            "evidence": f"Record types: {set(r.get('type', '') for r in records)}",
            "remediation": "Review DNS records for information disclosure and unnecessary entries.",
        }]

    # ------------------------------------------------------------------ #
    # Deduplication
    # ------------------------------------------------------------------ #
    def _dedupe(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for finding in findings:
            key = finding.get("fingerprint") or (finding.get("name"), finding.get("evidence"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _normalize_findings(self, findings: List[Dict[str, Any]], tool: str, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        normalized = []
        for finding in findings:
            item = dict(finding)
            item.setdefault("source_tool", tool)
            item.setdefault("category", self._infer_category(item, params))
            item.setdefault("confidence", self._infer_confidence(item, tool, params, result))
            item["confidence"] = max(0.05, min(float(item["confidence"]), 0.99))
            normalized.append(item)
        return normalized

    def _infer_category(self, finding: Dict[str, Any], params: Dict[str, Any]) -> str:
        name = str(finding.get("name", "")).lower()
        affected = str(finding.get("affected_resource", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()
        text = " ".join([name, affected, evidence])
        if "sql" in text:
            return "Injection"
        if "xss" in text:
            return "Injection"
        if "template" in text:
            return "Injection"
        if "command" in text:
            return "RCE"
        if "deserialization" in text:
            return "RCE"
        if "idor" in text or any(token in text for token in ["/account", "/profile", "/user", "/member", "/customer", "/order"]):
            return "Authorization"
        if "token" in text or "jwt" in text or "bearer" in text:
            return "Authentication"
        if "csrf" in text:
            return "Session"
        if "cookie" in text:
            return "Session"
        if "websocket" in text or "/ws" in text:
            return "Realtime"
        if "ssrf" in text or any(token in text for token in ["/fetch", "/proxy", "/url", "/webhook", "/import"]):
            return "Server-Side Request"
        if "file" in text or "download" in text:
            return "File Access"
        if "tls" in text or "ssl" in text or "http " in text:
            return "Transport"
        if "port" in text or "service" in text:
            return "Exposure"
        return "General"

    def _infer_confidence(self, finding: Dict[str, Any], tool: str, params: Dict[str, Any], result: Dict[str, Any]) -> float:
        name = str(finding.get("name", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()
        severity = str(finding.get("severity", "Low"))

        if tool == "sqlmap" and result.get("vulnerable"):
            return 0.95
        if tool == "nuclei":
            return 0.93
        if tool == "websocket_interact" and result.get("messages_received"):
            return 0.82
        if "command injection" in name:
            return 0.94
        if "arbitrary file read" in name:
            return 0.91
        if "unsigned bearer token" in name:
            return 0.84
        if "sql injection indicator" in name:
            return 0.72
        if "possible sql injection" in name:
            return 0.9
        if "idor" in name:
            return 0.83
        if "stored xss" in name:
            return 0.78
        if "server-side template injection" in name:
            return 0.76
        if "unsafe deserialization" in name:
            return 0.74
        if "ssrf" in name:
            return 0.81
        if "csrf" in name:
            return 0.65
        if "httponly" in name:
            return 0.86
        if "exposed service" in name:
            return 0.68 if severity == "High" else 0.58
        if "header disclosure" in name:
            return 0.88
        return 0.7 if severity in {"Critical", "High"} else 0.6


# ------------------------------------------------------------------ #
# Register all handlers
# ------------------------------------------------------------------ #
AnalysisEngine._handlers = {
    "nmap": AnalysisEngine._from_nmap,
    "sqlmap": AnalysisEngine._from_sqlmap,
    "http_probe": AnalysisEngine._from_http_probe,
    "web_interact": AnalysisEngine._from_web_interact,
    "websocket_interact": AnalysisEngine._from_websocket_interact,
    "wpscan": AnalysisEngine._from_wpscan,
    "searchsploit": AnalysisEngine._from_searchsploit,
    "metasploit_search": AnalysisEngine._from_metasploit_search,
    "msf_exploit": AnalysisEngine._from_msf_exploit,
    "msf_auxiliary": AnalysisEngine._from_msf_auxiliary,
    "nikto": AnalysisEngine._from_nikto,
    "gobuster": AnalysisEngine._from_gobuster,
    "hydra": AnalysisEngine._from_hydra,
    "enum4linux": AnalysisEngine._from_enum4linux,
    "nuclei": AnalysisEngine._from_nuclei,
    "ffuf": AnalysisEngine._from_ffuf,
    "sslscan": AnalysisEngine._from_sslscan,
    "dns_enum": AnalysisEngine._from_dns_enum,
}
