import xml.etree.ElementTree as ET

from tool_wrappers.base import ToolWrapper


class SSLScanWrapper(ToolWrapper):
    """TLS/SSL analysis via sslscan."""

    tool_name = "sslscan"
    risk_level = "low"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("sslscan requires 'target'")

        timeout = int(params.get("timeout", 120))
        stop_callback = params.get("__stop_callback")
        port = params.get("port", 443)

        host_port = f"{target}:{port}" if ":" not in target else target
        cmd = ["sslscan", "--xml=-", host_port]

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        parsed = self._parse_xml(stdout)

        return {
            "target": host_port,
            "data": parsed,
            "raw": stdout,
        }

    def _parse_xml(self, raw: str) -> dict:
        """Parse sslscan XML output."""
        result = {
            "protocols": [],
            "ciphers": [],
            "certificate": {},
            "vulnerabilities": [],
        }
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return result

        # Parse protocols
        for proto in root.findall(".//protocol"):
            result["protocols"].append({
                "type": proto.get("type", ""),
                "version": proto.get("version", ""),
                "enabled": proto.get("enabled", "") == "1",
            })

        # Parse cipher suites
        for cipher in root.findall(".//cipher"):
            result["ciphers"].append({
                "status": cipher.get("status", ""),
                "ssl_version": cipher.get("sslversion", ""),
                "bits": cipher.get("bits", ""),
                "cipher": cipher.get("cipher", ""),
                "curve": cipher.get("curve", ""),
            })

        # Parse certificate
        cert = root.find(".//certificate")
        if cert is not None:
            result["certificate"] = {
                "subject": cert.findtext("subject", ""),
                "issuer": cert.findtext("issuer", ""),
                "not_before": cert.findtext("not-valid-before", ""),
                "not_after": cert.findtext("not-valid-after", ""),
                "signature_algorithm": cert.findtext("signature-algorithm", ""),
                "pk_bits": cert.findtext("pk", {}).strip() if cert.find("pk") is not None else "",
                "self_signed": cert.findtext("self-signed", "") == "true",
                "expired": cert.findtext("expired", "") == "true",
            }

        # Check for weak configurations
        for proto in result["protocols"]:
            if proto["enabled"] and proto["version"] in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"):
                result["vulnerabilities"].append(
                    f"Deprecated protocol enabled: {proto['type']} {proto['version']}"
                )

        weak_ciphers = [c for c in result["ciphers"] if "NULL" in c["cipher"] or "RC4" in c["cipher"] or "DES" in c["cipher"]]
        if weak_ciphers:
            result["vulnerabilities"].append(f"{len(weak_ciphers)} weak cipher suite(s) supported")

        if result["certificate"].get("self_signed"):
            result["vulnerabilities"].append("Self-signed certificate detected")
        if result["certificate"].get("expired"):
            result["vulnerabilities"].append("Expired certificate detected")

        return result
