import json

from tool_wrappers.base import ToolWrapper


class DnsEnumWrapper(ToolWrapper):
    """DNS reconnaissance via dnsrecon."""

    tool_name = "dns_enum"
    risk_level = "low"

    VALID_TYPES = {"std", "rvl", "brt", "srv", "axfr", "bing", "crt", "snoop"}

    def run(self, params: dict) -> dict:
        domain = params.get("domain")
        if not domain:
            raise ValueError("dns_enum requires 'domain'")

        timeout = int(params.get("timeout", 180))
        stop_callback = params.get("__stop_callback")
        scan_type = params.get("type", "std")  # std, brt, axfr, etc.
        wordlist = params.get("wordlist")
        nameserver = params.get("nameserver")

        if scan_type not in self.VALID_TYPES:
            raise ValueError(f"dns_enum type must be one of: {', '.join(sorted(self.VALID_TYPES))}")

        cmd = ["dnsrecon", "-d", domain, "-t", scan_type, "-j", "-"]

        if wordlist and scan_type == "brt":
            cmd.extend(["-D", wordlist])
        if nameserver:
            cmd.extend(["-n", nameserver])

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        records = self._parse_json(stdout)

        return {
            "domain": domain,
            "type": scan_type,
            "records": records,
            "count": len(records),
            "raw": stdout,
        }

    def _parse_json(self, raw: str) -> list:
        """Parse dnsrecon JSON output."""
        records = []
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for entry in data:
                    records.append({
                        "type": entry.get("type", ""),
                        "name": entry.get("name", ""),
                        "address": entry.get("address", ""),
                        "target": entry.get("target", ""),
                        "port": entry.get("port", ""),
                        "strings": entry.get("strings", ""),
                    })
        except json.JSONDecodeError:
            pass
        return records
