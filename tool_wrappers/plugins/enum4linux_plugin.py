import json
import re

from tool_wrappers.base import ToolWrapper


class Enum4linuxWrapper(ToolWrapper):
    """SMB/LDAP/RPC enumeration via enum4linux-ng.

    Enumerates shares, users, groups, password policies, and OS info.
    """

    tool_name = "enum4linux"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("enum4linux requires 'target'")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        flags = params.get("flags", "-A")  # -A = all enumeration

        # Prefer enum4linux-ng (JSON output) over legacy enum4linux
        cmd = ["enum4linux-ng", "-A", "-oJ", "-", target]
        try:
            stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
            parsed = json.loads(stdout)
            return {
                "target": target,
                "source": "enum4linux-ng",
                "data": self._extract_ng(parsed),
                "raw": stdout,
            }
        except Exception:
            pass

        # Fallback to legacy enum4linux
        cmd = ["enum4linux", flags, target]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        return {
            "target": target,
            "source": "enum4linux",
            "data": self._extract_legacy(stdout),
            "raw": stdout,
        }

    def _extract_ng(self, data: dict) -> dict:
        """Extract key data from enum4linux-ng JSON."""
        return {
            "os_info": data.get("os_info", {}),
            "shares": data.get("shares", {}),
            "users": data.get("users", {}),
            "groups": data.get("groups", {}),
            "password_policy": data.get("password_policy", {}),
            "sessions": data.get("sessions", {}),
        }

    def _extract_legacy(self, raw: str) -> dict:
        """Best-effort parsing of legacy enum4linux text output."""
        result = {"shares": [], "users": [], "os_info": ""}

        # Extract shares
        for match in re.finditer(r"//\S+/(\S+)\s+Mapping:\s*(\S+)\s+Listing:\s*(\S+)", raw):
            result["shares"].append({
                "name": match.group(1),
                "mapping": match.group(2),
                "listing": match.group(3),
            })

        # Extract users
        for match in re.finditer(r"user:\[(.*?)\]\s+rid:\[(.*?)\]", raw):
            result["users"].append({
                "user": match.group(1),
                "rid": match.group(2),
            })

        # Extract OS info
        os_match = re.search(r"OS:\s*\[(.*?)\]", raw)
        if os_match:
            result["os_info"] = os_match.group(1)

        return result
