import json
import os
from fnmatch import fnmatch
from typing import Dict, Tuple


DEFAULT_POLICY = {
    "default_action": "deny",
    "require_confirmation_for_risk": ["high", "critical"],
    "allowed_tools": [
        "nmap", "http_probe", "searchsploit", "metasploit_search",
        "msf_auxiliary", "wpscan", "sqlmap", "nikto", "gobuster",
        "nuclei", "ffuf", "sslscan", "dns_enum", "enum4linux",
    ],
    "blocked_tools_require_unlock": [
        "msf_exploit", "msf_payload", "msf_session", "hydra",
    ],
    "max_tool_timeout_seconds": 600,
    "tool_timeouts": {
        "nmap": 180, "sqlmap": 300, "nikto": 300, "gobuster": 300,
        "hydra": 300, "nuclei": 300, "ffuf": 300, "msf_exploit": 600,
        "msf_auxiliary": 300, "msf_payload": 120, "msf_session": 120,
        "enum4linux": 300, "sslscan": 120, "dns_enum": 180,
    },
    "blocked_flags": {
        "nmap": ["--script vuln", "--script exploit", "-sU"],
        "wpscan": ["--passwords", "--usernames", "--password-attack", "--stealthy"],
        "sqlmap": ["--os-shell", "--sql-shell", "--file-write", "--file-read"],
        "gobuster": ["--wildcard"],
        "hydra": ["-e nsr"],
    },
}


class PolicyEngine:
    def __init__(self, policy_path: str = "policy.json"):
        self.policy_path = policy_path
        self.policy = self._load_policy()

    def evaluate(self, tool_name: str, params: Dict, target: str, risk_level: str) -> Tuple[bool, str, bool]:
        if not self._target_allowed(target):
            return False, f"Target '{target}' denied by policy scope.", False

        # Check if tool is in the explicit block list that requires manual unlock
        blocked_tools = set(self.policy.get("blocked_tools_require_unlock", []))
        if tool_name in blocked_tools:
            allowed_tools = set(self.policy.get("allowed_tools", []))
            if tool_name not in allowed_tools:
                return False, (
                    f"Tool '{tool_name}' is a critical-risk tool that requires manual unlock. "
                    f"Add it to 'allowed_tools' in policy.json to enable."
                ), False

        # Check if tool is in allowed list
        allowed_tools = set(self.policy.get("allowed_tools", []))
        if allowed_tools and tool_name not in allowed_tools:
            return False, f"Tool '{tool_name}' is not in allowed_tools.", False

        # Check blocked flags
        flags = params.get("flags", "")
        blocked_flags = self.policy.get("blocked_flags", {}).get(tool_name, [])
        for blocked in blocked_flags:
            if blocked == "*":
                return False, f"Tool '{tool_name}' is blocked by policy.", False
            if blocked in flags:
                return False, f"Blocked flag pattern '{blocked}' matched.", False

        needs_confirmation = risk_level.lower() in set(self.policy.get("require_confirmation_for_risk", []))
        return True, "Allowed by policy.", needs_confirmation

    def _target_allowed(self, target: str) -> bool:
        allowed_targets = self.policy.get("allowed_targets", [])
        if not allowed_targets:
            return True
        return any(fnmatch(target, pattern) for pattern in allowed_targets)

    def _load_policy(self):
        if not os.path.exists(self.policy_path):
            self._write_default_policy()
            return dict(DEFAULT_POLICY)
        with open(self.policy_path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def _write_default_policy(self):
        with open(self.policy_path, "w", encoding="utf-8") as handle:
            json.dump(DEFAULT_POLICY, handle, indent=2)
