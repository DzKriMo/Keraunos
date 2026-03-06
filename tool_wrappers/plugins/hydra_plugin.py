import re

from tool_wrappers.base import ToolWrapper


class HydraWrapper(ToolWrapper):
    """Network login brute-forcer wrapping THC Hydra.

    CRITICAL-risk: credential brute-forcing always requires user confirmation.
    """

    tool_name = "hydra"
    risk_level = "critical"

    SUPPORTED_SERVICES = {
        "ssh", "ftp", "http-get", "http-post-form", "http-head",
        "smb", "rdp", "telnet", "mysql", "mssql", "postgres",
        "vnc", "smtp", "pop3", "imap", "ldap",
    }

    def run(self, params: dict) -> dict:
        target = params.get("target")
        service = params.get("service")
        if not target:
            raise ValueError("hydra requires 'target'")
        if not service:
            raise ValueError("hydra requires 'service' (e.g. ssh, ftp, http-get)")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        username = params.get("username")
        userlist = params.get("userlist")
        passlist = params.get("passlist", "/usr/share/wordlists/rockyou.txt")
        password = params.get("password")
        threads = params.get("threads", 4)

        cmd = ["hydra"]

        # User specification
        if username:
            cmd.extend(["-l", username])
        elif userlist:
            cmd.extend(["-L", userlist])
        else:
            cmd.extend(["-l", "admin"])  # default

        # Password specification
        if password:
            cmd.extend(["-p", password])
        elif passlist:
            cmd.extend(["-P", passlist])

        cmd.extend([
            "-t", str(threads),
            "-f",  # exit on first valid pair
            "-o", "-",  # output to stdout
            target,
            service,
        ])

        # For http-post-form, append the form string
        form_string = params.get("form")
        if form_string and "http" in service:
            cmd.append(form_string)

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        credentials = self._parse_output(stdout)

        return {
            "target": target,
            "service": service,
            "credentials": credentials,
            "success": len(credentials) > 0,
            "raw": stdout,
        }

    def _parse_output(self, raw: str) -> list:
        """Parse hydra output for valid credentials."""
        credentials = []
        for line in raw.splitlines():
            # Lines like: [22][ssh] host: 192.168.1.1   login: admin   password: password123
            match = re.search(
                r"host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)",
                line,
            )
            if match:
                credentials.append({
                    "host": match.group(1),
                    "username": match.group(2),
                    "password": match.group(3),
                })
        return credentials
