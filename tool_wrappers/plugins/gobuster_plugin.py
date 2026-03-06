import re

from tool_wrappers.base import ToolWrapper


class GobusterWrapper(ToolWrapper):
    """Directory, DNS, and vhost brute-forcing via gobuster."""

    tool_name = "gobuster"
    risk_level = "medium"

    DEFAULT_WORDLISTS = {
        "dir": "/usr/share/wordlists/dirb/common.txt",
        "dns": "/usr/share/wordlists/dnsmap.txt",
        "vhost": "/usr/share/wordlists/dirb/common.txt",
    }

    def run(self, params: dict) -> dict:
        url = params.get("url")
        mode = params.get("mode", "dir")
        if not url:
            raise ValueError("gobuster requires 'url'")
        if mode not in ("dir", "dns", "vhost"):
            raise ValueError("gobuster mode must be 'dir', 'dns', or 'vhost'")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        wordlist = params.get("wordlist", self.DEFAULT_WORDLISTS.get(mode, ""))
        extensions = params.get("extensions")  # e.g. "php,html,txt"
        threads = params.get("threads", 10)

        cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-t", str(threads), "-q", "--no-progress"]

        if mode == "dir" and extensions:
            cmd.extend(["-x", extensions])

        # DNS mode uses -d instead of -u
        if mode == "dns":
            cmd = ["gobuster", "dns", "-d", url, "-w", wordlist, "-t", str(threads), "-q", "--no-progress"]

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        results = self._parse_output(stdout, mode)

        return {
            "url": url,
            "mode": mode,
            "results": results,
            "count": len(results),
            "raw": stdout,
        }

    def _parse_output(self, raw: str, mode: str) -> list:
        """Parse gobuster output by mode."""
        results = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("="):
                continue
            if mode == "dir":
                # Lines like: /admin                (Status: 200) [Size: 1234]
                match = re.match(r"(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)])?", line)
                if match:
                    results.append({
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "size": int(match.group(3)) if match.group(3) else 0,
                    })
            elif mode == "dns":
                # Lines like: Found: sub.example.com
                match = re.match(r"Found:\s+(\S+)", line)
                if match:
                    results.append({"subdomain": match.group(1)})
            elif mode == "vhost":
                match = re.match(r"Found:\s+(\S+)", line)
                if match:
                    results.append({"vhost": match.group(1)})
        return results
