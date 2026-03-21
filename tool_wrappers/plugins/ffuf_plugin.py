import json
from pathlib import Path

from tool_wrappers.base import ToolWrapper


class FfufWrapper(ToolWrapper):
    """Fast web fuzzer wrapping ffuf."""

    tool_name = "ffuf"
    risk_level = "medium"
    DEFAULT_FALLBACK_WORDLIST = str(Path(__file__).resolve().parents[2] / "data" / "default_web_paths.txt")

    def run(self, params: dict) -> dict:
        url = params.get("url")
        if not url:
            raise ValueError("ffuf requires 'url' (use FUZZ as placeholder, e.g. http://target/FUZZ)")

        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        wordlist = self._resolve_wordlist(wordlist)
        method = params.get("method", "GET")
        mc = params.get("match_codes", "200,204,301,302,307,401,403")
        fc = params.get("filter_codes")
        fs = params.get("filter_size")
        threads = params.get("threads", 40)
        data = params.get("data")  # POST data with FUZZ keyword
        headers = params.get("headers", {})

        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-X", method,
            "-mc", mc,
            "-t", str(threads),
            "-o", "-",
            "-of", "json",
            "-s",  # silent mode
        ]

        if fc:
            cmd.extend(["-fc", str(fc)])
        if fs:
            cmd.extend(["-fs", str(fs)])
        if data:
            cmd.extend(["-d", data])
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)
        results = self._parse_json(stdout)

        return {
            "url": url,
            "wordlist": wordlist,
            "results": results,
            "count": len(results),
            "raw": stdout,
        }

    def _resolve_wordlist(self, requested: str) -> str:
        candidate = Path(str(requested))
        if candidate.exists():
            return str(candidate)
        fallback = Path(self.DEFAULT_FALLBACK_WORDLIST)
        if fallback.exists():
            return str(fallback)
        return str(candidate)

    def _parse_json(self, raw: str) -> list:
        """Parse ffuf JSON output."""
        results = []
        try:
            data = json.loads(raw)
            for result in data.get("results", []):
                results.append({
                    "input": result.get("input", {}).get("FUZZ", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "content_type": result.get("content-type", ""),
                    "url": result.get("url", ""),
                    "redirect_location": result.get("redirectlocation", ""),
                })
        except json.JSONDecodeError:
            pass
        return results
