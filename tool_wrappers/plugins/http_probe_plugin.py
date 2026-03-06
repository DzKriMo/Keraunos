import requests

from tool_wrappers.base import ToolWrapper


class HTTPProbeWrapper(ToolWrapper):
    tool_name = "http_probe"
    risk_level = "low"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("http_probe target is required")

        timeout = int(params.get("timeout", 30))
        scheme = params.get("scheme", "http")
        path = params.get("path", "/")
        url = f"{scheme}://{target}{path}"
        response = requests.get(url, timeout=timeout, allow_redirects=True)

        return {
            "url": url,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "server": response.headers.get("Server"),
            "x_powered_by": response.headers.get("X-Powered-By"),
            "hsts": response.headers.get("Strict-Transport-Security"),
        }
