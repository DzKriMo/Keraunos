import shlex
import xml.etree.ElementTree as ET

from tool_wrappers.base import ToolWrapper


class NmapWrapper(ToolWrapper):
    tool_name = "nmap"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("nmap target is required")

        flags = params.get("flags", "-sV -sS")
        output_format = params.get("output_format", "xml")
        timeout = int(params.get("timeout", 300))
        stop_callback = params.get("__stop_callback")
        flag_parts = shlex.split(flags)

        cmd = ["nmap"] + flag_parts + [target]
        if output_format == "xml":
            cmd += ["-oX", "-"]
        stdout = self._run_command(cmd, timeout=timeout, stop_callback=stop_callback)

        ports = self._parse_ports(stdout, output_format)
        return {"ports": ports, "raw": stdout}

    def _parse_ports(self, raw_output: str, output_format: str):
        if output_format != "xml":
            return []
        ports = []
        try:
            root = ET.fromstring(raw_output)
            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                for port in host.findall(".//port"):
                    state_el = port.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    service_el = port.find("service")
                    ports.append(
                        {
                            "port": f"{port.get('portid')}/{port.get('protocol', 'tcp')}",
                            "service": service_el.get("name", "unknown") if service_el is not None else "unknown",
                        }
                    )
        except ET.ParseError:
            return []
        return ports
