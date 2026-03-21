import os
import socket
import logging

logger = logging.getLogger(__name__)

def is_running_in_docker() -> bool:
    """Detect if the application is running inside a Docker container."""
    return os.path.exists('/.dockerenv')

def sanitize_target(target: str) -> str:
    """
    Sanitizes the target hostname/IP.
    In Docker, maps 'localhost' or '127.0.0.1' to 'host.docker.internal'
    to allow targeting the host machine services.
    """
    if not is_running_in_docker():
        return target

    host_part = target
    protocol = ""
    port = ""

    if "://" in target:
        protocol, rest = target.split("://", 1)
        protocol += "://"
        host_part = rest

    if ":" in host_part:
        host_part, port = host_part.rsplit(":", 1)
        port = ":" + port

    if host_part.lower() in ["localhost", "127.0.0.1"]:
        logger.info(f"Mapping local target '{host_part}' to 'host.docker.internal' for Docker compatibility.")
        host_part = "host.docker.internal"

    return f"{protocol}{host_part}{port}"

def check_host_resolvable(host: str) -> bool:
    """Check if a hostname is resolvable."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False
