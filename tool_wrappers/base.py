import subprocess
import time
from abc import ABC, abstractmethod


class ToolWrapper(ABC):
    tool_name = ""
    risk_level = "low"

    @abstractmethod
    def run(self, params: dict) -> dict:
        """Execute the tool and return parsed results."""
        pass

    def _run_command(self, cmd: list, timeout: int = 300, stop_callback=None) -> str:
        """Run a shell command and return stdout."""
        process = None
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            started = time.monotonic()
            while True:
                if stop_callback and stop_callback():
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    raise Exception("Tool execution cancelled")
                if process.poll() is not None:
                    break
                if (time.monotonic() - started) > timeout:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    raise Exception(f"Tool execution timed out after {timeout} seconds")
                time.sleep(0.2)

            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise Exception(f"Tool error: {stderr}")
            return stdout
        finally:
            if process and process.poll() is None:
                process.kill()
