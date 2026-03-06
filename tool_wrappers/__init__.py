import importlib
import inspect
import pkgutil

from .base import ToolWrapper

class ToolWrapperFactory:
    def __init__(self):
        self._wrappers = self._discover_wrappers()

    def get_wrapper(self, tool_name: str):
        if tool_name not in self._wrappers:
            raise ValueError(f"Unknown tool: {tool_name}")
        return self._wrappers[tool_name]()

    def list_tools(self):
        return sorted(self._wrappers.keys())

    def _discover_wrappers(self):
        wrappers = {}
        plugins_pkg = "tool_wrappers.plugins"
        package = importlib.import_module(plugins_pkg)

        for module_info in pkgutil.iter_modules(package.__path__):
            module = importlib.import_module(f"{plugins_pkg}.{module_info.name}")
            for _, cls in inspect.getmembers(module, inspect.isclass):
                if not issubclass(cls, ToolWrapper) or cls is ToolWrapper:
                    continue
                if not getattr(cls, "tool_name", ""):
                    continue
                wrappers[cls.tool_name] = cls
        return wrappers
