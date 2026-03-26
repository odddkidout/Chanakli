"""Dynamic tool registry — discovers and loads all available tool wrappers."""
from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from tools.wrappers import BaseToolWrapper


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseToolWrapper] = {}
        self._discover()

    def _discover(self) -> None:
        import tools.wrappers as wrappers_pkg

        for _importer, modname, _ispkg in pkgutil.iter_modules(wrappers_pkg.__path__):
            if modname == "__init__":
                continue
            try:
                mod = importlib.import_module(f"tools.wrappers.{modname}")
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BaseToolWrapper)
                        and obj is not BaseToolWrapper
                    ):
                        instance = obj()
                        self._tools[instance.name] = instance
            except Exception:
                pass

    def get(self, name: str) -> "BaseToolWrapper | None":
        return self._tools.get(name)

    def available(self) -> list[str]:
        return [name for name, w in self._tools.items() if w.is_available()]
