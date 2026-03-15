from __future__ import annotations

import importlib
import pkgutil
from typing import Optional

import structlog

from models.task import AttackTask
from tools.safe_executor import SafeExecutor
from tools.wrappers.base import BaseToolWrapper

logger = structlog.get_logger()


class ToolRegistry:
    """Dynamically loads and manages all tool wrappers."""

    def __init__(self):
        self._tools: dict[str, BaseToolWrapper] = {}
        self._load_all_wrappers()

    def _load_all_wrappers(self) -> None:
        """Auto-discover and register all wrappers in the tools/wrappers package."""
        import tools.wrappers as wrappers_pkg

        for _finder, module_name, _is_pkg in pkgutil.iter_modules(wrappers_pkg.__path__):
            if module_name == "base":
                continue
            full_name = f"tools.wrappers.{module_name}"
            try:
                module = importlib.import_module(full_name)
                # Each wrapper module exposes exactly one BaseToolWrapper subclass
                for attr_name in dir(module):
                    obj = getattr(module, attr_name)
                    if (
                        isinstance(obj, type)
                        and issubclass(obj, BaseToolWrapper)
                        and obj is not BaseToolWrapper
                    ):
                        instance = obj()
                        self._tools[instance.name] = instance
                        logger.debug("tool_registered", tool=instance.name)
            except Exception as exc:
                logger.warning("tool_load_failed", module=full_name, error=str(exc))

    def get(self, name: str) -> Optional[BaseToolWrapper]:
        return self._tools.get(name)

    def list_available(self) -> list[str]:
        return [name for name, wrapper in self._tools.items() if wrapper.is_available()]

    def execute_task(
        self, task: AttackTask, executor: SafeExecutor
    ) -> list[dict]:
        """Execute an AttackTask using the appropriate wrapper."""
        wrapper = self.get(task.tool)
        if wrapper is None:
            logger.warning("tool_not_found", tool=task.tool)
            return []

        if not wrapper.is_available():
            logger.warning("tool_not_available", tool=task.tool)
            return []

        command = wrapper.build_command(task)
        result = executor.run(command)

        if result.scope_error:
            return []

        return wrapper.parse_output(result.stdout, result.stderr)
