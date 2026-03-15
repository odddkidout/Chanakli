from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.task import AttackTask


class BaseToolWrapper(ABC):
    name: str
    binary: str

    def is_available(self) -> bool:
        """Check if binary exists in PATH."""
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_command(self, task: "AttackTask") -> list[str]:
        """Build exact command list."""

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str) -> list[dict]:
        """Parse raw output into list of raw finding dicts."""
