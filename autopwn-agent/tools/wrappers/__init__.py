"""Base class for all tool wrappers."""
from __future__ import annotations

from abc import ABC, abstractmethod


class BaseToolWrapper(ABC):
    name: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the tool binary is present on PATH."""

    @abstractmethod
    def build_command(self, task: dict) -> list[str]:
        """Return the list of CLI args (without binary name) for the given task."""

    @abstractmethod
    def parse_output(self, output: str) -> dict | list | None:
        """Parse tool stdout into a finding dict (or list of dicts)."""
