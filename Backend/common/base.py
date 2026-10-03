"""Interface every module (FYP-1 and FYP-2) follows. The agent only talks to this."""
from abc import ABC, abstractmethod


class BaseModule(ABC):
    name = "base"

    @abstractmethod
    def scan(self, target: str) -> dict:
        """Scan a file/folder/target and return a finding dict."""

    @abstractmethod
    def status(self) -> dict:
        """Return running state."""

    @abstractmethod
    def stop(self) -> None:
        """Stop background work."""
