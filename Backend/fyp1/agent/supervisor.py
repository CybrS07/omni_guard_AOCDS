"""Main AI agent: loads modules, runs them, correlates findings, decides actions."""
from .registry import MODULES


class Supervisor:
    def __init__(self):
        self.modules = {}

    def start(self):
        for name, cls in MODULES.items():
            self.modules[name] = cls()

    def stop(self):
        for m in self.modules.values():
            m.stop()
