"""Modules publish findings here; the agent reads them."""
from queue import Queue

bus = Queue()


def publish(finding: dict):
    bus.put(finding)
