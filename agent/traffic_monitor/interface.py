"""
Traffic monitor abstraction to decouple capture backend.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Callable


class TrafficMonitor(ABC):
    @abstractmethod
    def start(self):
        ...

    @abstractmethod
    def stop(self):
        ...

    @abstractmethod
    def set_callback(self, cb: Callable[[dict], None]):
        ...








