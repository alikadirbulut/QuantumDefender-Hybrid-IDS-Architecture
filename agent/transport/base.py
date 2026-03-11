"""
Transport abstraction for agent-to-cloud communication.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class Transport(ABC):
    @abstractmethod
    def send_batch(self, events: List[Dict[str, Any]]) -> None:
        ...


