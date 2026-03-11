"""
Storage interfaces for events, signatures, and models.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from cloud.schemas import SignatureRule


class EventStore(ABC):
    @abstractmethod
    def save_event(self, evt: Dict[str, Any]) -> None:
        ...


class SignatureStore(ABC):
    @abstractmethod
    def fetch_all(self) -> List[SignatureRule]:
        ...

    @abstractmethod
    def save(self, rule: SignatureRule) -> None:
        ...








