"""
Queue abstraction with in-memory implementation; ready to swap for Kafka/Redis.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Callable, Iterable
from queue import Queue


class IngestionQueue(ABC):
    @abstractmethod
    def put(self, item: Any) -> None:
        ...

    @abstractmethod
    def consume(self) -> Iterable[Any]:
        ...


class InMemoryQueue(IngestionQueue):
    def __init__(self):
        self.q = Queue()

    def put(self, item: Any) -> None:
        self.q.put(item)

    def consume(self) -> Iterable[Any]:
        while True:
            item = self.q.get()
            if item is None:
                break
            yield item
            self.q.task_done()








