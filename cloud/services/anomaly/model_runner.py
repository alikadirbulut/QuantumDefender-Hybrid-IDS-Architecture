"""
Model runner scaffold for multiple deep learning models.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict


class ModelRunner(ABC):
    @abstractmethod
    def score(self, features: Dict[str, Any]) -> float:
        ...


class OnnxModelRunner(ModelRunner):
    def __init__(self, session):
        self.session = session
        self.input_name = session.get_inputs()[0].name

    def score(self, features: Dict[str, Any]) -> float:
        # TODO: map features to tensor input shape
        out = self.session.run(None, {self.input_name: features})
        return float(out[0][0][1])








