"""
Signature generator scaffold from anomaly patterns.
"""
from __future__ import annotations
from typing import List, Dict
from cloud.schemas import SignatureRule


class SignatureGeneratorService:
    def __init__(self, repo):
        self.repo = repo

    def generate_from_anomalies(self, anomalies: List[Dict]) -> List[SignatureRule]:
        # TODO: mine patterns and propose signatures
        return []

    def persist(self, rules: List[SignatureRule]) -> None:
        for r in rules:
            self.repo.save(r)








