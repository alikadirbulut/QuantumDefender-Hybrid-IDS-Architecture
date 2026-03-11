"""
Signature distribution service scaffold.
"""
from __future__ import annotations
from typing import List
from cloud.schemas import SignatureRule


class SignatureDistributionService:
    def __init__(self, repo):
        self.repo = repo

    def list_rules(self) -> List[SignatureRule]:
        return self.repo.fetch_all()

    def version(self) -> str:
        # TODO: compute version/hash over rules
        return "v0.1"








