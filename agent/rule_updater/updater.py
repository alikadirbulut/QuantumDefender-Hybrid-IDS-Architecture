"""
Rule updater stub: fetches rule bundles and hot-reloads the engine.
"""
from __future__ import annotations
import requests
from typing import Callable
from agent.schemas import SignatureRule


class RuleUpdater:
    def __init__(self, endpoint: str, token: str | None, on_rules: Callable[[list[SignatureRule]], None], log=None):
        self.endpoint = endpoint
        self.token = token
        self.on_rules = on_rules
        self.log = log or (lambda x: None)

    def fetch_and_update(self):
        try:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            r = requests.get(self.endpoint, headers=headers, timeout=5)
            r.raise_for_status()
            data = r.json()
            rules = [SignatureRule(**item) for item in data]
            self.on_rules(rules)
            self.log(f"🔄 Loaded {len(rules)} signatures")
        except Exception as e:
            self.log(f"⚠️ Rule update failed: {e}")








