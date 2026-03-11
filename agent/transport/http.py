"""
HTTPS transport implementation with token auth.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import requests
from .base import Transport


class HttpTransport(Transport):
    def __init__(self, url: str, token: Optional[str] = None, verify_tls: bool = False, log=None):
        self.url = url
        self.token = token
        self.verify_tls = verify_tls
        self.log = log or (lambda x: None)

    def send_batch(self, events: List[Dict[str, Any]]) -> None:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.post(self.url, json=events, headers=headers, timeout=5, verify=self.verify_tls)
            if not r.ok:
                self.log(f"⚠️ Transport error {r.status_code}")
        except Exception as e:
            self.log(f"⚠️ Transport failed: {e}")


