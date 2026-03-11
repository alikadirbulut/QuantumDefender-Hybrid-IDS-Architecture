"""
Agent configuration loader with env overrides.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class AgentConfig:
    cloud_url: str
    batch_size: int = 20
    send_interval: int = 2
    filter: str = "tcp and (port 80 or port 443)"
    auth_token: Optional[str] = None
    verify_tls: bool = False
    signature_url: Optional[str] = None


def load_config(path: str = "config.json") -> AgentConfig:
    with open(path, "r") as f:
        raw = json.load(f)
    default_sig = raw.get("SIGNATURE_URL") or raw.get("CLOUD_URL", "").replace("analyze", "api/signatures")
    return AgentConfig(
        cloud_url=os.getenv("QD_CLOUD_URL", raw.get("CLOUD_URL", "")),
        batch_size=int(os.getenv("QD_BATCH_SIZE", raw.get("BATCH_SIZE", 20))),
        send_interval=int(os.getenv("QD_SEND_INTERVAL", raw.get("SEND_INTERVAL", 2))),
        filter=os.getenv("QD_FILTER", raw.get("FILTER", "tcp and (port 80 or port 443)")),
        auth_token=os.getenv("QD_AUTH_TOKEN"),
        verify_tls=os.getenv("QD_VERIFY_TLS", "false").lower() in ("1", "true", "yes"),
        signature_url=os.getenv("QD_SIGNATURE_URL", default_sig),
    )

