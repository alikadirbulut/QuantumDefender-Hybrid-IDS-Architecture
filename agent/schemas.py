"""
Pydantic schemas for agent telemetry and signatures.
"""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class TelemetryEvent(BaseModel):
    agent_id: str
    hostname: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    url: Optional[str] = None
    port_dst: Optional[int] = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    alert: Optional[bool] = False
    reason: Optional[str] = None
    timestamp: Optional[str] = None
    features: Optional[dict] = Field(default=None, description="Feature vector for ML models")


class SignatureRule(BaseModel):
    id: Optional[str] = None
    type: str
    pattern: str
    severity: str = "low"
    source: str = "manual"


