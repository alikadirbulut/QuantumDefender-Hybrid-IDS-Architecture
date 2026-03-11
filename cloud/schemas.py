"""
Pydantic schemas for ingestion and signatures.
"""
from __future__ import annotations
from typing import Optional, List
from pydantic import BaseModel, Field, validator


class IngestEvent(BaseModel):
    agent_id: str
    host: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: Optional[str]
    url: Optional[str]
    port_dst: Optional[int]
    bytes_sent: int = 0
    bytes_recv: int = 0
    alert: Optional[bool] = False
    reason: Optional[str] = None
    timestamp: Optional[str]
    features: Optional[dict] = Field(default=None, description="Feature vector for ML models")


class IngestBatch(BaseModel):
    events: List[IngestEvent]

    @validator("events")
    def non_empty(cls, v):
        if not v:
            raise ValueError("events cannot be empty")
        return v


class SignatureRule(BaseModel):
    id: Optional[str] = None
    type: str
    pattern: str
    severity: str = "low"
    source: str = "manual"








