"""
Cloud configuration loader with env overrides.
"""
from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass
class CloudConfig:
    api_key: str | None
    model_path: str
    queue_backend: str = "memory"
    db_url: str = "sqlite:///cloud_store.db"
    signature_repo: str = "signatures.db"


def load_config() -> CloudConfig:
    return CloudConfig(
        api_key=os.getenv("QD_API_KEY"),
        model_path=os.getenv("QD_MODEL_PATH", "lite_model.onnx"),
        queue_backend=os.getenv("QD_QUEUE_BACKEND", "memory"),
        db_url=os.getenv("QD_DB_URL", "sqlite:///cloud_store.db"),
        signature_repo=os.getenv("QD_SIGNATURE_REPO", "signatures.db"),
    )








