"""
Agent bootstrap wiring existing capture with modular transport & serializer.
"""
from __future__ import annotations
from agent.config import load_config
from agent.transport.http import HttpTransport
from agent.telemetry.serializer import serialize_event


def build_transport(log):
    cfg = load_config()
    return HttpTransport(cfg.cloud_url, token=cfg.auth_token, verify_tls=cfg.verify_tls, log=log)


def serialize_batch(events):
    return [serialize_event(e) for e in events]








