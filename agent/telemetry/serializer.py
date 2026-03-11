"""
Telemetry serializer: validate and prepare events for transport.
"""
from __future__ import annotations
from typing import Dict, Any
from datetime import datetime
try:
    from agent.schemas import TelemetryEvent
except Exception:
    try:
        from schemas import TelemetryEvent  # type: ignore
    except Exception:
        import importlib, importlib.util, os, sys
        base = os.path.dirname(os.path.abspath(__file__))
        cand = os.path.join(os.path.dirname(base), "schemas.py")
        if cand not in sys.modules and os.path.isfile(cand):
            spec = importlib.util.spec_from_file_location("schemas", cand)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["schemas"] = mod
                spec.loader.exec_module(mod)  # type: ignore
                TelemetryEvent = getattr(mod, "TelemetryEvent")  # type: ignore
        else:
            from agent.schemas import TelemetryEvent  # type: ignore


def serialize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    # Validate and fill defaults via Pydantic
    evt = TelemetryEvent(**raw)
    data = evt.dict()
    if not data.get("timestamp"):
        data["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return data

