import importlib, importlib.util, os, sys
import threading, time
from typing import Callable, Dict, Any, Protocol


class Transport(Protocol):
    def send_batch(self, events):
        ...


def _load_serializer():
    # Try module imports first
    for modpath in ("agent.telemetry.serializer", "telemetry.serializer"):
        try:
            mod = importlib.import_module(modpath)
            fn = getattr(mod, "serialize_event", None)
            if fn:
                return fn
        except Exception:
            continue
    # Try direct file load (agent/telemetry/serializer.py)
    base = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(base, "agent", "telemetry", "serializer.py")
    if os.path.isfile(candidate):
        if base not in sys.path:
            sys.path.append(base)
        spec = importlib.util.spec_from_file_location("agent.telemetry.serializer", candidate)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["agent.telemetry.serializer"] = mod
            spec.loader.exec_module(mod)  # type: ignore
            fn = getattr(mod, "serialize_event", None)
            if fn:
                return fn
    raise ImportError("serialize_event not found")


serialize_event = _load_serializer()

class TelemetrySender:
    def __init__(self, transport: Transport, batch_size: int = 20, interval: int = 2, log_func=None):
        self.transport = transport
        self.batch_size = batch_size
        self.interval = interval
        self.log = log_func or (lambda x: None)
        self.buffer: list[Dict[str, Any]] = []
        self.last_send = time.time()

    def add_event(self, event: Dict[str, Any]):
        self.buffer.append(serialize_event(event))
        if len(self.buffer) >= self.batch_size or (time.time() - self.last_send > self.interval):
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        batch = self.buffer[:]
        self.buffer.clear()
        self.last_send = time.time()
        threading.Thread(target=self._send_batch, args=(batch,), daemon=True).start()

    def _send_batch(self, batch: list[Dict[str, Any]]):
        try:
            self.transport.send_batch(batch)
            self.log(f"📤 Sent {len(batch)} events to cloud.")
        except Exception as e:
            self.log(f"⚠️ Send failed: {e}")
