import time, random, threading
from datetime import datetime
from PySide6 import QtCore
# Support both package and standalone execution
try:
    from .utils import find_process_for_socket, extract_url
except Exception:
    from utils import find_process_for_socket, extract_url  # type: ignore
try:
    from .telemetry import TelemetrySender
except Exception:
    from telemetry import TelemetrySender  # type: ignore
try:
    from agent.app import build_transport
    from agent.config import load_config
    from agent.signature_engine.engine import SignatureEngine
    from agent.rule_updater.updater import RuleUpdater
    from agent.traffic_monitor.windivert import WinDivertMonitor
except Exception:
    import importlib.util, os, sys
    ROOT = os.path.dirname(os.path.abspath(__file__))
    def _load_local(modname, filename):
        path = os.path.join(ROOT, filename)
        spec = importlib.util.spec_from_file_location(modname, path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules[modname] = module
            spec.loader.exec_module(module)
            return module
        raise ImportError(modname)
    build_transport = _load_local("app_local", "app.py").build_transport  # type: ignore
    load_config = _load_local("config_local", "config.py").load_config  # type: ignore
    SignatureEngine = _load_local("signature_engine_local", os.path.join("agent","signature_engine","engine.py")).SignatureEngine  # type: ignore
    RuleUpdater = _load_local("rule_updater_local", os.path.join("agent","rule_updater","updater.py")).RuleUpdater  # type: ignore
    WinDivertMonitor = _load_local("windivert_local", os.path.join("agent","traffic_monitor","windivert.py")).WinDivertMonitor  # type: ignore

class CaptureThread(QtCore.QThread):
    log = QtCore.Signal(str)
    alert = QtCore.Signal(dict)
    status = QtCore.Signal(bool)
    metrics = QtCore.Signal(int, int, float)

    def __init__(self, device_info, config):
        super().__init__()
        self.running = False
        self.packet_count = 0
        self.alert_count = 0
        cfg = load_config()
        transport = build_transport(self.log.emit)
        self.sender = TelemetrySender(transport, batch_size=cfg.batch_size, interval=cfg.send_interval, log_func=self.log.emit)
        self.device_info = device_info
        self.config = config
        self.signature_engine = SignatureEngine()
        self.rule_updater = RuleUpdater(
            cfg.signature_url or "",
            cfg.auth_token,
            self.signature_engine.hot_reload,
            log=self.log.emit
        )
        self.monitor = WinDivertMonitor(cfg.filter, log=self.log.emit, on_packet=self._collect_packet)

    def run(self):
        self.running = True
        self.status.emit(True)
        # One-off rule fetch
        threading.Thread(target=self.rule_updater.fetch_and_update, daemon=True).start()
        start = time.time()
        self.monitor.start()
        while self.running:
            elapsed = time.time() - start
            if elapsed >= 1:
                pps = self.packet_count / elapsed if elapsed else 0
                self.metrics.emit(self.packet_count, self.alert_count, pps)
                start = time.time()
            time.sleep(0.1)
        self.monitor.stop()
        self.sender.flush()
        self.status.emit(False)
        self.log.emit("🛑 Capture stopped.")

    def _collect_packet(self, pkt):
        try:
            proto = getattr(pkt, "protocol", "unknown")
            src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
            payload = (pkt.payload or b"").decode(errors="ignore")
            src_port, dst_port = getattr(pkt, "src_port", None), getattr(pkt, "dst_port", None)
            payload_len = len(payload)
            category = self._categorize(proto, dst_port, payload)
            event = {
                **self.device_info,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": str(proto),
                "port_src": src_port,
                "port_dst": dst_port,
                "bytes_sent": payload_len,
                "bytes_recv": 0,
                "category": category,
                "detection_source": "agent",
                # minimal flow-esque features to populate ML-friendly fields
                "Destination_Port": dst_port or 0,
                "Total_Fwd_Packets": 1,
                "Total_Length_of_Fwd_Packets": float(payload_len),
            }
            url = extract_url(payload)
            if url:
                event["url"] = url
            # Local signature match
            sig = self.signature_engine.match(event)
            if sig:
                event["alert"] = True
                event["reason"] = f"Local signature: {sig.pattern}"
                self.alert_count += 1
                self.alert.emit({"host": dst_ip, "reason": event["reason"], "timestamp": event["timestamp"]})
            self.sender.add_event(event)
        except Exception as e:
            self.log.emit(f"⚠️ Telemetry parse error: {e}")

    def stop(self):
        self.running = False
