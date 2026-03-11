import time, random
from datetime import datetime
from PySide6 import QtCore
import pydivert
from .utils import find_process_for_socket, extract_url
from .telemetry import TelemetrySender

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
        self.sender = TelemetrySender(config.cloud_url, self.log.emit)
        self.device_info = device_info
        self.config = config

    def run(self):
        self.running = True
        self.status.emit(True)
        filter_expr = "(tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 443)"
        self.log.emit(f"🟢 Filter: {filter_expr}")
        try:
            with pydivert.WinDivert(filter_expr, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.SNIFF) as w:
                self.log.emit("✅ Capture active.")
                start = time.time()
                for pkt in w:
                    if not self.running:
                        break
                    self.packet_count += 1
                    self._collect(pkt)
                    if time.time() - start >= 1:
                        elapsed = time.time() - start
                        pps = self.packet_count / elapsed if elapsed else 0
                        self.metrics.emit(self.packet_count, self.alert_count, pps)
                        start = time.time()
        except Exception as e:
            self.log.emit(f"❌ Capture error: {e}")
        finally:
            self.sender.flush()
            self.status.emit(False)
            self.log.emit("🛑 Capture stopped.")

    def _collect(self, pkt):
        try:
            proto = getattr(pkt, "protocol", "unknown")
            src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
            src_port, dst_port = pkt.src_port, pkt.dst_port
            payload = (pkt.payload or b"").decode(errors="ignore")
            payload_len = len(payload)
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
                "category": self._categorize(proto, dst_port, payload),
                "detection_source": "agent",
                "Destination_Port": dst_port or 0,
                "Total_Fwd_Packets": 1,
                "Total_Length_of_Fwd_Packets": float(payload_len),
            }
            url = extract_url(payload)
            if url:
                event["url"] = url
            self.sender.add_event(event)
        except Exception as e:
            self.log.emit(f"⚠️ Telemetry parse error: {e}")

    def _categorize(self, proto, port, payload_text):
        p = str(proto).upper()
        if port in (80, 8080) or "http" in payload_text.lower():
            return "HTTP"
        if port == 443:
            return "HTTPS"
        if port == 53:
            return "DNS"
        if port == 22:
            return "SSH"
        if "login" in payload_text.lower() or "password" in payload_text.lower():
            return "Credential Transfer"
        return p or "Misc"

    def stop(self):
        self.running = False
