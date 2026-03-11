"""
WinDivert-based traffic monitor implementing the TrafficMonitor interface.
"""
from __future__ import annotations
import pydivert
from PySide6 import QtCore
class WinDivertMonitor(QtCore.QThread):
    def __init__(self, flt: str, on_packet=None, log=None):
        super().__init__()
        self.filter = flt
        self.on_packet = on_packet
        self.log = log or (lambda x: None)
        self.running = False

    def set_callback(self, cb):
        self.on_packet = cb

    def run(self):
        self.running = True
        self.log(f"🟢 Filter: {self.filter}")
        try:
            with pydivert.WinDivert(self.filter, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.SNIFF) as w:
                self.log("✅ Capture active.")
                for pkt in w:
                    if not self.running:
                        break
                    if self.on_packet:
                        self.on_packet(pkt)
        except Exception as e:
            self.log(f"❌ Capture error: {e}")
        finally:
            self.log("🛑 Capture stopped.")

    def start(self):  # type: ignore[override]
        super().start()

    def stop(self):  # type: ignore[override]
        self.running = False

