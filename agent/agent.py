# ===============================================================
# QuantumDefender Agent v3.3 — Full Duplex + URL Telemetry Edition (UI Enhanced)
# ===============================================================
# pip install pydivert PySide6 qdarktheme winotify requests psutil

import sys, time, uuid, socket, platform, subprocess, threading, requests, psutil, random, json, re
from datetime import datetime
from PySide6 import QtCore, QtWidgets, QtGui
import pydivert
from winotify import Notification
from qdarktheme import load_stylesheet

# ---------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------
CLOUD_URL = "http://127.0.0.1:5000/analyze"
ENABLE_FIREWALL_BLOCK = False
BATCH_SIZE = 20
SEND_INTERVAL = 2

DEVICE_INFO = {
    "agent_id": str(uuid.uuid4())[:8],
    "hostname": socket.gethostname(),
    "ip": socket.gethostbyname(socket.gethostname()),
    "os": f"{platform.system()} {platform.release()}",
}

# ---------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------
def block_ip(ip):
    if not ENABLE_FIREWALL_BLOCK:
        return
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name=QuantumDefender_Block_{ip}",
        "dir=out", "action=block", f"remoteip={ip}"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def find_process_for_socket(local_ip, local_port):
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.laddr:
                continue
            if (c.laddr.ip, c.laddr.port) == (local_ip, local_port):
                if c.pid:
                    p = psutil.Process(c.pid)
                    return {"pid": c.pid, "name": p.name(), "exe": p.exe(), "user": p.username()}
    except Exception:
        pass
    return {}

def extract_url(payload: str):
    try:
        urls = re.findall(r"(https?://[^\s\"']+|Host:\s?[^\r\n]+)", payload, flags=re.IGNORECASE)
        urls = [u.replace("Host:", "").strip() for u in urls]
        if urls:
            return urls[0][:150]
    except Exception:
        pass
    return None

def readable_bytes(num):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"

# ---------------------------------------------------------------
# CAPTURE THREAD
# ---------------------------------------------------------------
class CaptureThread(QtCore.QThread):
    log = QtCore.Signal(str)
    alert = QtCore.Signal(dict)
    status = QtCore.Signal(bool)
    metrics = QtCore.Signal(int, int, float)

    def __init__(self):
        super().__init__()
        self.running = False
        self.packet_count = 0
        self.alert_count = 0
        self.buffer = []
        self.last_send = time.time()

    def run(self):
        self.running = True
        self.status.emit(True)
        filter_expr = "inbound or outbound and ip"
        self.log.emit(f"🟢 Filter: {filter_expr}")
        try:
            with pydivert.WinDivert(filter_expr, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.SNIFF) as w:
                self.log.emit("✅ Capture active — monitoring inbound & outbound traffic.")
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
                    if len(self.buffer) >= BATCH_SIZE or (time.time() - self.last_send > SEND_INTERVAL):
                        self._flush()
        except Exception as e:
            self.log.emit(f"❌ Capture error: {e}")
        finally:
            self._flush()
            self.status.emit(False)
            self.log.emit("🛑 Capture stopped.")

    def _collect(self, pkt):
        try:
            proto = getattr(pkt, "protocol", "unknown")
            src_ip, dst_ip = pkt.src_addr, pkt.dst_addr
            src_port, dst_port = pkt.src_port, pkt.dst_port
            payload = (pkt.payload or b"").decode(errors="ignore")
            payload_len = len(payload)
            process = find_process_for_socket(src_ip, src_port)
            region = random.choice(["US", "DE", "JP", "FR", "IN", "CN"])
            category = self._categorize(proto, dst_port, payload)
            url = extract_url(payload)
            event = {
                **DEVICE_INFO,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": str(proto),
                "port_src": src_port,
                "port_dst": dst_port,
                "bytes_sent": payload_len,
                "region": region,
                "category": category,
                "url": url or "N/A",
                "process": process,
            }
            if random.random() > 0.9:
                event["alert"] = True
                event["reason"] = f"Suspicious {category}"
                self.alert_count += 1
                self.alert.emit({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "host": dst_ip,
                    "reason": event["reason"]
                })
            else:
                event["alert"] = False
                event["reason"] = "benign"
            self.buffer.append(event)
        except Exception as e:
            self.log.emit(f"⚠️ Telemetry parse error: {e}")

    def _categorize(self, proto, port, payload):
        proto = str(proto).upper()
        if port == 80 or "HTTP" in payload:
            return "HTTP"
        if port == 443:
            return "HTTPS"
        if port == 22:
            return "SSH"
        if port == 25:
            return "SMTP"
        if port == 21:
            return "FTP"
        if port == 53:
            return "DNS"
        if "login" in payload.lower() or "password" in payload.lower():
            return "Credential Transfer"
        return proto or "Misc"

    def _flush(self):
        if not self.buffer:
            return
        batch = self.buffer[:]
        self.buffer.clear()
        self.last_send = time.time()
        threading.Thread(target=self._send_batch, args=(batch,), daemon=True).start()

    def _send_batch(self, batch):
        try:
            r = requests.post(CLOUD_URL, json=batch, timeout=5)
            if r.ok:
                self.log.emit(f"📤 Sent {len(batch)} events to cloud.")
            else:
                self.log.emit(f"⚠️ Cloud error {r.status_code}")
        except Exception as e:
            self.log.emit(f"⚠️ Send failed: {e}")

    def stop(self):
        self.running = False

# ---------------------------------------------------------------
# MAIN UI
# ---------------------------------------------------------------
class AgentUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumDefender Agent v3.3 — Enhanced UI")
        self.resize(1080, 640)
        self.setWindowIcon(QtGui.QIcon.fromTheme("security-high"))

        main = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(main)
        self.setCentralWidget(main)

        # HEADER
        header = QtWidgets.QLabel(
            f"<b>🔒 {DEVICE_INFO['hostname']}</b> | {DEVICE_INFO['ip']} | {DEVICE_INFO['os']}"
        )
        header.setStyleSheet("font-size:17px;color:#00ffc8;font-weight:bold;")
        layout.addWidget(header)

        # STATUS BAR
        self.status_lbl = QtWidgets.QLabel("Status: Disconnected ❌")
        self.status_lbl.setStyleSheet("color:#ff5555;font-weight:bold;")
        self.cloud_lbl = QtWidgets.QLabel("Cloud: Unknown")
        self.cloud_lbl.setStyleSheet("color:orange;font-weight:bold;")
        status_bar = QtWidgets.QHBoxLayout()
        status_bar.addWidget(self.status_lbl)
        status_bar.addStretch()
        status_bar.addWidget(self.cloud_lbl)
        layout.addLayout(status_bar)

        # METRICS PANEL
        self.metric_lbl = QtWidgets.QLabel("Packets: 0 | Alerts: 0 | PPS: 0.0 | CPU: 0% | MEM: 0%")
        self.metric_lbl.setStyleSheet("color:#00ffb7;font-size:14px;")
        layout.addWidget(self.metric_lbl)

        # SPLITTER
        splitter = QtWidgets.QSplitter()
        layout.addWidget(splitter, 1)

        # LOG PANEL
        self.log_box = QtWidgets.QTextEdit(readOnly=True)
        self.log_box.setStyleSheet("background:#101010;color:#00ffb7;font-family:Consolas;")
        self.log_box.setPlaceholderText("Logs will appear here...")
        splitter.addWidget(self.log_box)

        # TABS PANEL
        right_tabs = QtWidgets.QTabWidget()
        right_tabs.setStyleSheet("QTabBar::tab { height:28px; width:120px; }")
        splitter.addWidget(right_tabs)

        # ALERT TAB
        self.alert_list = QtWidgets.QListWidget()
        self.alert_list.setStyleSheet(
            "QListWidget{background:#141414;color:white;} QListWidget::item:selected{background:#ff0040;}"
        )
        right_tabs.addTab(self.alert_list, "⚠ Alerts")

        # SYSTEM TAB
        self.sysinfo_lbl = QtWidgets.QLabel()
        self.sysinfo_lbl.setStyleSheet("color:#00ffc8;font-size:13px;")
        right_tabs.addTab(self.sysinfo_lbl, "🧠 System Info")

        # CONTROLS
        controls = QtWidgets.QHBoxLayout()
        self.btn_start = QtWidgets.QPushButton("▶ Start Capture")
        self.btn_stop = QtWidgets.QPushButton("⏹ Stop")
        self.btn_stop.setEnabled(False)
        controls.addWidget(self.btn_start)
        controls.addWidget(self.btn_stop)
        layout.addLayout(controls)

        # TRAY ICON
        self.tray = QtWidgets.QSystemTrayIcon(QtGui.QIcon.fromTheme("security-high"), self)
        menu = QtWidgets.QMenu()
        menu.addAction("Show", self.showNormal)
        menu.addAction("Start Capture", self.start_capture)
        menu.addAction("Stop Capture", self.stop_capture)
        menu.addSeparator()
        menu.addAction("Exit", QtWidgets.QApplication.quit)
        self.tray.setContextMenu(menu)
        self.tray.show()

        # CAPTURE THREAD
        self.capture = CaptureThread()
        self.capture.log.connect(self.add_log)
        self.capture.alert.connect(self.show_alert)
        self.capture.status.connect(self.set_status)
        self.capture.metrics.connect(self.update_metrics)

        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.stop_capture)

        threading.Thread(target=self._check_cloud, daemon=True).start()

    # ------------------ BACKGROUND TASKS ------------------ #
    def _check_cloud(self):
        while True:
            try:
                t0 = time.time()
                requests.get(CLOUD_URL.replace("/analyze", "/"), timeout=3)
                latency = (time.time() - t0) * 1000
                self.cloud_lbl.setText(f"☁ Cloud reachable ({latency:.1f} ms)")
                self.cloud_lbl.setStyleSheet("color:cyan;font-weight:bold;")
            except Exception:
                self.cloud_lbl.setText("☁ Cloud unreachable ❌")
                self.cloud_lbl.setStyleSheet("color:orange;font-weight:bold;")
            time.sleep(10)

    # ------------------ UI CALLBACKS ------------------ #
    def add_log(self, text):
        self.log_box.append(text)
        self.log_box.moveCursor(QtGui.QTextCursor.End)

    def show_alert(self, a):
        msg = f"[{a['time']}] 🚨 {a['host']} — {a['reason']}"
        self.alert_list.insertItem(0, msg)
        self.tray.showMessage("QuantumDefender Alert", msg, QtWidgets.QSystemTrayIcon.MessageIcon.Warning)

    def set_status(self, ok):
        if ok:
            self.status_lbl.setText("Status: Connected ✅")
            self.status_lbl.setStyleSheet("color:lime;font-weight:bold;")
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
        else:
            self.status_lbl.setText("Status: Disconnected ❌")
            self.status_lbl.setStyleSheet("color:#ff5555;font-weight:bold;")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)

    def update_metrics(self, pkts, alerts, pps):
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        self.metric_lbl.setText(
            f"Packets: {pkts:,} | Alerts: {alerts:,} | PPS: {pps:.1f} | CPU: {cpu:.0f}% | MEM: {mem:.0f}%"
        )
        self.sysinfo_lbl.setText(
            f"<b>CPU:</b> {cpu:.1f}%<br><b>Memory:</b> {mem:.1f}%<br>"
            f"<b>Agent ID:</b> {DEVICE_INFO['agent_id']}<br><b>Hostname:</b> {DEVICE_INFO['hostname']}"
        )

    def start_capture(self):
        self.add_log("🔗 Starting capture...")
        self.capture.start()

    def stop_capture(self):
        self.add_log("🛑 Stopping capture...")
        self.capture.stop()

# ---------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(load_stylesheet(theme="dark"))
    win = AgentUI()
    win.show()
    sys.exit(app.exec())
