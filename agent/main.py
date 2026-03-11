import sys, socket, uuid, platform, psutil, threading, requests, time
from datetime import datetime
from PySide6 import QtCore, QtWidgets, QtGui
from qdarktheme import load_stylesheet
from .capture import CaptureThread
import importlib
def load_config():
    for modpath in ("agent.config", "config"):
        try:
            return importlib.import_module(modpath).load_config  # type: ignore
        except Exception:
            continue
    raise ImportError("load_config not found")


CONFIG = load_config()

DEVICE_INFO = {
    "agent_id": str(uuid.uuid4())[:8],
    "hostname": socket.gethostname(),
    "ip": socket.gethostbyname(socket.gethostname()),
    "os": f"{platform.system()} {platform.release()}",
}

class AgentUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumDefender Agent v3.4 (Modular)")
        self.resize(1280, 760)

        main = QtWidgets.QWidget()
        outer = QtWidgets.QHBoxLayout(main)
        self.setCentralWidget(main)

        # Sidebar: device + status + metrics
        sidebar = QtWidgets.QVBoxLayout()
        sidebar.setSpacing(12)
        card = self._make_card("Agent Identity", [
            ("Agent ID", DEVICE_INFO["agent_id"]),
            ("Hostname", DEVICE_INFO["hostname"]),
            ("IP", DEVICE_INFO["ip"]),
            ("OS", DEVICE_INFO["os"]),
        ])
        sidebar.addWidget(card)
        sidebar.addWidget(self._make_status_card())
        sidebar.addWidget(self._make_metrics_card())
        sidebar.addStretch()

        # Main area: header metrics + controls + tabs
        right = QtWidgets.QVBoxLayout()
        header = QtWidgets.QHBoxLayout()
        self.metric_packets = self._metric_chip("Packets", "0")
        self.metric_alerts = self._metric_chip("Alerts", "0", accent="#ff6b6b")
        self.metric_pps = self._metric_chip("PPS", "0.0")
        self.metric_cloud = self._metric_chip("Cloud", "Unknown", accent="#66d9ff")
        for m in (self.metric_packets, self.metric_alerts, self.metric_pps, self.metric_cloud):
            header.addWidget(m)
        header.addStretch()
        right.addLayout(header)

        control_bar = QtWidgets.QHBoxLayout()
        self.btn_start = QtWidgets.QPushButton("▶ Start Capture")
        self.btn_stop = QtWidgets.QPushButton("⏹ Stop")
        self.btn_stop.setEnabled(False)
        control_bar.addWidget(self.btn_start)
        control_bar.addWidget(self.btn_stop)
        control_bar.addStretch()
        right.addLayout(control_bar)

        self.tabs = QtWidgets.QTabWidget()

        live_tab = QtWidgets.QWidget()
        live_layout = QtWidgets.QVBoxLayout(live_tab)
        self.feed_table = QtWidgets.QTableWidget(0, 4)
        self.feed_table.setHorizontalHeaderLabels(["Time", "Host", "URL / Reason", "Status"])
        self.feed_table.horizontalHeader().setStretchLastSection(True)
        self.feed_table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        self.feed_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.feed_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.feed_table.setAlternatingRowColors(True)
        live_layout.addWidget(self.feed_table)
        self.tabs.addTab(live_tab, "Live Feed")

        settings_tab = QtWidgets.QWidget()
        form = QtWidgets.QFormLayout(settings_tab)
        self.input_cloud = QtWidgets.QLineEdit(CONFIG.cloud_url)
        self.input_filter = QtWidgets.QLineEdit(CONFIG.filter)
        self.spin_batch = QtWidgets.QSpinBox()
        self.spin_batch.setRange(1, 1000)
        self.spin_batch.setValue(CONFIG.batch_size)
        self.spin_interval = QtWidgets.QDoubleSpinBox()
        self.spin_interval.setRange(0.1, 120.0)
        self.spin_interval.setSingleStep(0.5)
        self.spin_interval.setValue(CONFIG.send_interval)
        save_btn = QtWidgets.QPushButton("Save (session)")
        save_btn.clicked.connect(self._apply_settings)
        form.addRow("Cloud URL", self.input_cloud)
        form.addRow("Capture Filter", self.input_filter)
        form.addRow("Batch Size", self.spin_batch)
        form.addRow("Send Interval (s)", self.spin_interval)
        form.addRow("", save_btn)
        self.tabs.addTab(settings_tab, "Settings")

        right.addWidget(self.tabs)
        outer.addLayout(sidebar, 1)
        outer.addLayout(right, 3)

        self.capture = CaptureThread(DEVICE_INFO, CONFIG)
        self.capture.log.connect(self.add_log)
        self.capture.status.connect(self.set_status)
        self.capture.metrics.connect(self.update_metrics)
        self.capture.alert.connect(self.on_local_alert)

        self.btn_start.clicked.connect(self.start_capture)
        self.btn_stop.clicked.connect(self.stop_capture)

        self._set_status_chip(False)
        self.add_log("Agent initialized. Ready to capture.")
        self._last_cloud_ok = None
        self.cloud_timer = QtCore.QTimer(self)
        self.cloud_timer.timeout.connect(self._ping_cloud)
        self.cloud_timer.start(10000)
        self.tray = QtWidgets.QSystemTrayIcon(QtGui.QIcon(), self)
        self.tray.show()

    # --- UI helpers ---
    def _make_card(self, title, rows):
        box = QtWidgets.QGroupBox(title)
        layout = QtWidgets.QFormLayout(box)
        for label, value in rows:
            layout.addRow(QtWidgets.QLabel(label), QtWidgets.QLabel(str(value)))
        return box

    def _make_status_card(self):
        box = QtWidgets.QGroupBox("Capture Status")
        v = QtWidgets.QVBoxLayout(box)
        self.status_chip = QtWidgets.QLabel()
        self.status_chip.setAlignment(QtCore.Qt.AlignCenter)
        self.status_chip.setMinimumHeight(32)
        self.status_msg = QtWidgets.QLabel("Disconnected")
        self.status_msg.setAlignment(QtCore.Qt.AlignCenter)
        v.addWidget(self.status_chip)
        v.addWidget(self.status_msg)
        return box

    def _make_metrics_card(self):
        box = QtWidgets.QGroupBox("Live Metrics")
        g = QtWidgets.QGridLayout(box)
        self.lbl_packets = QtWidgets.QLabel("0")
        self.lbl_alerts = QtWidgets.QLabel("0")
        self.lbl_pps = QtWidgets.QLabel("0.0")
        g.addWidget(QtWidgets.QLabel("Packets"), 0, 0)
        g.addWidget(self.lbl_packets, 0, 1)
        g.addWidget(QtWidgets.QLabel("Alerts"), 1, 0)
        g.addWidget(self.lbl_alerts, 1, 1)
        g.addWidget(QtWidgets.QLabel("Packets/s"), 2, 0)
        g.addWidget(self.lbl_pps, 2, 1)
        return box

    def _metric_chip(self, label, value, accent="#00e0b8"):
        w = QtWidgets.QFrame()
        w.setStyleSheet(f"QFrame {{ border: 1px solid {accent}; border-radius: 10px; padding: 8px; }}")
        v = QtWidgets.QVBoxLayout(w)
        title = QtWidgets.QLabel(label)
        title.setStyleSheet("color: #ccc; font-size: 12px;")
        val = QtWidgets.QLabel(value)
        val.setStyleSheet("color: #fff; font-weight: 700; font-size: 16px;")
        v.addWidget(title)
        v.addWidget(val)
        v.setContentsMargins(6, 4, 6, 4)
        w._value_lbl = val
        return w

    def _set_status_chip(self, ok):
        color = "#1f9d55" if ok else "#c53030"
        text = "Running" if ok else "Stopped"
        self.status_chip.setStyleSheet(f"background:{color}; color:white; border-radius:8px;")
        self.status_chip.setText(text)
        self.status_msg.setText("✅ Capture active" if ok else "❌ Disconnected")

    # --- Slots ---
    def add_log(self, msg):
        ts = datetime.utcnow().strftime("%H:%M:%S")
        row = self.feed_table.rowCount()
        self.feed_table.insertRow(row)
        self.feed_table.setItem(row, 0, QtWidgets.QTableWidgetItem(ts))
        self.feed_table.setItem(row, 1, QtWidgets.QTableWidgetItem("N/A"))
        self.feed_table.setItem(row, 2, QtWidgets.QTableWidgetItem(msg))
        self.feed_table.setItem(row, 3, QtWidgets.QTableWidgetItem("INFO"))
        self.feed_table.scrollToBottom()

    def set_status(self, ok):
        self._set_status_chip(ok)

    def update_metrics(self, packets, alerts, pps):
        self.lbl_packets.setText(str(packets))
        self.lbl_alerts.setText(str(alerts))
        self.lbl_pps.setText(f"{pps:.1f}")
        self.metric_packets._value_lbl.setText(f"{packets}")
        self.metric_alerts._value_lbl.setText(f"{alerts}")
        self.metric_pps._value_lbl.setText(f"{pps:.1f}")

    def start_capture(self):
        self.capture.start()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.add_log("Capture started.")

    def stop_capture(self):
        self.capture.stop()
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.add_log("Capture stopped.")

    def on_local_alert(self, alert):
        ts = alert.get("timestamp", datetime.utcnow().strftime("%H:%M:%S"))
        host = alert.get("host", "unknown")
        reason = alert.get("reason", "Alert")
        self._append_feed(ts, host, reason, "ALERT")
        if self.tray:
            self.tray.showMessage("Local Alert", f"{host}: {reason}", QtWidgets.QSystemTrayIcon.MessageIcon.Warning)

    def _append_feed(self, ts, host, msg, status):
        row = self.feed_table.rowCount()
        self.feed_table.insertRow(row)
        self.feed_table.setItem(row, 0, QtWidgets.QTableWidgetItem(ts))
        self.feed_table.setItem(row, 1, QtWidgets.QTableWidgetItem(host))
        self.feed_table.setItem(row, 2, QtWidgets.QTableWidgetItem(msg))
        status_item = QtWidgets.QTableWidgetItem(status)
        if status.lower() == "alert":
            status_item.setForeground(QtGui.QColor("#ff6b6b"))
        self.feed_table.setItem(row, 3, status_item)
        self.feed_table.scrollToBottom()

    def _apply_settings(self):
        CONFIG.cloud_url = self.input_cloud.text().strip() or CONFIG.cloud_url
        CONFIG.filter = self.input_filter.text().strip() or CONFIG.filter
        CONFIG.batch_size = int(self.spin_batch.value())
        CONFIG.send_interval = float(self.spin_interval.value())
        self.add_log("Session settings updated (restart capture to apply).")

    def _ping_cloud(self):
        url = CONFIG.cloud_url
        if url.endswith("/analyze"):
            url = url.replace("/analyze", "/health")
        try:
            r = requests.get(url, timeout=3)
            ok = r.ok
        except Exception:
            ok = False
        self.metric_cloud._value_lbl.setText("OK" if ok else "Down")
        if getattr(self, "_last_cloud_ok", None) is None:
            self._last_cloud_ok = ok
            return
        if ok != self._last_cloud_ok and self.tray:
            self.tray.showMessage("Cloud Status", "Cloud reachable" if ok else "Cloud unreachable",
                                  QtWidgets.QSystemTrayIcon.MessageIcon.Information)
        self._last_cloud_ok = ok

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(load_stylesheet(theme="dark"))
    win = AgentUI()
    win.show()
    sys.exit(app.exec())
