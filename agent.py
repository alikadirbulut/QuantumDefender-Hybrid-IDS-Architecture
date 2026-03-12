# ===============================================================
# QuantumDefender Agent v9.0 — UI Shell
# Non-UI logic lives in agent_core.py
# ===============================================================
import random
from datetime import datetime
import sys
import time
import threading
import requests
import psutil

from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QColor, QPalette, QLinearGradient, QBrush

import agent_core
from agent_core import (
    load_config, save_config, DEFAULT_CONFIG, DEVICE_INFO,
    BLOCKED_IPS, BLOCKED_DOMAINS, BLOCKED_CIDRS, FIREWALL_RULES_LOCK,
    FLOW_LOCK, CONNECTION_FLOWS,
    BlockPageHandler, DeviceManagementClient, CaptureThread,
    send_batch_to_cloud, block_ip, detect_threat,
    check_firewall_block, check_domain_block,
    signature_engine, SIGNATURE_ENGINE_AVAILABLE, SignatureRule,
    CLOUD_URL, ENABLE_FIREWALL_BLOCK, BATCH_SIZE, SEND_INTERVAL, FILTER_EXPR,
    CONFIG, get_connection_stats, is_admin, readable_bytes,
    start_block_page_server, load_stylesheet,
)

# ===============================================================
# MODERN UI STYLES
# ===============================================================
MODERN_STYLE = """
QMainWindow {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #0a0e1a, stop:0.5 #0f1624, stop:1 #0a0e1a);
}

QWidget {
    background: transparent;
    color: #e8f0ff;
    font-family: 'Segoe UI', 'Inter', sans-serif;
}

QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(0, 255, 224, 0.2), stop:1 rgba(124, 111, 255, 0.2));
    border: 1px solid rgba(0, 255, 224, 0.4);
    border-radius: 12px;
    padding: 10px 20px;
    font-weight: 600;
    font-size: 13px;
    color: #00ffe0;
    min-height: 36px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(0, 255, 224, 0.3), stop:1 rgba(124, 111, 255, 0.3));
    border-color: #00ffe0;
    box-shadow: 0 4px 20px rgba(0, 255, 224, 0.3);
}

QPushButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(0, 255, 224, 0.4), stop:1 rgba(124, 111, 255, 0.4));
}

QPushButton:disabled {
    background: rgba(255, 255, 255, 0.05);
    border-color: rgba(255, 255, 255, 0.1);
    color: rgba(255, 255, 255, 0.3);
}

QLineEdit, QSpinBox, QDoubleSpinBox {
    background: rgba(15, 22, 36, 0.7);
    border: 1px solid rgba(0, 255, 224, 0.2);
    border-radius: 8px;
    padding: 8px 12px;
    color: #e8f0ff;
    font-size: 13px;
}

QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #00ffe0;
    background: rgba(15, 22, 36, 0.9);
}

QTextEdit {
    background: rgba(10, 14, 22, 0.8);
    border: 1px solid rgba(0, 255, 224, 0.2);
    border-radius: 12px;
    padding: 12px;
    color: #00ffb7;
    font-family: 'Consolas', 'JetBrains Mono', monospace;
    font-size: 12px;
}

QListWidget {
    background: rgba(10, 14, 22, 0.6);
    border: 1px solid rgba(0, 255, 224, 0.2);
    border-radius: 12px;
    padding: 8px;
    color: #e8f0ff;
    font-size: 12px;
}

QListWidget::item {
    padding: 8px;
    border-radius: 6px;
    margin: 2px;
}

QListWidget::item:selected {
    background: rgba(255, 92, 138, 0.3);
    border-left: 3px solid #ff5c8a;
}

QListWidget::item:hover {
    background: rgba(0, 255, 224, 0.1);
}

QTabWidget::pane {
    background: rgba(15, 22, 36, 0.7);
    border: 1px solid rgba(0, 255, 224, 0.2);
    border-radius: 12px;
    padding: 8px;
}

QTabBar::tab {
    background: rgba(15, 22, 36, 0.5);
    border: 1px solid rgba(0, 255, 224, 0.2);
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    padding: 10px 20px;
    margin-right: 4px;
    color: #9fb3c8;
    font-weight: 500;
}

QTabBar::tab:selected {
    background: rgba(0, 255, 224, 0.15);
    border-color: #00ffe0;
    color: #00ffe0;
}

QTabBar::tab:hover {
    background: rgba(0, 255, 224, 0.1);
    color: #00ffe0;
}

QCheckBox {
    color: #e8f0ff;
    font-size: 13px;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border: 2px solid rgba(0, 255, 224, 0.4);
    border-radius: 4px;
    background: rgba(15, 22, 36, 0.7);
}

QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #00ffe0, stop:1 #7c6fff);
    border-color: #00ffe0;
}

QLabel {
    color: #e8f0ff;
    font-size: 13px;
}

QLabel[status="success"] {
    color: #00e676;
    font-weight: 700;
}

QLabel[status="error"] {
    color: #ff5252;
    font-weight: 700;
}

QLabel[status="warning"] {
    color: #ffd54f;
    font-weight: 700;
}

QScrollBar:vertical {
    background: rgba(15, 22, 36, 0.5);
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: rgba(0, 255, 224, 0.3);
    border-radius: 5px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background: rgba(0, 255, 224, 0.5);
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
"""

# ===============================================================
# MODERN AGENT UI
# ===============================================================
class ModernMetricCard(QtWidgets.QFrame):
    def __init__(self, title, value="0", parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(0, 255, 224, 0.1), stop:1 rgba(124, 111, 255, 0.1));
                border: 1px solid rgba(0, 255, 224, 0.3);
                border-radius: 16px;
                padding: 16px;
            }
        """)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(8)

        self.title_label = QtWidgets.QLabel(title)
        self.title_label.setStyleSheet("""
            color: #9fb3c8;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        """)

        self.value_label = QtWidgets.QLabel(value)
        self.value_label.setStyleSheet("""
            color: #00ffe0;
            font-size: 28px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        """)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addStretch()

class AgentUI(QtWidgets.QMainWindow):
    cloud_status_signal = QtCore.Signal(bool, float)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuantumDefender Agent v9.0 — Advanced Windows Control")
        self.resize(1400, 900)
        self.setMinimumSize(1200, 700)

        # Apply modern style
        self.setStyleSheet(MODERN_STYLE)

        # Central widget
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Header
        header = self._create_header()
        main_layout.addWidget(header)

        # Metrics bar
        metrics_bar = self._create_metrics_bar()
        main_layout.addWidget(metrics_bar)

        # Main content area
        content_splitter = QtWidgets.QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(content_splitter, 1)

        # Left: Logs
        log_widget = self._create_log_widget()
        content_splitter.addWidget(log_widget)
        content_splitter.setStretchFactor(0, 2)

        # Right: Tabs
        tabs_widget = self._create_tabs_widget()
        content_splitter.addWidget(tabs_widget)
        content_splitter.setStretchFactor(1, 1)

        # Controls
        controls = self._create_controls()
        main_layout.addLayout(controls)

        # Initialize capture thread
        self.capture = CaptureThread()
        self.capture.log.connect(self.add_log)
        self.capture.alert.connect(self.show_alert)
        self.capture.status.connect(self.set_status)
        self.capture.metrics.connect(self.update_metrics)

        # Initialize device management client
        self.device_mgmt = DeviceManagementClient(
            CLOUD_URL,
            DEVICE_INFO['agent_id'],
            log_callback=self.add_log,
            alert_callback=self.show_alert
        )
        self.device_mgmt.restart_callback = self.start_capture
        # Connect device management
        threading.Thread(target=self.device_mgmt.connect, daemon=True).start()

        # Load initial signatures from cloud
        if signature_engine:
            threading.Thread(target=self._load_initial_signatures, daemon=True).start()

        # Timers
        self.metrics_timer = QtCore.QTimer()
        self.metrics_timer.timeout.connect(self.refresh_metrics)
        self.metrics_timer.start(2000)

        # Connection refresh timer
        self.connection_timer = QtCore.QTimer()
        self.connection_timer.timeout.connect(self.refresh_connections)
        self.connection_timer.start(5000)  # Every 5 seconds

        # Cloud status check
        self.cloud_status_signal.connect(self._on_cloud_status)
        threading.Thread(target=self._cloud_check_loop, daemon=True).start()

        # System tray
        self._setup_tray()

        # Initial messages
        if not is_admin():
            self.add_log("⚠️ Not running as Administrator. Packet capture may fail.")
        self.add_log("ℹ️ Agent initialized. Ready to capture.")
        self.add_log(f"ℹ️ Cloud endpoint: {CLOUD_URL}")

        # Shutdown handler
        QtWidgets.QApplication.instance().aboutToQuit.connect(self._shutdown)

    def _create_header(self):
        header = QtWidgets.QFrame()
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(0, 255, 224, 0.1), stop:1 rgba(124, 111, 255, 0.1));
                border: 1px solid rgba(0, 255, 224, 0.3);
                border-radius: 16px;
                padding: 16px 24px;
            }
        """)

        layout = QtWidgets.QHBoxLayout(header)

        title = QtWidgets.QLabel(f"🔒 {DEVICE_INFO['hostname']}")
        title.setStyleSheet("""
            font-size: 24px;
            font-weight: 700;
            color: #00ffe0;
            background: transparent;
        """)

        info = QtWidgets.QLabel(f"{DEVICE_INFO['ip']} • {DEVICE_INFO['os']} • {DEVICE_INFO['region']}")
        info.setStyleSheet("""
            font-size: 13px;
            color: #9fb3c8;
            background: transparent;
        """)

        layout.addWidget(title)
        layout.addWidget(info)
        layout.addStretch()

        self.status_label = QtWidgets.QLabel("Status: Disconnected")
        self.status_label.setProperty("status", "error")
        self.status_label.setStyleSheet("font-size: 14px; font-weight: 700;")

        self.cloud_label = QtWidgets.QLabel("Cloud: Checking...")
        self.cloud_label.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffd54f;")

        layout.addWidget(self.status_label)
        layout.addSpacing(20)
        layout.addWidget(self.cloud_label)

        return header

    def _create_metrics_bar(self):
        bar = QtWidgets.QFrame()
        bar.setStyleSheet("background: transparent;")
        layout = QtWidgets.QHBoxLayout(bar)
        layout.setSpacing(16)

        self.metric_packets = ModernMetricCard("Packets", "0")
        self.metric_alerts = ModernMetricCard("Alerts", "0")
        self.metric_pps = ModernMetricCard("PPS", "0.0")
        self.metric_connections = ModernMetricCard("Connections", "0")
        self.metric_blocked = ModernMetricCard("Blocked IPs", "0")
        self.metric_signatures = ModernMetricCard("Signatures", "0")
        self.metric_cpu = ModernMetricCard("CPU", "0%")
        self.metric_mem = ModernMetricCard("Memory", "0%")

        self.metric_alerts.value_label.setStyleSheet("""
            color: #ff5252;
            font-size: 28px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        """)

        self.metric_blocked.value_label.setStyleSheet("""
            color: #ffd54f;
            font-size: 28px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        """)

        self.metric_signatures.value_label.setStyleSheet("""
            color: #00ffe0;
            font-size: 28px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        """)

        layout.addWidget(self.metric_packets)
        layout.addWidget(self.metric_alerts)
        layout.addWidget(self.metric_pps)
        layout.addWidget(self.metric_connections)
        layout.addWidget(self.metric_blocked)
        layout.addWidget(self.metric_signatures)
        layout.addWidget(self.metric_cpu)
        layout.addWidget(self.metric_mem)
        layout.addStretch()

        return bar

    def _create_log_widget(self):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        label = QtWidgets.QLabel("📋 Activity Log")
        label.setStyleSheet("font-size: 16px; font-weight: 700; color: #00ffe0; padding: 8px;")
        layout.addWidget(label)

        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("Logs will appear here...")
        layout.addWidget(self.log_box)

        return widget

    def _create_tabs_widget(self):
        self.tabs = QtWidgets.QTabWidget()

        # Alerts tab
        alerts_widget = QtWidgets.QWidget()
        alerts_layout = QtWidgets.QVBoxLayout(alerts_widget)
        alerts_layout.setContentsMargins(8, 8, 8, 8)
        self.alert_list = QtWidgets.QListWidget()
        alerts_layout.addWidget(self.alert_list)
        self.tabs.addTab(alerts_widget, "⚠ Alerts")

        # System Info tab
        sysinfo_widget = QtWidgets.QWidget()
        sysinfo_layout = QtWidgets.QVBoxLayout(sysinfo_widget)
        sysinfo_layout.setContentsMargins(16, 16, 16, 16)
        self.sysinfo_label = QtWidgets.QLabel()
        self.sysinfo_label.setStyleSheet("""
            color: #00ffc8;
            font-size: 13px;
            line-height: 1.8;
        """)
        self.sysinfo_label.setWordWrap(True)
        sysinfo_layout.addWidget(self.sysinfo_label)

        # Connection list
        conn_label = QtWidgets.QLabel("🔗 Active Connections")
        conn_label.setStyleSheet("font-size: 14px; font-weight: 700; color: #00ffe0; margin-top: 16px;")
        sysinfo_layout.addWidget(conn_label)

        self.connection_list = QtWidgets.QListWidget()
        self.connection_list.setStyleSheet("""
            QListWidget {
                background: rgba(10, 14, 22, 0.6);
                border: 1px solid rgba(0, 255, 224, 0.2);
                border-radius: 8px;
                padding: 4px;
                font-size: 11px;
                font-family: 'Consolas', monospace;
            }
            QListWidget::item {
                padding: 4px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }
        """)
        sysinfo_layout.addWidget(self.connection_list)

        sysinfo_layout.addStretch()
        self.tabs.addTab(sysinfo_widget, "🧠 System Info")

    # Settings tab
        settings_widget = self._create_settings_tab()
        self.tabs.addTab(settings_widget, "⚙ Settings")

        return self.tabs

    def _create_settings_tab(self):
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QFormLayout(widget)
        layout.setSpacing(16)
        layout.setContentsMargins(16, 16, 16, 16)

        self.input_cloud = QtWidgets.QLineEdit(CLOUD_URL)
        self.input_filter = QtWidgets.QLineEdit(FILTER_EXPR)
        self.spin_batch = QtWidgets.QSpinBox()
        self.spin_batch.setRange(1, 1000)
        self.spin_batch.setValue(BATCH_SIZE)
        self.spin_interval = QtWidgets.QDoubleSpinBox()
        self.spin_interval.setRange(0.1, 120.0)
        self.spin_interval.setSingleStep(0.5)
        self.spin_interval.setValue(SEND_INTERVAL)
        self.chk_firewall = QtWidgets.QCheckBox("Enable Firewall Blocking")
        self.chk_firewall.setChecked(ENABLE_FIREWALL_BLOCK)

        btn_apply = QtWidgets.QPushButton("💾 Apply & Save")
        btn_apply.clicked.connect(self._apply_and_save_config)

        layout.addRow("Cloud URL:", self.input_cloud)
        layout.addRow("Filter:", self.input_filter)
        layout.addRow("Batch Size:", self.spin_batch)
        layout.addRow("Send Interval (s):", self.spin_interval)
        layout.addRow("", self.chk_firewall)
        layout.addRow("", btn_apply)

        return widget

    def _create_controls(self):
        layout = QtWidgets.QHBoxLayout()
        layout.setSpacing(12)

        self.btn_start = QtWidgets.QPushButton("▶ Start Capture")
        self.btn_start.clicked.connect(self.start_capture)

        self.btn_stop = QtWidgets.QPushButton("⏹ Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_capture)

        self.btn_simulate = QtWidgets.QPushButton("⚠ Simulate Attack")
        self.btn_simulate.clicked.connect(self.simulate_attack)

        layout.addWidget(self.btn_start)
        layout.addWidget(self.btn_stop)
        layout.addWidget(self.btn_simulate)
        layout.addStretch()

        return layout

    def _setup_tray(self):
        try:
            self.tray = QtWidgets.QSystemTrayIcon(self)
            menu = QtWidgets.QMenu()
            menu.addAction("Show", self.showNormal)
            menu.addAction("Start Capture", self.start_capture)
            menu.addAction("Stop Capture", self.stop_capture)
            menu.addSeparator()
            menu.addAction("Exit", QtWidgets.QApplication.quit)
            self.tray.setContextMenu(menu)
            self.tray.show()
        except Exception:
            self.tray = None

    def add_log(self, text):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.append(f"[{ts}] {text}")
        self.log_box.moveCursor(QtGui.QTextCursor.MoveOperation.End)
        if self.log_box.document().blockCount() > 2000:
            self.log_box.clear()
            self.add_log("ℹ️ Log truncated to preserve memory")

    def show_alert(self, alert_obj):
        msg = f"[{alert_obj['time']}] 🚨 {alert_obj['host']} — {alert_obj['reason']}"
        self.alert_list.insertItem(0, msg)
        if self.tray:
            try:
                self.tray.showMessage("QuantumDefender Alert", msg,
                                     QtWidgets.QSystemTrayIcon.MessageIcon.Warning)
            except Exception:
                pass

    def set_status(self, ok):
        if ok:
            self.status_label.setText("Status: Connected ✅")
            self.status_label.setProperty("status", "success")
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)
        else:
            self.status_label.setText("Status: Disconnected ❌")
            self.status_label.setProperty("status", "error")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def update_metrics(self, pkts, alerts, pps):
        self.metric_packets.value_label.setText(f"{pkts:,}")
        self.metric_alerts.value_label.setText(f"{alerts:,}")
        self.metric_pps.value_label.setText(f"{pps:.1f}")

    def refresh_metrics(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self.metric_cpu.value_label.setText(f"{cpu:.0f}%")
        self.metric_mem.value_label.setText(f"{mem:.0f}%")

        # Connection stats
        conn_stats = get_connection_stats()
        self.metric_connections.value_label.setText(f"{conn_stats['active_connections']}")

        # Blocked IPs count
        with FIREWALL_RULES_LOCK:
            blocked_count = len(BLOCKED_IPS)
        self.metric_blocked.value_label.setText(f"{blocked_count}")

        # Network stats
        net_io = psutil.net_io_counters()
        bytes_sent_mb = net_io.bytes_sent / (1024 * 1024)
        bytes_recv_mb = net_io.bytes_recv / (1024 * 1024)

        # Signature engine stats
        sig_count = 0
        sig_engine_status = "❌ Disabled"
        if signature_engine:
            try:
                stats = signature_engine.get_stats()
                sig_count = stats.get("total_rules", 0)
                if stats.get("aho_corasick_enabled", False):
                    sig_engine_status = "✅ Aho-Corasick Enabled"
                else:
                    sig_engine_status = "⚠️ Fallback Mode"
            except Exception:
                sig_engine_status = "❌ Error"

        self.sysinfo_label.setText(
            f"<b>CPU:</b> {cpu:.1f}%<br>"
            f"<b>Memory:</b> {mem:.1f}%<br>"
            f"<b>Agent ID:</b> {DEVICE_INFO['agent_id']}<br>"
            f"<b>Hostname:</b> {DEVICE_INFO['hostname']}<br>"
            f"<b>IP:</b> {DEVICE_INFO['ip']}<br>"
            f"<b>OS:</b> {DEVICE_INFO['os']}<br>"
            f"<b>Region:</b> {DEVICE_INFO['region']}<br>"
            f"<b>Active Connections:</b> {conn_stats['active_connections']}<br>"
            f"<b>Total Flows:</b> {conn_stats['total_flows']}<br>"
            f"<b>Blocked IPs:</b> {blocked_count}<br>"
            f"<b>Signature Engine:</b> {sig_engine_status}<br>"
            f"<b>Loaded Signatures:</b> {sig_count}<br>"
            f"<b>Network Sent:</b> {bytes_sent_mb:.1f} MB<br>"
            f"<b>Network Recv:</b> {bytes_recv_mb:.1f} MB"
        )

        # Update signature metric
        self.metric_signatures.value_label.setText(f"{sig_count}")

    def start_capture(self):
        print("[UI] start_capture() called")
        try:
            self.add_log("🔗 Starting capture...")

            print("[UI] Loading config...")
            # Reload config and propagate to agent_core globals
            new_cfg = load_config()
            agent_core.CONFIG = new_cfg
            agent_core.CLOUD_URL = new_cfg["CLOUD_URL"]
            agent_core.ENABLE_FIREWALL_BLOCK = new_cfg["ENABLE_FIREWALL_BLOCK"]
            agent_core.BATCH_SIZE = new_cfg["BATCH_SIZE"]
            agent_core.SEND_INTERVAL = new_cfg["SEND_INTERVAL"]
            agent_core.FILTER_EXPR = new_cfg["FILTER"]
            print(f"[UI] Config loaded - CLOUD_URL: {agent_core.CLOUD_URL}, FILTER: {agent_core.FILTER_EXPR}")

            if self.capture.isRunning():
                print("[UI] Capture already running, returning")
                self.add_log("⚠️ Capture already running")
                return

            print("[UI] Creating new CaptureThread...")
            self.capture = CaptureThread()
            print("[UI] Connecting signals...")
            self.capture.log.connect(self.add_log)
            self.capture.alert.connect(self.show_alert)
            self.capture.status.connect(self.set_status)
            self.capture.metrics.connect(self.update_metrics)
            print("[UI] Starting capture thread...")
            self.capture.start()
            print("[UI] Capture thread started")
        except Exception as e:
            print(f"[UI] ERROR in start_capture(): {e}")
            print(f"[UI] Error type: {type(e).__name__}")
            import traceback
            print(f"[UI] Traceback: {traceback.format_exc()}")
            self.add_log(f"❌ Failed to start capture: {e}")

    def stop_capture(self):
        self.add_log("🛑 Stopping capture...")
        self.capture.stop()

    def simulate_attack(self):
        """Generate and send simulated attack event"""
        dst_ip = "203.0.113.5"
        malicious_url = "http://simulate.attack/payload"

        model_features = [
            "Destination_Port", "Flow_Duration", "Total_Fwd_Packets", "Total_Backward_Packets",
            "Total_Length_of_Fwd_Packets", "Total_Length_of_Bwd_Packets", "Fwd_Packet_Length_Max",
            "Fwd_Packet_Length_Min", "Fwd_Packet_Length_Mean", "Fwd_Packet_Length_Std",
            "Bwd_Packet_Length_Max", "Bwd_Packet_Length_Min", "Bwd_Packet_Length_Mean",
            "Bwd_Packet_Length_Std", "Flow_Bytes_s", "Flow_Packets_s", "Flow_IAT_Mean",
            "Flow_IAT_Std", "Flow_IAT_Max", "Flow_IAT_Min", "Fwd_IAT_Total", "Fwd_IAT_Mean",
            "Fwd_IAT_Std", "Fwd_IAT_Max", "Fwd_IAT_Min", "Bwd_IAT_Total", "Bwd_IAT_Mean",
            "Bwd_IAT_Std", "Bwd_IAT_Max", "Bwd_IAT_Min", "Fwd_PSH_Flags", "Bwd_PSH_Flags",
            "Fwd_URG_Flags", "Bwd_URG_Flags", "Fwd_Header_Length", "Bwd_Header_Length",
            "Fwd_Packets_s", "Bwd_Packets_s", "Min_Packet_Length", "Max_Packet_Length",
            "Packet_Length_Mean", "Packet_Length_Std", "Packet_Length_Variance", "FIN_Flag_Count",
            "SYN_Flag_Count", "RST_Flag_Count", "PSH_Flag_Count", "ACK_Flag_Count", "URG_Flag_Count",
            "CWE_Flag_Count", "ECE_Flag_Count", "Down_Up_Ratio", "Average_Packet_Size",
            "Avg_Fwd_Segment_Size", "Avg_Bwd_Segment_Size", "Fwd_Header_Length_1",
            "Fwd_Avg_Bytes_Bulk", "Fwd_Avg_Packets_Bulk", "Fwd_Avg_Bulk_Rate",
            "Bwd_Avg_Bytes_Bulk", "Bwd_Avg_Packets_Bulk", "Bwd_Avg_Bulk_Rate",
            "Subflow_Fwd_Packets", "Subflow_Fwd_Bytes", "Subflow_Bwd_Packets", "Subflow_Bwd_Bytes",
            "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
            "min_seg_size_forward", "Active_Mean", "Active_Std", "Active_Max", "Active_Min",
            "Idle_Mean", "Idle_Std", "Idle_Max", "Idle_Min"
        ]

        def random_feature_value(name):
            name = name.lower()
            if "port" in name:
                return random.choice([80, 443, 3389, 8080, 12345])
            if "duration" in name or "time" in name or "iat" in name:
                return float(random.randint(1, 5_000_000))
            if "packets" in name or "bytes" in name or "length" in name or "size" in name:
                return float(random.randint(0, 20000))
            if "ratio" in name or "average" in name or "mean" in name:
                return float(random.random() * 1000)
            if "flag" in name or "count" in name:
                return int(random.choice([0, 1, 2, 3]))
            if "active" in name or "idle" in name:
                return float(random.randint(0, 1_000_000))
            return float(random.randint(0, 10000))

        feat_values = {k: random_feature_value(k) for k in model_features}
        feat_values["Destination_Port"] = 3389
        feat_values["Packet_Length_Mean"] = 1200.0
        feat_values["Total_Fwd_Packets"] = 60
        feat_values["Total_Length_of_Fwd_Packets"] = 124000.0

        event = {
            **DEVICE_INFO,
            "host": DEVICE_INFO["hostname"],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": DEVICE_INFO.get("ip", "127.0.0.1"),
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "port_src": random.randint(1024, 65000),
            "port_dst": int(feat_values.get("Destination_Port", 3389)),
            "bytes_sent": int(feat_values.get("Total_Length_of_Fwd_Packets", 0)),
            "bytes_recv": int(feat_values.get("Total_Length_of_Bwd_Packets", 0)),
            "url": malicious_url,
            "category": "Misc",
            "process": {"pid": 9999, "name": "powershell.exe"},
            "detection_source": "simulated",
            "alert": True,
            "reason": "Simulated RDP brute force + large payload"
        }

        for k, v in feat_values.items():
            event[k] = v

        self.add_log("🛠 Simulating attack payload...")
        self.show_alert({
            "time": datetime.now().strftime("%H:%M:%S"),
            "host": dst_ip,
            "reason": "Simulated attack - test"
        })

        def _send():
            try:
                r = requests.post(agent_core.CLOUD_URL, json=[event], timeout=8)
                if r.ok:
                    self.add_log("📤 Simulated event sent to cloud")
                else:
                    self.add_log(f"⚠️ Cloud returned {r.status_code}")
            except Exception as e:
                self.add_log(f"⚠️ Send failed: {str(e)[:50]}")

        threading.Thread(target=_send, daemon=True).start()

    def _apply_and_save_config(self):
        new_cfg = {
            "CLOUD_URL": self.input_cloud.text().strip() or DEFAULT_CONFIG["CLOUD_URL"],
            "ENABLE_FIREWALL_BLOCK": bool(self.chk_firewall.isChecked()),
            "BATCH_SIZE": int(self.spin_batch.value()),
            "SEND_INTERVAL": float(self.spin_interval.value()),
            "FILTER": self.input_filter.text().strip() or DEFAULT_CONFIG["FILTER"]
        }
        ok = save_config(new_cfg)
        if ok:
            # Propagate new config to agent_core globals so capture thread picks them up
            agent_core.CONFIG = new_cfg
            agent_core.CLOUD_URL = new_cfg["CLOUD_URL"]
            agent_core.ENABLE_FIREWALL_BLOCK = new_cfg["ENABLE_FIREWALL_BLOCK"]
            agent_core.BATCH_SIZE = new_cfg["BATCH_SIZE"]
            agent_core.SEND_INTERVAL = new_cfg["SEND_INTERVAL"]
            agent_core.FILTER_EXPR = new_cfg["FILTER"]
            self.add_log("✅ Settings saved. Changes apply on next capture start.")
            QtWidgets.QMessageBox.information(
                self, "Settings Saved",
                "Settings saved successfully.\nChanges will apply on next capture start."
            )
        else:
            self.add_log("⚠️ Failed to save settings")
            QtWidgets.QMessageBox.warning(self, "Save Failed", "Failed to save settings. Check permissions.")

    def _cloud_check_loop(self):
        while True:
            try:
                t0 = time.time()
                root = agent_core.CLOUD_URL
                if root.endswith("/analyze"):
                    root = root.replace("/analyze", "/health")
                r = requests.get(root, timeout=6)
                latency = (time.time() - t0) * 1000.0
                self.cloud_status_signal.emit(r.ok, latency)
            except Exception:
                self.cloud_status_signal.emit(False, 0.0)
            time.sleep(10)

    def _on_cloud_status(self, reachable, latency_ms):
        if reachable:
            self.cloud_label.setText(f"☁ Cloud: {latency_ms:.0f}ms")
            self.cloud_label.setStyleSheet("font-size: 14px; font-weight: 700; color: #00e676;")
        else:
            self.cloud_label.setText("☁ Cloud: Unreachable")
            self.cloud_label.setStyleSheet("font-size: 14px; font-weight: 700; color: #ff5252;")

    def refresh_connections(self):
        """Refresh active connections display"""
        self.connection_list.clear()
        with FLOW_LOCK:
            active_flows = [
                (k, v) for k, v in CONNECTION_FLOWS.items()
                if time.time() - v["last_seen"] < 60
            ]
            active_flows.sort(key=lambda x: x[1]["last_seen"], reverse=True)

            for (src_ip, src_port, dst_ip, dst_port, proto), flow in active_flows[:20]:
                duration = time.time() - flow["start_time"]
                item_text = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{proto}] | {flow['packet_count']} pkts | {duration:.1f}s"
                self.connection_list.addItem(item_text)

    def _load_initial_signatures(self):
        """Load initial signatures from cloud on startup"""
        if not SIGNATURE_ENGINE_AVAILABLE or not agent_core.signature_engine:
            return

        try:
            time.sleep(2)  # Wait for cloud to be ready
            root_url = agent_core.CLOUD_URL.replace("/analyze", "")
            sig_url = f"{root_url}/api/signatures"
            r = requests.get(sig_url, timeout=5)

            if r.ok:
                sigs_data = r.json()
                rules = [SignatureRule(**sig) for sig in sigs_data]
                agent_core.signature_engine.load_rules(rules)
                count = len(rules)
                self.add_log(f"🔄 Loaded {count} signatures into optimized engine")
                print(f"[Agent] ✅ Initial signature load: {count} rules")
            else:
                self.add_log(f"⚠️ Failed to fetch initial signatures: {r.status_code}")
        except Exception as e:
            self.add_log(f"⚠️ Initial signature load error: {str(e)[:50]}")
            print(f"[Agent] ⚠️ Initial signature load failed: {e}")

    def _shutdown(self):
        self.add_log("⏳ Shutting down...")
        try:
            if hasattr(self, 'device_mgmt'):
                self.device_mgmt.disconnect()
            self.capture.stop()
            if self.capture.isRunning():
                self.capture.quit()
                self.capture.wait(2000)
        except Exception:
            pass
        self.add_log("✅ Shutdown complete")

# ===============================================================
# MAIN
# ===============================================================
def main():
    # Start local block-page HTTP server for soft firewall rules
    start_block_page_server(port=8899)

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("QuantumDefender Agent")

    # Apply dark theme if available
    if load_stylesheet:
        try:
            dark_style = load_stylesheet(theme="dark")
            app.setStyleSheet(dark_style + MODERN_STYLE)
        except Exception:
            app.setStyleSheet(MODERN_STYLE)
    else:
        app.setStyleSheet(MODERN_STYLE)

    win = AgentUI()
    win.show()

    try:
        sys.exit(app.exec())
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        raise

if __name__ == "__main__":
    main()
