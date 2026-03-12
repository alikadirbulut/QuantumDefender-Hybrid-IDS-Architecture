# ===============================================================
# QuantumDefender Agent Core — Non-UI Logic
# Extracted from agent.py lines 1-2181
# Imports, config, utilities, firewall state, capture thread, cloud sender
# ===============================================================
import random
from datetime import datetime
import sys
import os
import time
import uuid
import socket
import platform
import subprocess
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import requests
import psutil
import json
import re
import ctypes
from PySide6 import QtCore, QtWidgets, QtGui
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QFont, QColor, QPalette, QLinearGradient, QBrush

# Windows-specific imports
try:
    import win32api
    import win32con
    import win32net
    import win32security
    import win32process
    import win32event
    WIN32_AVAILABLE = True
except Exception:
    WIN32_AVAILABLE = False
    win32api = None
    win32con = None
    win32net = None
    win32security = None
    win32process = None
    win32event = None

try:
    import wmi
    WMI_AVAILABLE = True
except Exception:
    WMI_AVAILABLE = False
    wmi = None

# Optional modules
try:
    import pydivert
except Exception:
    pydivert = None

try:
    from qdarktheme import load_stylesheet
except Exception:
    load_stylesheet = None

try:
    import socketio
    socketio_available = True
except Exception:
    socketio_available = False
    socketio = None

# Signature engine (optimized Aho-Corasick)
try:
    from agent.signature_engine.engine import SignatureEngine
    from agent.schemas import SignatureRule
    SIGNATURE_ENGINE_AVAILABLE = True
except ImportError:
    SIGNATURE_ENGINE_AVAILABLE = False
    SignatureEngine = None
    SignatureRule = None

# ===============================================================
# CONFIGURATION MANAGEMENT
# ===============================================================
CONFIG_FILE = "agent_config.json"
DEFAULT_CONFIG = {
    "CLOUD_URL": "https://quantum.akedon.com/analyze",
    "ENABLE_FIREWALL_BLOCK": False,
    "BATCH_SIZE": 20,
    "SEND_INTERVAL": 2.0,
    "FILTER": "(tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 443)"
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        cfg["BATCH_SIZE"] = int(cfg.get("BATCH_SIZE", DEFAULT_CONFIG["BATCH_SIZE"]))
        cfg["SEND_INTERVAL"] = float(cfg.get("SEND_INTERVAL", DEFAULT_CONFIG["SEND_INTERVAL"]))
        cfg["ENABLE_FIREWALL_BLOCK"] = bool(cfg.get("ENABLE_FIREWALL_BLOCK", DEFAULT_CONFIG["ENABLE_FIREWALL_BLOCK"]))
        cfg["CLOUD_URL"] = str(cfg.get("CLOUD_URL", DEFAULT_CONFIG["CLOUD_URL"]))
        cfg["FILTER"] = str(cfg.get("FILTER", DEFAULT_CONFIG["FILTER"]))
        return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except Exception as e:
        print(f"[Config] Failed to save config: {e}", file=sys.stderr)
        return False

CONFIG = load_config()
CLOUD_URL = CONFIG["CLOUD_URL"]
ENABLE_FIREWALL_BLOCK = CONFIG["ENABLE_FIREWALL_BLOCK"]
BATCH_SIZE = CONFIG["BATCH_SIZE"]
SEND_INTERVAL = CONFIG["SEND_INTERVAL"]
FILTER_EXPR = CONFIG["FILTER"]

# ===============================================================
# SYSTEM INFO & UTILITIES
# ===============================================================
DOMAIN_CACHE = {}
_partial_http_buffers = {}
_partial_buffers_lock = threading.Lock()
_region_cache = None

def get_region():
    global _region_cache
    if _region_cache:
        return _region_cache
    try:
        ip = requests.get("https://api.ipify.org", timeout=3).text.strip()
        if ip:
            resp = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=5)
            if resp.ok:
                _region_cache = resp.text.strip() or "Unknown"
                return _region_cache
    except Exception:
        pass
    _region_cache = "Unknown"
    return _region_cache

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

DEVICE_INFO = {
    "agent_id": str(uuid.uuid4())[:8],
    "hostname": socket.gethostname(),
    "ip": get_local_ip(),
    "os": f"{platform.system()} {platform.release()}",
    "region": get_region()
}

def readable_bytes(num):
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"

def sanitize_ipv4(ip):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip))

def block_ip(ip):
    """AGGRESSIVE IP blocking using ALL Windows methods - INCLUDING ICMP/PING"""
    if not ENABLE_FIREWALL_BLOCK:
        return
    if not sanitize_ipv4(ip):
        return
    try:
        rule_base = f"QuantumDefender_Block_{ip.replace('.', '_')}"

        # Method 1: Block ALL protocols (TCP, UDP, ICMP) - OUTBOUND
        protocols = ["TCP", "UDP", "ICMPv4"]
        for protocol in protocols:
            rule_name = f"{rule_base}_{protocol}_OUT"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block",
                    f"protocol={protocol}", f"remoteip={ip}",
                    "enable=yes", "profile=any"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except Exception:
                pass

        # Method 2: Block ALL protocols - INBOUND
        for protocol in protocols:
            rule_name = f"{rule_base}_{protocol}_IN"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"protocol={protocol}", f"remoteip={ip}",
                    "enable=yes", "profile=any"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except Exception:
                pass

        # Method 3: Block ANY protocol (catch-all)
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_base}_ANY_OUT", "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes", "profile=any"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        except Exception:
            pass

        # Method 4: Route table manipulation (blackhole route) - MORE AGGRESSIVE
        try:
            subprocess.run([
                "route", "delete", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            subprocess.run([
                "route", "add", ip, "127.0.0.1", "metric", "1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
        except Exception:
            pass

        # Method 5: ARP table manipulation (block at layer 2)
        try:
            subprocess.run([
                "arp", "-d", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            subprocess.run([
                "arp", "-s", ip, "00-00-00-00-00-00"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        except Exception:
            pass  # May require admin

        # Method 6: Kill any ping.exe processes that might be running
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] and 'ping' in proc.info['name'].lower():
                        p = psutil.Process(proc.info['pid'])
                        p.terminate()
                        try:
                            p.wait(timeout=1)
                        except psutil.TimeoutExpired:
                            p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        # Method 7: Add to hosts file (redirect to localhost)
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            with open(hosts_path, "r", encoding="utf-8") as f:
                content = f.read()
            if ip not in content:
                with open(hosts_path, "a", encoding="utf-8") as f:
                    f.write(f"\n127.0.0.1 {ip} # QuantumDefender Block\n")
        except Exception:
            pass  # May not have write access

        print(f"[block_ip] ✅ AGGRESSIVE BLOCK applied to {ip} (TCP/UDP/ICMP/ALL protocols)")
    except Exception as e:
        print(f"[block_ip] Error: {e}")

def force_kill_process_by_connection(ip, port=None):
    """Aggressively kill processes using Windows APIs"""
    killed_pids = set()
    try:
        # Method 1: Use psutil with elevated privileges
        for conn in psutil.net_connections(kind='inet'):
            try:
                raddr = conn.raddr if conn.raddr else None
                laddr = conn.laddr if conn.laddr else None
                pid = conn.pid

                if pid and pid not in killed_pids:
                    match = False
                    if raddr and raddr.ip == ip:
                        if port is None or raddr.port == port:
                            match = True
                    if laddr and laddr.ip == ip:
                        if port is None or laddr.port == port:
                            match = True

                    if match:
                        try:
                            p = psutil.Process(pid)
                            p.terminate()
                            try:
                                p.wait(timeout=2)
                            except psutil.TimeoutExpired:
                                p.kill()
                            killed_pids.add(pid)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
            except Exception:
                continue

        # Method 2: Use Windows taskkill for stubborn processes
        if killed_pids:
            for pid in killed_pids:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    )
                except Exception:
                    pass

        # Method 3: Use WMI to find and kill processes (if available)
        if WMI_AVAILABLE and wmi:
            try:
                c = wmi.WMI()
                for process in c.Win32_Process():
                    try:
                        pid = process.ProcessId
                        if pid in killed_pids:
                            process.Terminate()
                    except Exception:
                        continue
            except Exception:
                pass

        return len(killed_pids)
    except Exception as e:
        print(f"[force_kill_process_by_connection] Error: {e}")
        return len(killed_pids)

def drop_connection_windows_firewall(ip, port=None, protocol="TCP"):
    """Drop connection using Windows Firewall rules - INCLUDING ICMP"""
    try:
        rule_base = f"QuantumDefender_Drop_{ip.replace('.', '_')}_{port or 'all'}"
        port_str = f"port={port}" if port else ""

        # Block ALL protocols (TCP, UDP, ICMP)
        protocols = ["TCP", "UDP", "ICMPv4"] if not port else [protocol]  # ICMP doesn't use ports

        for proto in protocols:
            if proto == "ICMPv4" and port:
                continue  # Skip ICMP if port specified (ICMP doesn't use ports)

            # Create outbound block rule
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_base}_{proto}_OUT", "dir=out", "action=block",
                    f"protocol={proto}", f"remoteip={ip}", port_str,
                    "enable=yes", "profile=any"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except Exception:
                pass

            # Create inbound block rule
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_base}_{proto}_IN", "dir=in", "action=block",
                    f"protocol={proto}", f"remoteip={ip}", port_str,
                    "enable=yes", "profile=any"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except Exception:
                pass

        # Also create catch-all rule
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_base}_ANY", "dir=out", "action=block",
                f"remoteip={ip}", "enable=yes", "profile=any"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        except Exception:
            pass

        return True
    except Exception as e:
        print(f"[drop_connection_windows_firewall] Error: {e}")
        return False

def manipulate_route_table(ip, action="add"):
    """Manipulate Windows route table to block IP"""
    try:
        if action == "add":
            subprocess.run([
                "route", "delete", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            subprocess.run([
                "route", "add", ip, "127.0.0.1", "metric", "1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
        elif action == "delete":
            subprocess.run([
                "route", "delete", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
        return True
    except Exception:
        return False

def kill_ping_processes():
    """Kill all ping.exe processes to stop active pings"""
    killed = 0
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = proc.info.get('name', '').lower()
                cmdline = ' '.join(proc.info.get('cmdline', [])).lower() if proc.info.get('cmdline') else ''

                if 'ping' in name or ('ping' in cmdline and 'ping.exe' in cmdline):
                    p = psutil.Process(proc.info['pid'])
                    p.terminate()
                    try:
                        p.wait(timeout=1)
                    except psutil.TimeoutExpired:
                        p.kill()
                    killed += 1
                    print(f"[kill_ping_processes] Killed ping process PID {proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.NoSuchProcess):
                pass
    except Exception as e:
        print(f"[kill_ping_processes] Error: {e}")
    return killed

def manipulate_arp_table(ip, action="block"):
    """Manipulate ARP table to block IP at layer 2"""
    try:
        if action == "block":
            subprocess.run([
                "arp", "-d", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            subprocess.run([
                "arp", "-s", ip, "00-00-00-00-00-00"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        elif action == "delete":
            subprocess.run([
                "arp", "-d", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        return True
    except Exception:
        return False

# ===============================================================
# PROCESS SOCKET CACHE
# ===============================================================
_PROCESS_SOCKET_CACHE = {}
_PROCESS_CACHE_LOCK = threading.Lock()

def _refresh_connection_cache_forever():
    while True:
        try:
            tmp = {}
            for c in psutil.net_connections(kind="inet"):
                if not c.laddr:
                    continue
                try:
                    key = (c.laddr.ip, c.laddr.port)
                    tmp[key] = c.pid
                except Exception:
                    continue
            with _PROCESS_CACHE_LOCK:
                _PROCESS_SOCKET_CACHE.clear()
                _PROCESS_SOCKET_CACHE.update(tmp)
        except Exception:
            pass
        time.sleep(1)

threading.Thread(target=_refresh_connection_cache_forever, daemon=True).start()

def find_process_for_socket(local_ip, local_port):
    with _PROCESS_CACHE_LOCK:
        pid = _PROCESS_SOCKET_CACHE.get((local_ip, local_port))
    if not pid:
        return {}
    try:
        p = psutil.Process(pid)
        return {"pid": pid, "name": p.name(), "exe": p.exe(), "user": p.username()}
    except Exception:
        return {}

# ===============================================================
# TLS SNI PARSER
# ===============================================================
def parse_sni_from_client_hello(payload_bytes):
    try:
        if not payload_bytes or len(payload_bytes) < 5:
            return None
        content_type = payload_bytes[0]
        if content_type != 0x16:
            return None
        offset = 5
        if offset + 4 > len(payload_bytes):
            return None
        handshake_type = payload_bytes[offset]
        if handshake_type != 0x01:
            return None
        offset += 4
        offset += 34
        if offset >= len(payload_bytes):
            return None
        sid_len = payload_bytes[offset]
        offset += 1 + sid_len
        if offset + 2 > len(payload_bytes):
            return None
        cs_len = int.from_bytes(payload_bytes[offset:offset+2], "big")
        offset += 2 + cs_len
        if offset + 1 > len(payload_bytes):
            return None
        comp_len = payload_bytes[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload_bytes):
            return None
        ext_len_total = int.from_bytes(payload_bytes[offset:offset+2], "big")
        offset += 2
        end_ext = offset + ext_len_total
        while offset + 4 <= end_ext and offset + 4 <= len(payload_bytes):
            ext_type = int.from_bytes(payload_bytes[offset:offset+2], "big")
            ext_len = int.from_bytes(payload_bytes[offset+2:offset+4], "big")
            offset += 4
            if ext_type == 0x00:
                if offset + 2 > len(payload_bytes):
                    return None
                list_len = int.from_bytes(payload_bytes[offset:offset+2], "big")
                offset += 2
                if offset + 3 > len(payload_bytes):
                    return None
                name_type = payload_bytes[offset]
                name_len = int.from_bytes(payload_bytes[offset+1:offset+3], "big")
                offset += 3
                if offset + name_len > len(payload_bytes):
                    return None
                server_name = payload_bytes[offset:offset+name_len].decode(errors="ignore")
                return server_name
            offset += ext_len
        return None
    except Exception:
        return None

# ===============================================================
# URL EXTRACTION
# ===============================================================
def extract_url_from_text(payload_text, dst_ip="", dst_port=0):
    try:
        m = re.search(r"(https?://[^\s\"']{4,200})", payload_text, flags=re.IGNORECASE)
        if m:
            url = m.group(1)[:200]
            domain = re.sub(r"^https?://", "", url).split("/")[0]
            if dst_ip and domain:
                DOMAIN_CACHE[dst_ip] = domain
            return url
        m = re.search(r"Host:\s*([^\r\n]+)", payload_text, flags=re.IGNORECASE)
        if m:
            domain = m.group(1).strip()
            if dst_ip and domain:
                DOMAIN_CACHE[dst_ip] = domain
            scheme = "https" if dst_port == 443 else "http"
            return f"{scheme}://{domain}"
        if dst_ip in DOMAIN_CACHE:
            scheme = "https" if dst_port == 443 else "http"
            return f"{scheme}://{DOMAIN_CACHE[dst_ip]}"
        if dst_ip:
            scheme = "https" if dst_port == 443 else "http" if dst_port == 80 else "tcp"
            return f"{scheme}://{dst_ip}:{dst_port}"
    except Exception:
        pass
    return None

# ===============================================================
# THREAT DETECTION
# ===============================================================
def detect_threat(event):
    url = (event.get("url") or "").lower()
    process = (event.get("process", {}).get("name") or "").lower()
    dst_port = event.get("port_dst", 0)
    size = event.get("bytes_sent", 0)

    if any(k in url for k in ["malware", "phishing", "botnet", "crypt"]):
        return True, f"Malicious keyword in URL: {url[:50]}"
    if dst_port in [22, 23, 3389]:
        return True, f"Suspicious remote-access port {dst_port}"
    if any(p in process for p in ["powershell", "cmd.exe", "wmic.exe", "regsvr32"]):
        return True, f"Suspicious process: {process}"
    if size > 10_000_000:
        return True, f"Large payload: {readable_bytes(size)}"
    return False, "benign"

# ===============================================================
# SIGNATURE ENGINE (Optimized Aho-Corasick)
# ===============================================================
if SIGNATURE_ENGINE_AVAILABLE and SignatureEngine:
    signature_engine = SignatureEngine()
    print("[Agent] ✅ Optimized Aho-Corasick signature engine initialized")
else:
    signature_engine = None
    print("[Agent] ⚠️ Signature engine unavailable, using cloud-only detection")

# ===============================================================
# FIREWALL RULES MANAGER
# ===============================================================
BLOCKED_IPS = set()
BLOCKED_DOMAINS = set()  # Track blocked domains
BLOCKED_CIDRS = set()  # Track CIDR blocks (e.g., "192.168.1.0/24")
FIREWALL_RULES_LOCK = threading.Lock()

# Soft-block rules for HTTP(S) "block with page" mode
SOFT_BLOCK_IPS = set()
SOFT_BLOCK_DOMAINS = set()
SOFT_BLOCK_CIDRS = set()


def is_soft_blocked(host: str) -> bool:
    """Check if a given Host header should be soft-blocked (block page)."""
    if not host:
        return False
    host = host.split(":")[0].strip().lower()

    # Hard-coded demo/test domains that should always show the block page
    if host in {"blocked.test", "www.blocked.test"}:
        return True

    with FIREWALL_RULES_LOCK:
        if host in SOFT_BLOCK_DOMAINS or host in SOFT_BLOCK_IPS:
            return True
        for cidr in SOFT_BLOCK_CIDRS:
            try:
                if ip_in_cidr(host, cidr):
                    return True
            except Exception:
                continue
    return False


class BlockPageHandler(BaseHTTPRequestHandler):
    def _send_block_page(self, submitted: bool = False):
        parsed = urlparse(self.path)
        host = self.headers.get("Host", "")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        message_section = """
          <div class="pill pill-red">This destination is blocked by QuantumDefender policy.</div>
        """ if not submitted else """
          <div class="pill pill-green">Your unblock request has been submitted. This page may not refresh automatically.</div>
        """
        html = f"""
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Blocked by QuantumDefender</title>
    <style>
      :root {{
        --bg: #020617;
        --card-bg: rgba(15,23,42,0.96);
        --accent: #38bdf8;
        --accent-soft: rgba(56,189,248,0.2);
        --danger: #f97373;
        --success: #22c55e;
        --text-main: #e5e7eb;
        --text-muted: #9ca3af;
      }}
      * {{
        box-sizing: border-box;
      }}
      body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background:
          radial-gradient(circle at 0% 0%, rgba(56,189,248,0.2) 0, transparent 55%),
          radial-gradient(circle at 100% 100%, rgba(244,63,94,0.18) 0, transparent 55%),
          var(--bg);
        color: var(--text-main);
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
        margin: 0;
        padding: 16px;
      }}
      .card {{
        position: relative;
        background: var(--card-bg);
        border-radius: 18px;
        padding: 28px 32px 26px;
        max-width: 620px;
        width: 100%;
        box-shadow: 0 24px 80px rgba(15,23,42,0.9);
        border: 1px solid var(--accent-soft);
        overflow: hidden;
      }}
      .card::before {{
        content: "";
        position: absolute;
        inset: -40%;
        background:
          radial-gradient(circle at 0 0, rgba(56,189,248,0.18) 0, transparent 50%),
          radial-gradient(circle at 100% 100%, rgba(244,63,94,0.18) 0, transparent 50%);
        opacity: 0.35;
        pointer-events: none;
      }}
      .card-inner {{
        position: relative;
        z-index: 1;
      }}
      h1 {{
        margin: 0 0 6px;
        font-size: 22px;
        display: flex;
        align-items: center;
        gap: 10px;
      }}
      h1 span.icon {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        border-radius: 999px;
        background: radial-gradient(circle at 30% 0%, #f97373 0, #ef4444 40%, #b91c1c 100%);
        box-shadow: 0 0 18px rgba(248,113,113,0.75);
        font-size: 16px;
      }}
      .subtitle {{
        font-size: 13px;
        color: var(--text-muted);
        margin-bottom: 14px;
      }}
      .pill {{
        display: inline-flex;
        align-items: center;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        margin-bottom: 14px;
      }}
      .pill span.dot {{
        width: 7px;
        height: 7px;
        border-radius: 999px;
        margin-right: 6px;
        background: currentColor;
      }}
      .pill-red {{
        color: #fecaca;
        background: rgba(127,29,29,0.65);
        border: 1px solid rgba(254,202,202,0.4);
      }}
      .pill-green {{
        color: #bbf7d0;
        background: rgba(22,101,52,0.7);
        border: 1px solid rgba(134,239,172,0.45);
      }}
      .grid {{
        display: grid;
        grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr);
        gap: 18px;
        margin-top: 4px;
      }}
      @media (max-width: 640px) {{
        .grid {{
          grid-template-columns: minmax(0, 1fr);
        }}
      }}
      .info-item {{
        font-size: 13px;
        margin-bottom: 6px;
      }}
      .info-label {{
        display: inline-block;
        width: 70px;
        color: var(--text-muted);
      }}
      code {{
        background: rgba(15,23,42,0.95);
        padding: 1px 6px;
        border-radius: 4px;
        font-size: 12px;
      }}
      form {{
        margin-top: 4px;
      }}
      label {{
        display: block;
        font-size: 12px;
        color: var(--text-muted);
        margin-bottom: 3px;
      }}
      input[type="text"],
      input[type="email"],
      textarea {{
        width: 100%;
        background: rgba(15,23,42,0.9);
        border-radius: 8px;
        border: 1px solid rgba(148,163,184,0.6);
        color: var(--text-main);
        font-size: 13px;
        padding: 7px 9px;
        outline: none;
        margin-bottom: 8px;
      }}
      input[type="text"]:focus,
      input[type="email"]:focus,
      textarea:focus {{
        border-color: var(--accent);
        box-shadow: 0 0 0 1px rgba(56,189,248,0.35);
      }}
      textarea {{
        min-height: 72px;
        resize: vertical;
      }}
      .hint {{
        font-size: 11px;
        color: var(--text-muted);
        margin-top: -4px;
        margin-bottom: 8px;
      }}
      button[type="submit"] {{
        width: 100%;
        margin-top: 4px;
        border-radius: 999px;
        border: none;
        padding: 8px 12px;
        font-weight: 600;
        font-size: 13px;
        cursor: pointer;
        background: linear-gradient(135deg, #38bdf8, #6366f1);
        color: #0b1120;
        box-shadow: 0 12px 30px rgba(56,189,248,0.45);
      }}
      button[type="submit"]:hover {{
        filter: brightness(1.05);
      }}
      .footer-note {{
        margin-top: 10px;
        font-size: 11px;
        color: var(--text-muted);
      }}
    </style>
  </head>
  <body>
    <div class="card">
      <div class="card-inner">
        <h1><span class="icon">⛔</span> QuantumDefender Web Control</h1>
        <div class="subtitle">Access to this destination has been restricted by your security policy.</div>
        {message_section}
        <div class="grid">
          <div>
            <div class="info-item">
              <span class="info-label">Host</span>
              <code>{host or 'unknown'}</code>
            </div>
            <div class="info-item">
              <span class="info-label">Path</span>
              <code>{parsed.path}</code>
            </div>
            <div class="info-item">
              <span class="info-label">Mode</span>
              <code>Block with page</code>
            </div>
            <p class="hint">This soft block does not kill the connection at firewall level; it replaces the page instead.</p>
          </div>
          <div>
            <form method="POST" action="/">
              <input type="hidden" name="host" value="{host or ''}">
              <label for="q_user">Your name (optional)</label>
              <input id="q_user" name="user" type="text" placeholder="e.g. Alice from Finance">
              <label for="q_reason">Why do you need access?</label>
              <textarea id="q_reason" name="reason" required placeholder="Describe why this destination is business‑relevant or required for your work."></textarea>
              <div class="hint">Your request will be logged by the local QuantumDefender agent and can be reviewed by an administrator.</div>
              <button type="submit">Submit unblock request</button>
            </form>
          </div>
        </div>
        <div class="footer-note">
          QuantumDefender Agent &middot; Local policy enforcement. If this is unexpected, contact your security team.
        </div>
      </div>
    </div>
  </body>
</html>
"""
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        host = self.headers.get("Host", "")
        if is_soft_blocked(host):
            self._send_block_page()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"QuantumDefender local block page service is running.\n"
                b"This host is not currently configured for soft blocking.\n"
            )

    def do_POST(self):
        """Handle unblock request submissions."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            from urllib.parse import parse_qs
            data = parse_qs(raw.decode("utf-8", errors="ignore"))
        except Exception:
            data = {}

        host = (data.get("host", [""])[0] or self.headers.get("Host", "")).strip()
        user = (data.get("user", [""])[0] or "").strip()
        reason = (data.get("reason", [""])[0] or "").strip()

        try:
            line = f"[UNBLOCK_REQUEST] host={host!r}, user={user!r}, reason={reason!r}\n"
            print(line.strip())
            with open("qd_unblock_requests.log", "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

        self._send_block_page(submitted=True)

    def log_message(self, format, *args):
        return


def start_block_page_server(port: int = 8899):
    """Start a lightweight local HTTP server that serves the QuantumDefender block page."""
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), BlockPageHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print(f"[Agent] ✅ Block-page HTTP server running on http://127.0.0.1:{port}")
    except Exception as e:
        print(f"[Agent] ⚠️ Failed to start block-page HTTP server: {e}")

def resolve_domain_to_ip(domain):
    """Resolve domain name to IP address"""
    if not domain:
        return None
    try:
        domain = str(domain).replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
        if not domain:
            return None
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            return domain
        ip = socket.gethostbyname(domain)
        return ip
    except (socket.gaierror, socket.herror, OSError, Exception):
        return None

def ip_in_cidr(ip, cidr):
    """Check if IP is in CIDR range"""
    try:
        print(f"[ip_in_cidr] Checking if {ip} is in {cidr}")
        import ipaddress
        if not ip or not cidr:
            print("[ip_in_cidr] IP or CIDR is None/empty")
            return False
        ip_obj = ipaddress.ip_address(str(ip))
        print(f"[ip_in_cidr] IP object created: {ip_obj}")
        network = ipaddress.ip_network(str(cidr), strict=False)
        print(f"[ip_in_cidr] Network object created: {network}")
        result = ip_obj in network
        print(f"[ip_in_cidr] Result: {result}")
        return result
    except (ValueError, AttributeError, Exception) as e:
        print(f"[ip_in_cidr] ERROR: {e}")
        import traceback
        print(f"[ip_in_cidr] Traceback: {traceback.format_exc()}")
        return False

def update_firewall_rules(blocked_ips_list):
    """Update blocked IPs list from cloud"""
    global BLOCKED_IPS
    with FIREWALL_RULES_LOCK:
        BLOCKED_IPS.update(blocked_ips_list)
        for ip in blocked_ips_list:
            if ip not in BLOCKED_IPS or ENABLE_FIREWALL_BLOCK:
                block_ip(ip)

def block_domain(domain):
    """Block a domain by resolving to IP and blocking"""
    ip = resolve_domain_to_ip(domain)
    if ip:
        with FIREWALL_RULES_LOCK:
            BLOCKED_DOMAINS.add(domain)
            BLOCKED_IPS.add(ip)
        if ENABLE_FIREWALL_BLOCK:
            block_ip(ip)
        return ip
    return None

def block_cidr(cidr):
    """Block a CIDR range"""
    try:
        import ipaddress
        ipaddress.ip_network(cidr, strict=False)
        with FIREWALL_RULES_LOCK:
            BLOCKED_CIDRS.add(cidr)
        if ENABLE_FIREWALL_BLOCK:
            rule_name = f"QuantumDefender_Block_{cidr.replace('/', '_')}"
            try:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block", f"remoteip={cidr}"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass
        return True
    except Exception:
        return False

def check_firewall_block(ip):
    """Check if IP is blocked (directly, via domain, or via CIDR)"""
    print(f"[check_firewall_block] Checking IP: {ip}")
    if not ip:
        print("[check_firewall_block] IP is None/empty, returning False")
        return False
    try:
        print("[check_firewall_block] Acquiring FIREWALL_RULES_LOCK...")
        with FIREWALL_RULES_LOCK:
            print(f"[check_firewall_block] BLOCKED_IPS: {BLOCKED_IPS}")
            print(f"[check_firewall_block] BLOCKED_CIDRS: {BLOCKED_CIDRS}")
            if ip in BLOCKED_IPS:
                print(f"[check_firewall_block] IP {ip} found in BLOCKED_IPS")
                return True
            print("[check_firewall_block] Checking CIDR blocks...")
            for cidr in BLOCKED_CIDRS:
                print(f"[check_firewall_block] Checking CIDR: {cidr}")
                if ip_in_cidr(ip, cidr):
                    print(f"[check_firewall_block] IP {ip} matches CIDR {cidr}")
                    return True
        print("[check_firewall_block] IP not blocked")
    except Exception as e:
        print(f"[check_firewall_block] ERROR: {e}")
        import traceback
        print(f"[check_firewall_block] Traceback: {traceback.format_exc()}")
        pass
    return False

def check_domain_block(domain_or_url):
    """Check if domain is blocked (handles both domain and URL)"""
    print(f"[check_domain_block] Checking domain: {domain_or_url}")
    if not domain_or_url:
        print("[check_domain_block] Domain is None/empty")
        return False
    try:
        domain = str(domain_or_url)
        if "://" in domain:
            domain = domain.split("://")[1]
        domain = domain.split("/")[0].split(":")[0]
        print(f"[check_domain_block] Extracted domain: {domain}")

        with FIREWALL_RULES_LOCK:
            print(f"[check_domain_block] BLOCKED_DOMAINS: {BLOCKED_DOMAINS}")
            if domain in BLOCKED_DOMAINS:
                print(f"[check_domain_block] Domain {domain} found in BLOCKED_DOMAINS")
                return True
            print("[check_domain_block] Resolving domain to IP...")
            ip = resolve_domain_to_ip(domain)
            print(f"[check_domain_block] Resolved IP: {ip}")
            if ip:
                if ip in BLOCKED_IPS:
                    print(f"[check_domain_block] IP {ip} found in BLOCKED_IPS")
                    return True
                for cidr in BLOCKED_CIDRS:
                    if ip_in_cidr(ip, cidr):
                        print(f"[check_domain_block] IP {ip} matches CIDR {cidr}")
                        return True
        print("[check_domain_block] Domain not blocked")
    except Exception as e:
        print(f"[check_domain_block] ERROR: {e}")
        import traceback
        print(f"[check_domain_block] Traceback: {traceback.format_exc()}")
        pass
    return False

# ===============================================================
# CONNECTION TRACKING
# ===============================================================
CONNECTION_FLOWS = {}  # Track active connections
FLOW_LOCK = threading.Lock()

def track_connection(src_ip, src_port, dst_ip, dst_port, protocol):
    """Track network connections for flow analysis"""
    key = (src_ip, src_port, dst_ip, dst_port, protocol)
    with FLOW_LOCK:
        if key not in CONNECTION_FLOWS:
            CONNECTION_FLOWS[key] = {
                "start_time": time.time(),
                "packet_count": 0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "last_seen": time.time()
            }
        flow = CONNECTION_FLOWS[key]
        flow["packet_count"] += 1
        flow["last_seen"] = time.time()
    return flow

def get_connection_stats():
    """Get statistics about active connections"""
    with FLOW_LOCK:
        active = [f for f in CONNECTION_FLOWS.values() if time.time() - f["last_seen"] < 60]
        return {
            "active_connections": len(active),
            "total_flows": len(CONNECTION_FLOWS),
            "total_packets": sum(f["packet_count"] for f in CONNECTION_FLOWS.values()),
            "total_bytes": sum(f["bytes_sent"] + f["bytes_recv"] for f in CONNECTION_FLOWS.values())
        }

# ===============================================================
# DEVICE MANAGEMENT CLIENT
# ===============================================================
class DeviceManagementClient:
    """Handles real-time communication with cloud for device management"""
    def __init__(self, cloud_url, agent_id, log_callback=None, alert_callback=None):
        self.cloud_url = cloud_url.replace("/analyze", "").replace("/api", "")
        self.agent_id = agent_id
        self.log_callback = log_callback or (lambda x: None)
        self.alert_callback = alert_callback or (lambda x: None)
        self.sio = None
        self.connected = False

    def connect(self):
        """Connect to cloud Socket.IO server"""
        if not socketio_available:
            self.log_callback("⚠️ Socket.IO not available. Device management disabled.")
            return False

        try:
            self.sio = socketio.Client() if socketio else None
            if not self.sio:
                return False

            @self.sio.on('connect')
            def on_connect():
                self.connected = True
                self.log_callback("🔗 Connected to cloud device management")
                self.sio.emit('agent_register', {
                    'agent_id': self.agent_id,
                    'hostname': DEVICE_INFO['hostname'],
                    'ip': DEVICE_INFO['ip'],
                    'os': DEVICE_INFO['os'],
                    'region': DEVICE_INFO['region']
                })

            @self.sio.on('disconnect')
            def on_disconnect():
                self.connected = False
                self.log_callback("⚠️ Disconnected from cloud device management")

            @self.sio.on('agent_command')
            def on_command(data):
                self._handle_command(data)

            @self.sio.on('firewall_rule')
            def on_firewall_rule(data):
                action = data.get('action')
                ip = data.get('ip')
                domain = data.get('domain')
                cidr = data.get('cidr')
                port_raw = data.get('port')
                mode = (data.get('mode') or 'drop').lower()
                try:
                    port = int(port_raw) if port_raw not in (None, "", 0) else None
                except Exception:
                    port = None

                if action == 'block':
                    if mode == 'allow':
                        with FIREWALL_RULES_LOCK:
                            if ip:
                                BLOCKED_IPS.discard(ip)
                                SOFT_BLOCK_IPS.discard(ip)
                            if domain:
                                BLOCKED_DOMAINS.discard(domain)
                                SOFT_BLOCK_DOMAINS.discard(domain)
                            if cidr:
                                BLOCKED_CIDRS.discard(cidr)
                                SOFT_BLOCK_CIDRS.discard(cidr)
                        self.log_callback(f"✅ Firewall allow-rule received for {ip or domain or cidr}")
                        return

                    if mode == 'page':
                        with FIREWALL_RULES_LOCK:
                            if ip:
                                SOFT_BLOCK_IPS.add(ip)
                            if domain:
                                SOFT_BLOCK_DOMAINS.add(domain)
                            if cidr:
                                SOFT_BLOCK_CIDRS.add(cidr)
                        self.log_callback(f"🛡️ Soft firewall rule (block with page) received for {ip or domain or cidr}")
                        return

                    if ip:
                        if ip not in BLOCKED_IPS:
                            update_firewall_rules([ip])
                            self.log_callback(f"🛡️ Firewall rule received: Block IP {ip}")
                            if ENABLE_FIREWALL_BLOCK:
                                block_ip(ip)
                                if port:
                                    drop_connection_windows_firewall(ip, port)
                    elif domain:
                        resolved_ip = block_domain(domain)
                        if resolved_ip:
                            self.log_callback(f"🛡️ Firewall rule received: Block domain {domain} ({resolved_ip})")
                        else:
                            self.log_callback(f"⚠️ Could not resolve domain: {domain}")
                    elif cidr:
                        if block_cidr(cidr):
                            self.log_callback(f"🛡️ Firewall rule received: Block CIDR {cidr}")
                        else:
                            self.log_callback(f"⚠️ Invalid CIDR format: {cidr}")
                elif action == 'unblock':
                    if ip:
                        with FIREWALL_RULES_LOCK:
                            BLOCKED_IPS.discard(ip)
                            SOFT_BLOCK_IPS.discard(ip)
                        self.log_callback(f"🛡️ Firewall rule received: Unblock IP {ip}")
                    elif domain:
                        with FIREWALL_RULES_LOCK:
                            BLOCKED_DOMAINS.discard(domain)
                            SOFT_BLOCK_DOMAINS.discard(domain)
                        self.log_callback(f"🛡️ Firewall rule received: Unblock domain {domain}")
                    elif cidr:
                        with FIREWALL_RULES_LOCK:
                            BLOCKED_CIDRS.discard(cidr)
                            SOFT_BLOCK_CIDRS.discard(cidr)
                        self.log_callback(f"🛡️ Firewall rule received: Unblock CIDR {cidr}")

            @self.sio.on('notification')
            def on_notification(data):
                self._show_notification(data)

            @self.sio.on('drop_connection')
            def on_drop_connection(data):
                print(f"[SOCKET] drop_connection event received: {data}")
                self.log_callback(f"📡 Received drop_connection command from cloud")
                self._drop_connection(data)

            @self.sio.on('signature_update')
            def on_signature_update(data):
                """Handle signature updates from cloud"""
                self._handle_signature_update(data)

            self.sio.connect(self.cloud_url, wait_timeout=10)
            return True
        except Exception as e:
            self.log_callback(f"⚠️ Failed to connect device management: {str(e)[:50]}")
            return False

    def _handle_command(self, data):
        """Handle commands from cloud"""
        cmd = data.get('command', '')
        params = data.get('params', {})

        if cmd == 'show_notification':
            self._show_notification(params)
        elif cmd == 'drop_connection':
            self._drop_connection(params)
        elif cmd == 'update_config':
            self._update_config(params)
        elif cmd == 'restart_capture':
            self.log_callback("🔄 Restart capture command received")
            if hasattr(self, 'restart_callback'):
                self.restart_callback()

    def _show_notification(self, data):
        """Show Windows notification"""
        title = data.get('title', 'QuantumDefender')
        message = data.get('message', '')
        duration = data.get('duration', 5000)

        try:
            if self.alert_callback:
                self.alert_callback({
                    'time': datetime.now().strftime("%H:%M:%S"),
                    'host': 'Cloud',
                    'reason': f"{title}: {message}"
                })
            try:
                from winotify import Notification
                toast = Notification(app_id="QuantumDefender", title=title, msg=message, duration="long")
                toast.show()
            except Exception:
                pass
            self.log_callback(f"📢 Notification: {title} - {message}")
        except Exception as e:
            self.log_callback(f"⚠️ Notification failed: {str(e)[:50]}")

    def _drop_connection(self, data):
        """AGGRESSIVE connection dropping using multiple Windows APIs and methods"""
        print(f"[DROP_CONNECTION] ⚡ AGGRESSIVE MODE - Received drop command: {data}")
        self.log_callback("🔪 Initiating aggressive connection termination...")

        target_ip = data.get('ip')
        target_domain = data.get('domain')
        target_cidr = data.get('cidr')
        target_port_raw = data.get('port')
        try:
            target_port = int(target_port_raw) if target_port_raw not in (None, "") else None
        except Exception:
            target_port = None

        if not target_ip and not target_domain and not target_cidr:
            print("[DROP_CONNECTION] No IP, domain, or CIDR provided")
            self.log_callback("⚠️ Drop connection: No IP, domain, or CIDR provided")
            return

        try:
            ips_to_drop = []
            if target_ip:
                ips_to_drop.append(target_ip)
            if target_domain:
                print(f"[DROP_CONNECTION] Resolving domain: {target_domain}")
                try:
                    resolved = {res[4][0] for res in socket.getaddrinfo(target_domain, None)}
                    ips_to_drop.extend(list(resolved))
                    print(f"[DROP_CONNECTION] Resolved {target_domain} to {resolved}")
                except Exception:
                    resolved_ip = resolve_domain_to_ip(target_domain)
                    if resolved_ip:
                        ips_to_drop.append(resolved_ip)
                        print(f"[DROP_CONNECTION] Resolved via fallback to {resolved_ip}")
                    else:
                        self.log_callback(f"⚠️ Could not resolve domain: {target_domain}")
                        return

            cidr_to_drop = None
            if target_cidr:
                try:
                    import ipaddress
                    cidr_to_drop = str(ipaddress.ip_network(str(target_cidr), strict=False))
                    print(f"[DROP_CONNECTION] CIDR validated: {cidr_to_drop}")
                except Exception as e:
                    self.log_callback(f"⚠️ Invalid CIDR: {target_cidr}")
                    print(f"[DROP_CONNECTION] Invalid CIDR {target_cidr}: {e}")
                    return

            ips_to_drop = list({ip for ip in ips_to_drop if ip})
            if not ips_to_drop and not cidr_to_drop:
                self.log_callback("⚠️ No valid IPs/CIDR to drop")
                return

            self.log_callback("🛡️ Applying AGGRESSIVE firewall blocks (TCP/UDP/ICMP)...")
            for ip in ips_to_drop:
                try:
                    block_ip(ip)
                    update_firewall_rules([ip])
                    drop_connection_windows_firewall(ip, target_port)
                    manipulate_route_table(ip, "add")
                    manipulate_arp_table(ip, "block")
                    print(f"[DROP_CONNECTION] ✅ Multi-layer block applied for {ip} (ICMP included)")
                except Exception as e:
                    print(f"[DROP_CONNECTION] Firewall block failed for {ip}: {e}")

            self.log_callback("🔪 Terminating all ping processes...")
            ping_killed = kill_ping_processes()
            if ping_killed > 0:
                self.log_callback(f"🔪 Killed {ping_killed} ping process(es)")
                print(f"[DROP_CONNECTION] Killed {ping_killed} ping processes")

            if cidr_to_drop:
                try:
                    block_cidr(cidr_to_drop)
                    print(f"[DROP_CONNECTION] ✅ CIDR block applied for {cidr_to_drop}")
                except Exception as e:
                    print(f"[DROP_CONNECTION] CIDR block failed: {e}")

            self.log_callback("🔪 Terminating processes...")
            dropped_count = 0
            terminated_pids = set()

            for ip in ips_to_drop:
                killed = force_kill_process_by_connection(ip, target_port)
                dropped_count += killed
                print(f"[DROP_CONNECTION] Killed {killed} processes for {ip}")

            try:
                print("[DROP_CONNECTION] Comprehensive psutil scan...")
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        raddr_ip = conn.raddr.ip if conn.raddr else None
                        raddr_port = conn.raddr.port if conn.raddr else None
                        laddr_ip = conn.laddr.ip if conn.laddr else None
                        laddr_port = conn.laddr.port if conn.laddr else None
                        pid = conn.pid

                        match_ip = (raddr_ip in ips_to_drop) or (laddr_ip in ips_to_drop)
                        match_cidr = False
                        if cidr_to_drop:
                            match_cidr = (ip_in_cidr(raddr_ip, cidr_to_drop) if raddr_ip else False) or \
                                         (ip_in_cidr(laddr_ip, cidr_to_drop) if laddr_ip else False)
                        match_port = True
                        if target_port is not None:
                            match_port = (raddr_port == target_port) or (laddr_port == target_port)

                        if (match_ip or match_cidr) and match_port and pid and pid not in terminated_pids:
                            try:
                                p = psutil.Process(pid)
                                proc_name = p.name()
                                p.terminate()
                                try:
                                    p.wait(timeout=2)
                                except psutil.TimeoutExpired:
                                    p.kill()
                                    p.wait(timeout=1)
                                terminated_pids.add(pid)
                                dropped_count += 1
                                self.log_callback(f"🔪 Terminated {proc_name} (PID {pid}) → {raddr_ip or laddr_ip}:{raddr_port or laddr_port}")
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                                print(f"[DROP_CONNECTION] Could not terminate PID {pid}: {e}")
                            except Exception as e:
                                print(f"[DROP_CONNECTION] Error terminating PID {pid}: {e}")
                    except Exception:
                        continue
            except Exception as e:
                print(f"[DROP_CONNECTION] psutil scan failed: {e}")

            try:
                print("[DROP_CONNECTION] Netstat + taskkill fallback...")
                netstat_output = subprocess.run(
                    ["netstat", "-ano"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=5
                )

                if netstat_output.returncode == 0:
                    lines = netstat_output.stdout.split('\n')
                    pids_to_kill = set()

                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5:
                            try:
                                foreign_addr = parts[2] if len(parts) > 2 else ""
                                pid = parts[-1] if parts[-1].isdigit() else None

                                if ':' in foreign_addr:
                                    foreign_ip, foreign_port = foreign_addr.rsplit(':', 1)
                                    try:
                                        foreign_port = int(foreign_port)
                                    except ValueError:
                                        continue

                                    match_ip = foreign_ip in ips_to_drop
                                    match_cidr = ip_in_cidr(foreign_ip, cidr_to_drop) if cidr_to_drop else False
                                    port_ok = not target_port or foreign_port == int(target_port)
                                    if (match_ip or match_cidr) and port_ok and pid:
                                        pids_to_kill.add(pid)
                            except Exception:
                                continue

                    for pid in pids_to_kill:
                        if pid not in terminated_pids:
                            try:
                                result = subprocess.run(
                                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=3
                                )
                                if result.returncode == 0:
                                    dropped_count += 1
                                    terminated_pids.add(pid)
                                    print(f"[DROP_CONNECTION] ✅ taskkill success for PID {pid}")
                            except Exception as e:
                                print(f"[DROP_CONNECTION] taskkill exception for PID {pid}: {e}")
            except Exception as e:
                print(f"[DROP_CONNECTION] Netstat/taskkill error: {e}")

            if WMI_AVAILABLE and wmi and terminated_pids:
                try:
                    print("[DROP_CONNECTION] WMI process termination...")
                    c = wmi.WMI()
                    for pid in terminated_pids:
                        try:
                            processes = c.Win32_Process(ProcessId=pid)
                            for proc in processes:
                                proc.Terminate()
                        except Exception:
                            pass
                except Exception as e:
                    print(f"[DROP_CONNECTION] WMI error: {e}")

            print("[DROP_CONNECTION] Cleaning connection tracking...")
            with FLOW_LOCK:
                to_remove = []
                for key, flow in CONNECTION_FLOWS.items():
                    src_ip, src_port, dst_ip, dst_port, proto = key
                    ip_match = dst_ip in ips_to_drop or src_ip in ips_to_drop
                    cidr_match = False
                    if cidr_to_drop:
                        cidr_match = ip_in_cidr(dst_ip, cidr_to_drop) or ip_in_cidr(src_ip, cidr_to_drop)
                    port_match = (not target_port) or dst_port == int(target_port or 0) or src_port == int(target_port or 0)
                    if (ip_match or cidr_match) and port_match:
                        to_remove.append(key)

                for key in to_remove:
                    del CONNECTION_FLOWS[key]
                print(f"[DROP_CONNECTION] Removed {len(to_remove)} connection(s) from tracking")

            target_desc = cidr_to_drop if cidr_to_drop else (ips_to_drop[0] if len(ips_to_drop) == 1 else f"{len(ips_to_drop)} IPs")
            if dropped_count > 0:
                msg = f"✅ DROPPED {dropped_count} connection(s) to {target_desc}:{target_port or 'all'} | Firewall: BLOCKED (TCP/UDP/ICMP) | Routes: BLACKHOLED | ARP: BLOCKED | Ping: KILLED"
                print(f"[DROP_CONNECTION] {msg}")
                self.log_callback(msg)
            else:
                msg = f"🛡️ BLOCKED {target_desc}:{target_port or 'all'} (no active connections found) | Firewall: ACTIVE (TCP/UDP/ICMP) | Routes: BLACKHOLED | ARP: BLOCKED | Ping: KILLED"
                print(f"[DROP_CONNECTION] {msg}")
                self.log_callback(msg)

        except Exception as e:
            error_msg = f"⚠️ Drop connection failed: {str(e)[:100]}"
            print(f"[DROP_CONNECTION] ERROR: {e}")
            import traceback
            print(f"[DROP_CONNECTION] Traceback: {traceback.format_exc()}")
            self.log_callback(error_msg)

    def _update_config(self, data):
        """Update agent configuration"""
        global CONFIG, CLOUD_URL, ENABLE_FIREWALL_BLOCK, BATCH_SIZE, SEND_INTERVAL, FILTER_EXPR

        if 'cloud_url' in data:
            CONFIG['CLOUD_URL'] = data['cloud_url']
            CLOUD_URL = data['cloud_url']
        if 'enable_firewall_block' in data:
            CONFIG['ENABLE_FIREWALL_BLOCK'] = bool(data['enable_firewall_block'])
            ENABLE_FIREWALL_BLOCK = CONFIG['ENABLE_FIREWALL_BLOCK']
        if 'batch_size' in data:
            CONFIG['BATCH_SIZE'] = int(data['batch_size'])
            BATCH_SIZE = CONFIG['BATCH_SIZE']
        if 'send_interval' in data:
            CONFIG['SEND_INTERVAL'] = float(data['send_interval'])
            SEND_INTERVAL = CONFIG['SEND_INTERVAL']

        save_config(CONFIG)
        self.log_callback("⚙️ Configuration updated from cloud")

    def _handle_signature_update(self, data):
        """Handle signature updates from cloud and reload optimized engine"""
        global signature_engine

        if not SIGNATURE_ENGINE_AVAILABLE or not signature_engine:
            return

        try:
            root_url = CLOUD_URL.replace("/analyze", "")
            sig_url = f"{root_url}/api/signatures"
            r = requests.get(sig_url, timeout=5)

            if r.ok:
                sigs_data = r.json()
                rules = [SignatureRule(**sig) for sig in sigs_data]
                signature_engine.hot_reload(rules)
                count = len(rules)
                self.log_callback(f"🔄 Reloaded {count} signatures into optimized engine")
                print(f"[Agent] ✅ Signature engine updated with {count} rules")
            else:
                self.log_callback(f"⚠️ Failed to fetch signatures: {r.status_code}")
        except Exception as e:
            self.log_callback(f"⚠️ Signature update error: {str(e)[:50]}")
            print(f"[Agent] ⚠️ Signature update failed: {e}")

    def disconnect(self):
        """Disconnect from cloud"""
        if self.sio and self.connected:
            try:
                self.sio.disconnect()
            except Exception:
                pass

# ===============================================================
# CLOUD SENDER WITH ENHANCED FEATURES
# ===============================================================
def send_batch_to_cloud(batch, log_callback=None):
    """Send batch to cloud /analyze endpoint with retry logic"""
    headers = {"Content-Type": "application/json"}
    attempts = 3
    backoff = 1.0

    try:
        root_url = CLOUD_URL.replace("/analyze", "")
        rules_resp = requests.get(f"{root_url}/api/firewall/rules?agent_id={DEVICE_INFO['agent_id']}", timeout=3)
        if rules_resp.ok:
            rules_data = rules_resp.json()
            blocked_ips = rules_data.get("blocked_ips", [])
            blocked_domains = rules_data.get("blocked_domains", [])
            blocked_cidrs = rules_data.get("blocked_cidrs", [])

            if blocked_ips:
                update_firewall_rules(blocked_ips)
            for domain in blocked_domains:
                block_domain(domain)
            for cidr in blocked_cidrs:
                block_cidr(cidr)
    except Exception:
        pass

    for i in range(attempts):
        try:
            r = requests.post(CLOUD_URL, json=batch, headers=headers, timeout=8)
            if r.ok:
                if log_callback:
                    log_callback(f"📤 Sent {len(batch)} events to cloud")
                return True
            else:
                if log_callback:
                    log_callback(f"⚠️ Cloud returned {r.status_code} (attempt {i+1})")
        except Exception as e:
            if log_callback:
                log_callback(f"⚠️ Send attempt {i+1} failed: {str(e)[:50]}")
        time.sleep(backoff)
        backoff *= 2

    if log_callback:
        log_callback("❌ Failed to deliver batch after retries")
    return False

# ===============================================================
# CAPTURE THREAD
# ===============================================================
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
        self.batch_size = BATCH_SIZE
        self.send_interval = SEND_INTERVAL

    def run(self):
        print("[CAPTURE] Starting capture thread...")
        try:
            self.running = True
            self.status.emit(True)
            self.log.emit(f"🟢 Using filter: {FILTER_EXPR}")
            print(f"[CAPTURE] Filter: {FILTER_EXPR}")

            if pydivert is None:
                print("[CAPTURE] ERROR: pydivert not available!")
                self.log.emit("❌ pydivert not available. Capture disabled.")
                self.status.emit(False)
                self.running = False
                return

            print("[CAPTURE] pydivert available, initializing WinDivert...")
            try:
                with pydivert.WinDivert(FILTER_EXPR, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.SNIFF) as w:
                    print("[CAPTURE] WinDivert initialized successfully")
                    self.log.emit("✅ Capture active — monitoring network traffic")
                    start = time.time()

                    print("[CAPTURE] Starting packet loop...")
                    for pkt in w:
                        if not self.running:
                            print("[CAPTURE] Running flag set to False, breaking loop")
                            break

                        self.packet_count += 1
                        try:
                            self._collect(pkt)
                        except Exception as e:
                            error_msg = f"⚠️ Collection error: {str(e)[:50]}"
                            print(f"[CAPTURE] ERROR in _collect: {e}")
                            print(f"[CAPTURE] Error type: {type(e).__name__}")
                            import traceback
                            print(f"[CAPTURE] Traceback: {traceback.format_exc()}")
                            self.log.emit(error_msg)

                        if time.time() - start >= 1:
                            elapsed = time.time() - start
                            pps = self.packet_count / elapsed if elapsed else 0.0
                            self.metrics.emit(self.packet_count, self.alert_count, pps)
                            start = time.time()

                        if len(self.buffer) >= self.batch_size or (time.time() - self.last_send > self.send_interval):
                            self._flush()
            except Exception as e:
                print(f"[CAPTURE] ERROR in WinDivert context: {e}")
                print(f"[CAPTURE] Error type: {type(e).__name__}")
                import traceback
                print(f"[CAPTURE] Traceback: {traceback.format_exc()}")
                self.log.emit(f"❌ Capture error: {e}")
        except Exception as e:
            print(f"[CAPTURE] FATAL ERROR in run(): {e}")
            print(f"[CAPTURE] Error type: {type(e).__name__}")
            import traceback
            print(f"[CAPTURE] Traceback: {traceback.format_exc()}")
            self.log.emit(f"❌ Fatal capture error: {e}")
        finally:
            print("[CAPTURE] Cleaning up...")
            self._flush()
            self.status.emit(False)
            self.log.emit("🛑 Capture stopped")
            print("[CAPTURE] Capture thread ended")

    def _collect(self, pkt):
        try:
            print(f"[_COLLECT] Processing packet #{self.packet_count}")

            try:
                proto_raw = str(getattr(pkt, "protocol", "TCP")).upper()
                proto = {"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP"}.get(proto_raw, "TCP")
                print(f"[_COLLECT] Protocol: {proto}")
            except Exception as e:
                print(f"[_COLLECT] ERROR getting protocol: {e}")
                proto = "TCP"

            try:
                dst_port = getattr(pkt, "dst_port", 0) or 0
                print(f"[_COLLECT] dst_port: {dst_port}")
            except (AttributeError, TypeError) as e:
                print(f"[_COLLECT] ERROR getting dst_port: {e}")
                dst_port = 0

            if dst_port in (80, 8080):
                proto = "HTTP"
            elif dst_port == 443:
                proto = "HTTPS"
            elif dst_port == 53:
                proto = "DNS"
            elif dst_port == 22:
                proto = "SSH"
            elif dst_port == 3389:
                proto = "RDP"

            try:
                src_ip = getattr(pkt, "src_addr", "0.0.0.0") or "0.0.0.0"
                dst_ip = getattr(pkt, "dst_addr", "0.0.0.0") or "0.0.0.0"
                src_port = getattr(pkt, "src_port", 0) or 0
                dst_port = getattr(pkt, "dst_port", 0) or 0
                print(f"[_COLLECT] IPs: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            except (AttributeError, TypeError) as e:
                print(f"[_COLLECT] ERROR getting IPs/ports: {e}")
                print(f"[_COLLECT] Packet object type: {type(pkt)}")
                print(f"[_COLLECT] Packet attributes: {dir(pkt)}")
                return

            try:
                payload_bytes = getattr(pkt, "payload", b"") or b""
                payload_len = len(payload_bytes)
                print(f"[_COLLECT] Payload length: {payload_len}")
            except Exception as e:
                print(f"[_COLLECT] ERROR getting payload: {e}")
                payload_bytes = b""
                payload_len = 0

            try:
                is_outbound = src_ip == DEVICE_INFO.get("ip", "")
                print(f"[_COLLECT] is_outbound: {is_outbound}")
            except Exception as e:
                print(f"[_COLLECT] ERROR determining direction: {e}")
                is_outbound = True

            if is_outbound:
                bytes_sent = payload_len
                bytes_recv = 0
            else:
                bytes_sent = 0
                bytes_recv = payload_len

            global _partial_http_buffers, _partial_buffers_lock
            key = (src_ip, src_port, dst_ip, dst_port)

            try:
                payload_text = payload_bytes.decode(errors="ignore")
            except Exception:
                payload_text = ""

            with _partial_buffers_lock:
                buf = _partial_http_buffers.get(key, "")
                if payload_text:
                    buf = (buf + payload_text)[-32768:]
                _partial_http_buffers[key] = buf

            url = None
            if "\r\n\r\n" in buf:
                hdrs, _rest = buf.split("\r\n\r\n", 1)
                m = re.search(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/",
                              hdrs, flags=re.IGNORECASE | re.MULTILINE)
                host_m = re.search(r"Host:\s*([^\r\n]+)", hdrs, flags=re.IGNORECASE)

                if m:
                    method = m.group(1).upper()
                    path = m.group(2)
                    host = host_m.group(1).strip() if host_m else dst_ip
                    scheme = "https" if dst_port == 443 else "http"
                    url = f"{scheme}://{host}{path}"
                    with _partial_buffers_lock:
                        _partial_http_buffers.pop(key, None)

            if not url:
                try:
                    sni = parse_sni_from_client_hello(payload_bytes[:2048])
                    if sni:
                        DOMAIN_CACHE[dst_ip] = sni
                        scheme = "https" if dst_port == 443 else "http"
                        url = f"{scheme}://{sni}"
                except Exception:
                    pass

            if not url:
                    url = extract_url_from_text(payload_text, dst_ip, dst_port)

            try:
                process = find_process_for_socket(src_ip, src_port)
            except Exception:
                process = {}

            try:
                category = self._categorize(proto, dst_port, payload_text)
            except Exception:
                category = "Misc"

            try:
                print("[_COLLECT] Tracking connection...")
                flow = track_connection(src_ip, src_port, dst_ip, dst_port, proto)
                print(f"[_COLLECT] Flow tracked: {flow}")
            except Exception as e:
                print(f"[_COLLECT] ERROR in track_connection: {e}")
                import traceback
                print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                flow = {
                    "start_time": time.time(),
                    "packet_count": 1,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "last_seen": time.time()
                }

            try:
                with FLOW_LOCK:
                    if (src_ip, src_port, dst_ip, dst_port, proto) in CONNECTION_FLOWS:
                        CONNECTION_FLOWS[(src_ip, src_port, dst_ip, dst_port, proto)]["bytes_sent"] += bytes_sent
                        CONNECTION_FLOWS[(src_ip, src_port, dst_ip, dst_port, proto)]["bytes_recv"] += bytes_recv
            except Exception as e:
                print(f"[_COLLECT] ERROR updating flow bytes: {e}")

            try:
                cpu_percent = psutil.cpu_percent(interval=None)
            except Exception:
                cpu_percent = 0.0
            try:
                mem_percent = psutil.virtual_memory().percent
            except Exception:
                mem_percent = 0.0
            try:
                net_io = psutil.net_io_counters()
            except Exception:
                net_io = None
            try:
                disk_io = psutil.disk_io_counters()
            except Exception:
                disk_io = None

            try:
                conn_stats = get_connection_stats()
            except Exception:
                conn_stats = {"active_connections": 0}
            try:
                with FIREWALL_RULES_LOCK:
                    blocked_count = len(BLOCKED_IPS)
            except Exception:
                blocked_count = 0

            print("[_COLLECT] Creating event dictionary...")
            try:
                print("[_COLLECT] Step 1: DEVICE_INFO...")
                event = {}
                event.update(DEVICE_INFO)
                print("[_COLLECT] Step 2: Basic fields...")
                event["host"] = DEVICE_INFO.get("hostname", "unknown")
                print("[_COLLECT] Step 3: Timestamp...")
                from datetime import timezone
                event["timestamp"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                print("[_COLLECT] Step 4: IPs and ports...")
                event["src_ip"] = src_ip
                event["dst_ip"] = dst_ip
                event["protocol"] = proto
                event["port_src"] = src_port
                event["port_dst"] = dst_port
                print("[_COLLECT] Step 5: Bytes...")
                event["bytes_sent"] = bytes_sent
                event["bytes_recv"] = bytes_recv
                print("[_COLLECT] Step 6: Region and category...")
                event["region"] = DEVICE_INFO.get("region", "Unknown")
                event["category"] = category
                print("[_COLLECT] Step 7: URL...")
                event["url"] = url or f"{proto.lower()}://{dst_ip}:{dst_port}"
                print("[_COLLECT] Step 8: Process...")
                event["process"] = process
                event["detection_source"] = "agent"
                print("[_COLLECT] Step 9: System metrics...")
                event["system_metrics"] = {
                    "cpu_percent": cpu_percent,
                    "memory_percent": mem_percent,
                    "network_bytes_sent_total": net_io.bytes_sent if net_io else 0,
                    "network_bytes_recv_total": net_io.bytes_recv if net_io else 0,
                    "network_packets_sent": net_io.packets_sent if net_io else 0,
                    "network_packets_recv": net_io.packets_recv if net_io else 0,
                    "disk_read_bytes": disk_io.read_bytes if disk_io else 0,
                    "disk_write_bytes": disk_io.write_bytes if disk_io else 0,
                }
                print("[_COLLECT] Step 10: Flow data...")
                event["flow_id"] = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                event["connection_duration"] = time.time() - flow["start_time"]
                event["flow_packet_count"] = flow["packet_count"]
                event["flow_bytes_sent"] = flow["bytes_sent"]
                event["flow_bytes_recv"] = flow["bytes_recv"]
                print("[_COLLECT] Step 11: Network context...")
                event["active_connections_count"] = conn_stats["active_connections"]
                event["blocked_ips_count"] = blocked_count
                print("[_COLLECT] Step 12: Metadata...")
                event["packet_timestamp"] = time.time()
                event["is_outbound"] = is_outbound
                print("[_COLLECT] Event dictionary created successfully!")
            except Exception as e:
                print(f"[_COLLECT] ERROR creating event dictionary at step: {e}")
                print(f"[_COLLECT] Error type: {type(e).__name__}")
                import traceback
                print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                raise

            print("[_COLLECT] Step 13: Checking firewall rules...")
            print(f"[_COLLECT] dst_ip: {dst_ip}, url: {url}")
            try:
                print("[_COLLECT] Calling check_firewall_block...")
                if dst_ip:
                    print(f"[_COLLECT] Checking if {dst_ip} is blocked...")
                    is_blocked = check_firewall_block(dst_ip)
                    print(f"[_COLLECT] check_firewall_block returned: {is_blocked}")
                    if is_blocked:
                        print("[_COLLECT] IP is blocked, setting alert...")
                        event["alert"] = True
                        event["reason"] = f"Blocked IP: {dst_ip} (firewall rule)"
                        event["detection_source"] = "firewall"
                if url and not event.get("alert"):
                    print(f"[_COLLECT] Checking if domain {url} is blocked...")
                    is_domain_blocked = check_domain_block(url)
                    print(f"[_COLLECT] check_domain_block returned: {is_domain_blocked}")
                    if is_domain_blocked:
                        print("[_COLLECT] Domain is blocked, setting alert...")
                        event["alert"] = True
                        event["reason"] = f"Blocked domain: {url} (firewall rule)"
                        event["detection_source"] = "firewall"
                print("[_COLLECT] Firewall check completed")
            except Exception as e:
                print(f"[_COLLECT] ERROR in firewall check: {e}")
                import traceback
                print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                pass

            print("[_COLLECT] Step 14: Threat detection...")
            if signature_engine:
                try:
                    match = signature_engine.match(event)
                    if match:
                        event["alert"] = True
                        event["reason"] = f"Matched signature: {match.pattern} (Severity: {match.severity})"
                        event["detection_source"] = "signature"
                        print(f"[_COLLECT] Signature match: {match.pattern}")
                except Exception as e:
                    print(f"[_COLLECT] ERROR in signature matching: {e}")

            if not event.get("alert"):
                try:
                    event["alert"], event["reason"] = detect_threat(event)
                    print(f"[_COLLECT] Threat detection result: alert={event.get('alert')}, reason={event.get('reason')}")
                except Exception as e:
                    print(f"[_COLLECT] ERROR in detect_threat: {e}")
                    import traceback
                    print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                    event["alert"] = False
                    event["reason"] = "benign"

            print("[_COLLECT] Step 15: Processing alerts...")
            if event.get("alert"):
                try:
                    print("[_COLLECT] Alert detected, emitting signal...")
                    self.alert_count += 1
                    self.alert.emit({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "host": dst_ip,
                        "reason": event.get("reason", "Unknown threat")
                    })
                    print("[_COLLECT] Alert signal emitted")
                    if ENABLE_FIREWALL_BLOCK and dst_ip:
                        try:
                            print("[_COLLECT] Blocking IP in firewall...")
                            block_ip(dst_ip)
                        except Exception as e:
                            print(f"[_COLLECT] ERROR blocking IP: {e}")
                            pass
                    try:
                        print("[_COLLECT] Notifying cloud about blocked IP...")
                        root_url = CLOUD_URL.replace("/analyze", "")
                        requests.post(f"{root_url}/api/firewall/block",
                                    json={"ip": dst_ip, "agent_id": DEVICE_INFO["agent_id"],
                                          "reason": event.get("reason", "Threat detected")}, timeout=2)
                    except Exception as e:
                        print(f"[_COLLECT] ERROR notifying cloud: {e}")
                        pass
                except Exception as e:
                    print(f"[_COLLECT] ERROR in alert processing: {e}")
                    import traceback
                    print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                    pass

            print("[_COLLECT] Step 16: Adding event to buffer...")
            try:
                self.buffer.append(event)
                print(f"[_COLLECT] Event added to buffer (size: {len(self.buffer)})")
            except Exception as e:
                print(f"[_COLLECT] ERROR adding to buffer: {e}")
                import traceback
                print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                raise
        except Exception as e:
            print(f"[_COLLECT] FATAL ERROR in _collect: {e}")
            print(f"[_COLLECT] Error type: {type(e).__name__}")
            import traceback
            print(f"[_COLLECT] Full traceback: {traceback.format_exc()}")
            self.log.emit(f"⚠️ Fatal collection error: {str(e)[:50]}")

    def _categorize(self, proto, port, payload_text):
        try:
            proto = str(proto).upper() if proto else "TCP"
            payload_lower = str(payload_text).lower() if payload_text else ""

            if port == 80 or "http" in payload_lower:
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
            if "login" in payload_lower or "password" in payload_lower:
                return "Credential Transfer"
            return proto or "Misc"
        except Exception:
            return "Misc"

    def _flush(self):
        if not self.buffer:
            return
        batch = self.buffer[:]
        self.buffer.clear()
        self.last_send = time.time()
        threading.Thread(
            target=lambda: send_batch_to_cloud(batch, log_callback=lambda m: self.log.emit(m)),
            daemon=True
        ).start()

    def stop(self):
        self.running = False
