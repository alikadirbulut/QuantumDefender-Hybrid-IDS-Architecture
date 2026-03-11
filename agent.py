# ===============================================================
# QuantumDefender Agent v9.0 — Advanced Windows Control Edition
# ===============================================================
# Requirements:
# pip install pydivert PySide6 qdarktheme requests psutil python-socketio winotify pywin32 wmi
#
# Run on Windows with administrator privileges for capture/firewall features.
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
    "CLOUD_URL": "http://127.0.0.1:5000/analyze",
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
            # Delete existing route first if any
            subprocess.run([
                "route", "delete", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            # Add blackhole route
            subprocess.run([
                "route", "add", ip, "127.0.0.1", "metric", "1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
        except Exception:
            pass
        
        # Method 5: ARP table manipulation (block at layer 2)
        try:
            # Delete ARP entry to force re-resolution failure
            subprocess.run([
                "arp", "-d", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            # Add invalid ARP entry pointing to non-existent MAC
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
                            # Try graceful termination first
                            p.terminate()
                            try:
                                p.wait(timeout=2)
                            except psutil.TimeoutExpired:
                                # Force kill if graceful fails
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
            # Delete existing route first
            subprocess.run([
                "route", "delete", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            # Add blackhole route
            subprocess.run([
                "route", "add", ip, "127.0.0.1", "metric", "1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)
        elif action == "delete":
            # Remove route
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
                
                # Kill ping.exe or any process with ping in command line
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
            # Delete existing ARP entry
            subprocess.run([
                "arp", "-d", ip
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            # Add invalid ARP entry (points to non-existent MAC)
            subprocess.run([
                "arp", "-s", ip, "00-00-00-00-00-00"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        elif action == "delete":
            # Remove ARP entry
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
        # Very simple CIDR-domain/IP check – for HTTP use-cases CIDRs are rare, so keep it light
        for cidr in SOFT_BLOCK_CIDRS:
            try:
                # reuse existing ip_in_cidr helper if available
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
            # For destinations not in soft-block list, just show a simple info page
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

        # Very simple local logging of requests; could be extended to send to cloud
        try:
            line = f"[UNBLOCK_REQUEST] host={host!r}, user={user!r}, reason={reason!r}\n"
            print(line.strip())
            with open("qd_unblock_requests.log", "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

        # Show the same block page but with a success pill
        self._send_block_page(submitted=True)

    def log_message(self, format, *args):
        # Silence default HTTP server logging to avoid noisy console
        return


def start_block_page_server(port: int = 8899):
    """Start a lightweight local HTTP server that serves the QuantumDefender block page.

    To use it as a soft-block page, configure browser/OS to send HTTP(S) traffic
    for blocked domains through 127.0.0.1:port (e.g., via hosts/DNS + this server).
    """
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
        import socket
        # Remove protocol if present
        domain = str(domain).replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
        if not domain:
            return None
        # Skip if it's already an IP
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
        # Also create Windows firewall rules
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
        # Validate CIDR format
        ipaddress.ip_network(cidr, strict=False)
        with FIREWALL_RULES_LOCK:
            BLOCKED_CIDRS.add(cidr)
        # Create firewall rule for CIDR
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
            # Direct IP block
            if ip in BLOCKED_IPS:
                print(f"[check_firewall_block] IP {ip} found in BLOCKED_IPS")
                return True
            # CIDR block check
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
        # Silent fail on error
        pass
    return False

def check_domain_block(domain_or_url):
    """Check if domain is blocked (handles both domain and URL)"""
    print(f"[check_domain_block] Checking domain: {domain_or_url}")
    if not domain_or_url:
        print("[check_domain_block] Domain is None/empty")
        return False
    try:
        # Extract domain from URL if needed
        domain = str(domain_or_url)
        # Remove protocol
        if "://" in domain:
            domain = domain.split("://")[1]
        # Remove path and port
        domain = domain.split("/")[0].split(":")[0]
        print(f"[check_domain_block] Extracted domain: {domain}")
        
        with FIREWALL_RULES_LOCK:
            print(f"[check_domain_block] BLOCKED_DOMAINS: {BLOCKED_DOMAINS}")
            # Check if domain is directly blocked
            if domain in BLOCKED_DOMAINS:
                print(f"[check_domain_block] Domain {domain} found in BLOCKED_DOMAINS")
                return True
            # Also check resolved IP (but don't call check_firewall_block to avoid deadlock)
            print("[check_domain_block] Resolving domain to IP...")
            ip = resolve_domain_to_ip(domain)
            print(f"[check_domain_block] Resolved IP: {ip}")
            if ip:
                # Check directly without calling check_firewall_block to avoid deadlock
                if ip in BLOCKED_IPS:
                    print(f"[check_domain_block] IP {ip} found in BLOCKED_IPS")
                    return True
                # Check CIDR blocks
                for cidr in BLOCKED_CIDRS:
                    if ip_in_cidr(ip, cidr):
                        print(f"[check_domain_block] IP {ip} matches CIDR {cidr}")
                        return True
        print("[check_domain_block] Domain not blocked")
    except Exception as e:
        print(f"[check_domain_block] ERROR: {e}")
        import traceback
        print(f"[check_domain_block] Traceback: {traceback.format_exc()}")
        # Silent fail on error
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
                # Register agent
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
                    # "Allow" mode is a future override; for now just log and make sure it is not blocked locally
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

                    # Soft block with block page (HTTP/S)
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

                    # Default: hard drop (current behaviour)
                    if ip:
                        if ip not in BLOCKED_IPS:
                            update_firewall_rules([ip])
                            self.log_callback(f"🛡️ Firewall rule received: Block IP {ip}")
                            if ENABLE_FIREWALL_BLOCK:
                                # Apply broad block plus optional port-specific firewall rule
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
            # Signal to restart capture
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
            # Try Windows toast notification
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
            # STEP 1: Resolve all targets to IPs
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
            
            # Validate CIDR if provided
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
            
            # De-duplicate IPs
            ips_to_drop = list({ip for ip in ips_to_drop if ip})
            if not ips_to_drop and not cidr_to_drop:
                self.log_callback("⚠️ No valid IPs/CIDR to drop")
                return
            
            # STEP 2: IMMEDIATE FIREWALL BLOCKING (Multiple Methods) - INCLUDING ICMP
            self.log_callback("🛡️ Applying AGGRESSIVE firewall blocks (TCP/UDP/ICMP)...")
            for ip in ips_to_drop:
                try:
                    block_ip(ip)  # Uses multiple blocking methods including ICMP
                    update_firewall_rules([ip])
                    drop_connection_windows_firewall(ip, target_port)  # Blocks ICMP too
                    manipulate_route_table(ip, "add")  # Blackhole route
                    manipulate_arp_table(ip, "block")  # Block at layer 2
                    print(f"[DROP_CONNECTION] ✅ Multi-layer block applied for {ip} (ICMP included)")
                except Exception as e:
                    print(f"[DROP_CONNECTION] Firewall block failed for {ip}: {e}")
            
            # STEP 2.5: KILL ALL PING PROCESSES IMMEDIATELY
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
            
            # STEP 3: AGGRESSIVE PROCESS TERMINATION
            self.log_callback("🔪 Terminating processes...")
            dropped_count = 0
            terminated_pids = set()
            
            # Method 1: Force kill by IP/Port using Windows APIs
            for ip in ips_to_drop:
                killed = force_kill_process_by_connection(ip, target_port)
                dropped_count += killed
                print(f"[DROP_CONNECTION] Killed {killed} processes for {ip}")
            
            # Method 2: psutil comprehensive scan
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
                                # Try graceful first
                                p.terminate()
                                try:
                                    p.wait(timeout=2)
                                except psutil.TimeoutExpired:
                                    # Force kill
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
            
            # Method 3: Windows netstat + taskkill (aggressive)
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
                    
                    # Aggressive taskkill
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
            
            # Method 4: WMI process termination (if available)
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
            
            # STEP 4: Clean up connection tracking
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
            
            # STEP 5: Final status report
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
            # Fetch updated signatures from cloud
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
    
    # Check for firewall rules from cloud
    try:
        root_url = CLOUD_URL.replace("/analyze", "")
        rules_resp = requests.get(f"{root_url}/api/firewall/rules?agent_id={DEVICE_INFO['agent_id']}", timeout=3)
        if rules_resp.ok:
            rules_data = rules_resp.json()
            # Handle new format with ips, domains, cidrs
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
        pass  # Silent fail for firewall rules check
    
    for i in range(attempts):
        try:
            # Send as list to match cloud expectations
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
            # Safely get packet attributes with defaults
            try:
                proto_raw = str(getattr(pkt, "protocol", "TCP")).upper()
                proto = {"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP"}.get(proto_raw, "TCP")
                print(f"[_COLLECT] Protocol: {proto}")
            except Exception as e:
                print(f"[_COLLECT] ERROR getting protocol: {e}")
                proto = "TCP"
            
            # Safely get ports with error handling
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

            # Safely get IP addresses and ports
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
                # Skip packet if we can't get basic info
                return

            try:
                payload_bytes = getattr(pkt, "payload", b"") or b""
                payload_len = len(payload_bytes)
                print(f"[_COLLECT] Payload length: {payload_len}")
            except Exception as e:
                print(f"[_COLLECT] ERROR getting payload: {e}")
                payload_bytes = b""
                payload_len = 0
            
            # Determine if this is inbound or outbound
            try:
                is_outbound = src_ip == DEVICE_INFO.get("ip", "")
                print(f"[_COLLECT] is_outbound: {is_outbound}")
            except Exception as e:
                print(f"[_COLLECT] ERROR determining direction: {e}")
                is_outbound = True
            
            # Track bytes sent/received based on direction
            if is_outbound:
                bytes_sent = payload_len
                bytes_recv = 0
            else:
                bytes_sent = 0
                bytes_recv = payload_len

            # HTTP header reassembly
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

            # Get process info (with error handling)
            try:
                process = find_process_for_socket(src_ip, src_port)
            except Exception:
                process = {}
            
            # Categorize (with error handling)
            try:
                category = self._categorize(proto, dst_port, payload_text)
            except Exception:
                category = "Misc"

            # Track connection FIRST (before using flow data)
            try:
                print("[_COLLECT] Tracking connection...")
                flow = track_connection(src_ip, src_port, dst_ip, dst_port, proto)
                print(f"[_COLLECT] Flow tracked: {flow}")
            except Exception as e:
                print(f"[_COLLECT] ERROR in track_connection: {e}")
                import traceback
                print(f"[_COLLECT] Traceback: {traceback.format_exc()}")
                # Create a default flow
                flow = {
                    "start_time": time.time(),
                    "packet_count": 1,
                    "bytes_sent": 0,
                    "bytes_recv": 0,
                    "last_seen": time.time()
                }
            
            # Update flow bytes
            try:
                with FLOW_LOCK:
                    if (src_ip, src_port, dst_ip, dst_port, proto) in CONNECTION_FLOWS:
                        CONNECTION_FLOWS[(src_ip, src_port, dst_ip, dst_port, proto)]["bytes_sent"] += bytes_sent
                        CONNECTION_FLOWS[(src_ip, src_port, dst_ip, dst_port, proto)]["bytes_recv"] += bytes_recv
            except Exception as e:
                print(f"[_COLLECT] ERROR updating flow bytes: {e}")

            # Collect comprehensive system metrics (with error handling)
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
            
            # Get connection stats (with error handling)
            try:
                conn_stats = get_connection_stats()
            except Exception:
                conn_stats = {"active_connections": 0}
            try:
                with FIREWALL_RULES_LOCK:
                    blocked_count = len(BLOCKED_IPS)
            except Exception:
                blocked_count = 0
            
            # Enhanced event with comprehensive data
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
                raise  # Re-raise to be caught by outer try-except
            
            print("[_COLLECT] Step 13: Checking firewall rules...")
            print(f"[_COLLECT] dst_ip: {dst_ip}, url: {url}")
            # Check firewall rules (IP, domain, CIDR)
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
                # Check domain blocking
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
                # Silent fail on firewall check errors to prevent crashes
                pass
            
            print("[_COLLECT] Step 14: Threat detection...")
            # Signature-based detection (optimized Aho-Corasick)
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
            
            # Enhanced threat detection (with error handling)
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
                    # Notify cloud to add firewall rule
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
                    # Silent fail on alert processing
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
        
        # Style alerts metric differently
        self.metric_alerts.value_label.setStyleSheet("""
            color: #ff5252;
            font-size: 28px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        """)
        
        # Style blocked IPs metric
        self.metric_blocked.value_label.setStyleSheet("""
            color: #ffd54f;
            font-size: 28px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
        """)
        
        # Style signatures metric (cyan for optimized engine)
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
            global CLOUD_URL, ENABLE_FIREWALL_BLOCK, BATCH_SIZE, SEND_INTERVAL, FILTER_EXPR
            
            print("[UI] Loading config...")
            # Reload config
            CONFIG = load_config()
            CLOUD_URL = CONFIG["CLOUD_URL"]
            ENABLE_FIREWALL_BLOCK = CONFIG["ENABLE_FIREWALL_BLOCK"]
            BATCH_SIZE = CONFIG["BATCH_SIZE"]
            SEND_INTERVAL = CONFIG["SEND_INTERVAL"]
            FILTER_EXPR = CONFIG["FILTER"]
            print(f"[UI] Config loaded - CLOUD_URL: {CLOUD_URL}, FILTER: {FILTER_EXPR}")
            
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
                r = requests.post(CLOUD_URL, json=[event], timeout=8)
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
            global CONFIG, CLOUD_URL, ENABLE_FIREWALL_BLOCK, BATCH_SIZE, SEND_INTERVAL, FILTER_EXPR
            CONFIG = new_cfg
            CLOUD_URL = CONFIG["CLOUD_URL"]
            ENABLE_FIREWALL_BLOCK = CONFIG["ENABLE_FIREWALL_BLOCK"]
            BATCH_SIZE = CONFIG["BATCH_SIZE"]
            SEND_INTERVAL = CONFIG["SEND_INTERVAL"]
            FILTER_EXPR = CONFIG["FILTER"]
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
                root = CLOUD_URL
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
            # Sort by last seen
            active_flows.sort(key=lambda x: x[1]["last_seen"], reverse=True)
            
            for (src_ip, src_port, dst_ip, dst_port, proto), flow in active_flows[:20]:
                duration = time.time() - flow["start_time"]
                item_text = f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{proto}] | {flow['packet_count']} pkts | {duration:.1f}s"
                self.connection_list.addItem(item_text)

    def _load_initial_signatures(self):
        """Load initial signatures from cloud on startup"""
        global signature_engine
        
        if not SIGNATURE_ENGINE_AVAILABLE or not signature_engine:
            return
        
        try:
            time.sleep(2)  # Wait for cloud to be ready
            root_url = CLOUD_URL.replace("/analyze", "")
            sig_url = f"{root_url}/api/signatures"
            r = requests.get(sig_url, timeout=5)
            
            if r.ok:
                sigs_data = r.json()
                rules = [SignatureRule(**sig) for sig in sigs_data]
                signature_engine.load_rules(rules)
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
            # Disconnect device management
            if hasattr(self, 'device_mgmt'):
                self.device_mgmt.disconnect()
            # Stop capture
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
