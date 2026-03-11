# ===============================================================
# QuantumDefender Cloud v9.0 — Next-Gen Advanced SOC Platform
# Author: Ali Kadir Bulut
# Katowice Institute of Information Technologies
# ===============================================================
# Features:
# ✅ Asynchronous event ingestion queue (non-blocking)
# ✅ Batch database writes for scalability
# ✅ Enhanced hybrid detection (agent + signature + ML)
# ✅ Cached DNS/Region enrichment
# ✅ Live stats broadcasting for UI dashboard
# ✅ Real-time connection monitoring
# ✅ Advanced threat intelligence & correlation
# ✅ Device performance metrics & health monitoring
# ✅ Automated response rules engine
# ✅ Threat timeline & correlation analysis
# ===============================================================
# pip install flask flask-socketio onnxruntime numpy requests
import threading
from collections import defaultdict, deque
import math
import time
import os, json, sqlite3, threading, time, requests, socket, re
import numpy as np
from datetime import datetime
from flask import Flask, request, jsonify, g, render_template
from flask_socketio import SocketIO
import onnxruntime as ort
from datetime import datetime, timezone, timedelta
from cloud.schemas import IngestBatch, SignatureRule
from cloud.ingestion.queue import InMemoryQueue
from cloud.storage.sqlite_store import SQLiteEventStore, SQLiteSignatureStore

# Import optimized signature matcher
try:
    from cloud.services.signature_matcher import CloudSignatureMatcher, get_cloud_matcher
    CLOUD_MATCHER_AVAILABLE = True
except ImportError:
    # Fallback if module not found
    CLOUD_MATCHER_AVAILABLE = False
    CloudSignatureMatcher = None
    get_cloud_matcher = None

# ---------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------
HOST = "0.0.0.0"
PORT = 5000
DB_PATH = "cloud_store.db"
ONNX_MODEL = "lite_model.onnx"
ALERT_THRESHOLD = 0.85
SIGNATURE_REFRESH = 60
MAX_EVENTS = 50000
BATCH_COMMIT_SIZE = 20
DNS_CACHE, REGION_CACHE = {}, {}
db_lock = threading.Lock()
event_queue = InMemoryQueue()
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
event_store = SQLiteEventStore(lambda: get_db(), db_lock)
signature_store = SQLiteSignatureStore(lambda: get_db(), db_lock)

socketio = SocketIO(app, cors_allowed_origins="*")
start_time = time.time()

# ---------------------------------------------------------------
# DATABASE HELPERS
# ---------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA busy_timeout=3000;")
        g.db.execute("PRAGMA journal_mode=WAL;")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("PRAGMA journal_mode=WAL;")
    db.execute("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            agent_id TEXT,
            host TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            url TEXT,
            protocol TEXT,
            bytes_sent REAL,
            bytes_recv REAL,
            region TEXT,
            category TEXT,
            alert INTEGER,
            reason TEXT,
            detection_source TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS signatures(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            pattern TEXT,
            severity TEXT,
            source TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            value TEXT NOT NULL,
            port INTEGER,
            mode TEXT DEFAULT 'drop',
            created_at TEXT
        )
    """)
    # Ensure legacy databases have the new 'mode' column
    try:
        db.execute("ALTER TABLE firewall_rules ADD COLUMN mode TEXT DEFAULT 'drop'")
    except sqlite3.OperationalError:
        # Column already exists or table just created
        pass
    db.commit()

def rotate_db():
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    if count > MAX_EVENTS:
        excess = count - MAX_EVENTS
        with db_lock:
            db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)", (excess,))
            db.commit()

# ---------------------------------------------------------------
# MODEL LOADING
# ---------------------------------------------------------------
model_start = time.time()
if not os.path.exists(ONNX_MODEL):
    raise SystemExit("❌ Model file missing — please place lite_model.onnx in working directory.")

try:
    sess = ort.InferenceSession(ONNX_MODEL)
    print(f"[+] Loaded ONNX model in {time.time()-model_start:.2f}s: {ONNX_MODEL}")
except Exception as e:
    raise SystemExit(f"❌ Failed to load model: {e}")

# ---------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------
def readable_bytes(num):
    for unit in ['B','KB','MB','GB']:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"

def enrich_url(url_or_ip, dst_ip="", port=0):
    if not url_or_ip or url_or_ip in ("N/A","unknown","None"):
        url_or_ip = dst_ip or ""
    if re.search(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", str(url_or_ip)):
        if not str(url_or_ip).startswith(("http://","https://")):
            scheme = "https" if str(port) == "443" else "http"
            return f"{scheme}://{url_or_ip}"
        return url_or_ip
    domain = dst_ip or url_or_ip
    if not domain: return "http://unknown"
    if domain in DNS_CACHE:
        resolved = DNS_CACHE[domain]
    else:
        try:
            resolved = socket.gethostbyaddr(domain)[0]
        except Exception:
            resolved = domain
        DNS_CACHE[domain] = resolved
    scheme = "https" if str(port) == "443" else "http"
    return f"{scheme}://{resolved}"

def lookup_region(ip):
    if not ip: return "Unknown"
    if ip.startswith(("127.","10.","192.168.","172.")): return "Local Network"
    entry = REGION_CACHE.get(ip)
    if entry and (time.time()-entry["ts"]) < 600:
        return entry["region"]
    region = "Unknown"
    try:
        r = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=1.5)
        if r.ok: region = r.text.strip() or "Unknown"
    except Exception:
        region = "Unknown"
    REGION_CACHE[ip] = {"region": region, "ts": time.time()}
    return region

def enrich_category(url):
    if not url: return "General"
    u = url.lower()
    if any(k in u for k in ["login","auth"]): return "Authentication"
    if any(k in u for k in ["bank","finance","paypal"]): return "Finance"
    if any(k in u for k in ["cdn","image","media","video"]): return "Media"
    if any(k in u for k in ["update","patch","download"]): return "Software Update"
    return "General"

# ---------------------------------------------------------------
# ML FEEDBACK & SIGNATURE GENERATION SYSTEM
# ---------------------------------------------------------------
sig_cache, sig_last_update = [], 0
ml_detected_patterns = deque(maxlen=1000)  # Store ML-detected anomalies for pattern analysis
pattern_analysis_queue = deque(maxlen=500)  # Queue for signature generation
signature_generation_enabled = True
MIN_PATTERN_OCCURRENCES = 3  # Minimum occurrences to generate signature
PATTERN_ANALYSIS_INTERVAL = 300  # Analyze patterns every 5 minutes

# Initialize optimized signature matcher
if CLOUD_MATCHER_AVAILABLE and get_cloud_matcher:
    cloud_matcher = get_cloud_matcher()
    print("[Cloud] ✅ Optimized Aho-Corasick signature matcher initialized")
else:
    cloud_matcher = None
    print("[Cloud] ⚠️ Optimized matcher unavailable, using fallback")

def refresh_signatures():
    """Refresh signature cache and reload optimized matcher"""
    global sig_cache, sig_last_update
    if time.time() - sig_last_update > SIGNATURE_REFRESH:
        sig_cache = [r.dict() for r in signature_store.fetch_all()]
        sig_last_update = time.time()
        
        # Reload optimized matcher with new signatures
        if cloud_matcher:
            try:
                cloud_matcher.load_signatures(sig_cache)
                print(f"[Cloud] ✅ Reloaded {len(sig_cache)} signatures into optimized matcher")
            except Exception as e:
                print(f"[Cloud] ⚠️ Error reloading optimized matcher: {e}")
        
        # Notify agents of signature updates
        socketio.emit("signature_update", {
            "count": len(sig_cache), 
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "optimized": cloud_matcher is not None
        })

def match_signature(payload):
    """
    Match payload against signatures using optimized Aho-Corasick matcher.
    Falls back to linear search if optimized matcher unavailable.
    """
    refresh_signatures()
    
    # Use optimized matcher if available
    if cloud_matcher:
        try:
            match = cloud_matcher.match(payload)
            if match:
                return match
        except Exception as e:
            print(f"[Cloud] ⚠️ Optimized matcher error, falling back: {e}")
    
    # Fallback to linear search (backward compatibility)
    host = str(payload.get("host","")).lower()
    body = json.dumps(payload).lower()
    url = str(payload.get("url","")).lower()
    
    for sig in sig_cache:
        ptype, pat = sig.get("type",""), (sig.get("pattern") or "").lower()
        if ptype == "host_contains" and pat in host: 
            return sig
        if ptype == "payload_contains" and pat in body: 
            return sig
        if ptype == "ip_equals" and (payload.get("dst_ip")==pat or payload.get("ip")==pat): 
            return sig
        if ptype == "regex_contains" and re.search(pat, body): 
            return sig
        if ptype == "domain_match" and pat in url: 
            return sig
    return None

MODEL_FEATURES = [
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

def anomaly_score(event_dict):
    """Run the event through the ONNX model and return the attack probability."""
    try:
        # Build the input vector with default 0 for missing keys
        x = np.array([[float(event_dict.get(k, 0)) for k in MODEL_FEATURES]], dtype=np.float32)

        inp_name = sess.get_inputs()[0].name
        out = sess.run(None, {inp_name: x})
        attack_prob = float(out[0][0][1])  # second column = attack probability

        return attack_prob
    except Exception as e:
        print("[!] ONNX inference failed:", e)
        return np.random.rand() * 0.1  # fallback noise

def extract_pattern_from_event(event_dict, score):
    """Extract identifiable patterns from ML-detected anomaly for signature generation."""
    patterns = {}
    
    # Extract IP pattern
    dst_ip = event_dict.get("dst_ip") or event_dict.get("ip", "")
    if dst_ip and not dst_ip.startswith(("127.", "10.", "192.168.", "172.")):
        patterns["ip"] = dst_ip
    
    # Extract URL/domain pattern
    url = str(event_dict.get("url", "")).lower()
    if url:
        # Extract domain
        domain_match = re.search(r"https?://([^/]+)", url)
        if domain_match:
            patterns["domain"] = domain_match.group(1)
        # Extract path patterns
        path_match = re.search(r"https?://[^/]+(/[^?]+)", url)
        if path_match:
            patterns["path"] = path_match.group(1)
    
    # Extract port pattern
    port = event_dict.get("port_dst") or event_dict.get("Destination_Port", 0)
    if port and port > 0:
        patterns["port"] = int(port)
    
    # Extract protocol pattern
    protocol = str(event_dict.get("protocol", "")).upper()
    if protocol:
        patterns["protocol"] = protocol
    
    # Extract feature patterns (suspicious values)
    suspicious_features = {}
    if event_dict.get("Total_Fwd_Packets", 0) > 100:
        suspicious_features["high_fwd_packets"] = event_dict.get("Total_Fwd_Packets")
    if event_dict.get("Flow_Duration", 0) > 1000000:
        suspicious_features["long_duration"] = event_dict.get("Flow_Duration")
    if event_dict.get("Packet_Length_Mean", 0) > 1500:
        suspicious_features["large_packet_size"] = event_dict.get("Packet_Length_Mean")
    
    if suspicious_features:
        patterns["features"] = suspicious_features
    
    # Extract payload patterns (if available)
    payload_text = json.dumps(event_dict).lower()
    suspicious_keywords = ["malware", "exploit", "injection", "sql", "xss", "cmd", "exec"]
    found_keywords = [kw for kw in suspicious_keywords if kw in payload_text]
    if found_keywords:
        patterns["keywords"] = found_keywords
    
    return {
        "patterns": patterns,
        "score": score,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_data": {
            "dst_ip": dst_ip,
            "url": url,
            "protocol": protocol,
            "port": port
        }
    }

def analyze_patterns_for_signature_generation():
    """Analyze collected ML patterns and generate signatures if patterns are recurring."""
    if not signature_generation_enabled or len(ml_detected_patterns) < MIN_PATTERN_OCCURRENCES:
        return []
    
    # Group patterns by type
    ip_patterns = defaultdict(int)
    domain_patterns = defaultdict(int)
    port_patterns = defaultdict(int)
    url_path_patterns = defaultdict(int)
    keyword_patterns = defaultdict(int)
    
    for pattern_data in ml_detected_patterns:
        patterns = pattern_data.get("patterns", {})
        
        if "ip" in patterns:
            ip_patterns[patterns["ip"]] += 1
        if "domain" in patterns:
            domain_patterns[patterns["domain"]] += 1
        if "port" in patterns:
            port_patterns[patterns["port"]] += 1
        if "path" in patterns:
            url_path_patterns[patterns["path"]] += 1
        if "keywords" in patterns:
            for kw in patterns["keywords"]:
                keyword_patterns[kw] += 1
    
    generated_signatures = []
    
    # Generate IP-based signatures
    for ip, count in ip_patterns.items():
        if count >= MIN_PATTERN_OCCURRENCES:
            sig = {
                "type": "ip_equals",
                "pattern": ip,
                "severity": "high" if count >= 10 else "medium",
                "source": "ml_feedback"
            }
            generated_signatures.append(sig)
            print(f"[ML Feedback] Generated IP signature: {ip} (occurrences: {count})")
    
    # Generate domain-based signatures
    for domain, count in domain_patterns.items():
        if count >= MIN_PATTERN_OCCURRENCES:
            sig = {
                "type": "domain_match",
                "pattern": domain,
                "severity": "high" if count >= 10 else "medium",
                "source": "ml_feedback"
            }
            generated_signatures.append(sig)
            print(f"[ML Feedback] Generated domain signature: {domain} (occurrences: {count})")
    
    # Generate URL path signatures
    for path, count in url_path_patterns.items():
        if count >= MIN_PATTERN_OCCURRENCES:
            sig = {
                "type": "regex_contains",
                "pattern": re.escape(path),
                "severity": "medium",
                "source": "ml_feedback"
            }
            generated_signatures.append(sig)
            print(f"[ML Feedback] Generated path signature: {path} (occurrences: {count})")
    
    # Generate keyword-based signatures
    for keyword, count in keyword_patterns.items():
        if count >= MIN_PATTERN_OCCURRENCES:
            sig = {
                "type": "payload_contains",
                "pattern": keyword,
                "severity": "high" if count >= 10 else "medium",
                "source": "ml_feedback"
            }
            generated_signatures.append(sig)
            print(f"[ML Feedback] Generated keyword signature: {keyword} (occurrences: {count})")
    
    return generated_signatures

def generate_and_deploy_signatures(signatures):
    """Generate and deploy new signatures to agents."""
    deployed_count = 0
    for sig in signatures:
        try:
            # Check if signature already exists
            existing = signature_store.fetch_all()
            pattern_exists = any(
                s.pattern == sig["pattern"] and s.type == sig["type"] 
                for s in existing
            )
            
            if not pattern_exists:
                signature_store.save(SignatureRule(**sig))
                deployed_count += 1
                print(f"[Signature Generation] Deployed new signature: {sig['type']} -> {sig['pattern']}")
        except Exception as e:
            print(f"[Signature Generation] Error deploying signature: {e}")
    
    if deployed_count > 0:
        # Refresh signature cache
        refresh_signatures()
        # Notify all agents of new signatures
        socketio.emit("signature_update", {
            "new_signatures": deployed_count,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        print(f"[Signature Generation] Deployed {deployed_count} new signatures to agents")
    
    return deployed_count

# ---------------------------------------------------------------
# THIRD-PARTY API INTEGRATION LAYER
# ---------------------------------------------------------------
THIRD_PARTY_APIS = {
    "abuseipdb": {
        "enabled": False,
        "api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
        "endpoint": "https://api.abuseipdb.com/api/v2/check"
    },
    "virustotal": {
        "enabled": False,
        "api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
        "endpoint": "https://www.virustotal.com/vtapi/v2/url/report"
    },
    "alienvault": {
        "enabled": False,
        "api_key": os.getenv("ALIENVAULT_API_KEY", ""),
        "endpoint": "https://otx.alienvault.com/api/v1/indicators"
    }
}

def fetch_external_threat_intelligence(ip=None, url=None, domain=None):
    """Fetch threat intelligence from third-party APIs."""
    threat_data = {
        "sources": [],
        "reputation": "unknown",
        "threat_indicators": [],
        "signature_candidates": []
    }
    
    # AbuseIPDB check
    if THIRD_PARTY_APIS["abuseipdb"]["enabled"] and ip:
        try:
            headers = {
                "Key": THIRD_PARTY_APIS["abuseipdb"]["api_key"],
                "Accept": "application/json"
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            r = requests.get(
                THIRD_PARTY_APIS["abuseipdb"]["endpoint"],
                headers=headers,
                params=params,
                timeout=5
            )
            if r.ok:
                data = r.json()
                if data.get("data", {}).get("abuseConfidencePercentage", 0) > 50:
                    threat_data["sources"].append("abuseipdb")
                    threat_data["reputation"] = "malicious"
                    threat_data["threat_indicators"].append({
                        "type": "ip_reputation",
                        "value": ip,
                        "confidence": data["data"]["abuseConfidencePercentage"]
                    })
                    # Generate signature candidate
                    threat_data["signature_candidates"].append({
                        "type": "ip_equals",
                        "pattern": ip,
                        "severity": "high",
                        "source": "abuseipdb"
                    })
        except Exception as e:
            print(f"[Third-Party API] AbuseIPDB error: {e}")
    
    # VirusTotal check (for URLs/domains)
    if THIRD_PARTY_APIS["virustotal"]["enabled"] and (url or domain):
        try:
            target = url or domain
            params = {
                "apikey": THIRD_PARTY_APIS["virustotal"]["api_key"],
                "resource": target
            }
            r = requests.get(
                THIRD_PARTY_APIS["virustotal"]["endpoint"],
                params=params,
                timeout=10
            )
            if r.ok:
                data = r.json()
                if data.get("response_code") == 1:
                    positives = data.get("positives", 0)
                    if positives > 0:
                        threat_data["sources"].append("virustotal")
                        threat_data["reputation"] = "malicious"
                        threat_data["threat_indicators"].append({
                            "type": "url_reputation",
                            "value": target,
                            "positives": positives,
                            "total": data.get("total", 0)
                        })
                        # Generate signature candidate
                        if domain:
                            threat_data["signature_candidates"].append({
                                "type": "domain_match",
                                "pattern": domain,
                                "severity": "high" if positives > 5 else "medium",
                                "source": "virustotal"
                            })
        except Exception as e:
            print(f"[Third-Party API] VirusTotal error: {e}")
    
    return threat_data

def process_external_threat_data(threat_data):
    """Process external threat intelligence and generate signatures."""
    if not threat_data.get("signature_candidates"):
        return 0
    
    deployed = 0
    for candidate in threat_data["signature_candidates"]:
        try:
            # Check if signature already exists
            existing = signature_store.fetch_all()
            pattern_exists = any(
                s.pattern == candidate["pattern"] and s.type == candidate["type"]
                for s in existing
            )
            
            if not pattern_exists:
                signature_store.save(SignatureRule(**candidate))
                deployed += 1
                print(f"[Third-Party API] Generated signature from external source: {candidate['source']} -> {candidate['pattern']}")
        except Exception as e:
            print(f"[Third-Party API] Error processing threat data: {e}")
    
    if deployed > 0:
        refresh_signatures()
        socketio.emit("signature_update", {
            "new_signatures": deployed,
            "source": "third_party",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    return deployed

def periodic_pattern_analysis():
    """Periodic worker to analyze ML patterns and generate signatures."""
    with app.app_context():
        while True:
            try:
                if len(ml_detected_patterns) >= MIN_PATTERN_OCCURRENCES:
                    print(f"[Pattern Analysis] Analyzing {len(ml_detected_patterns)} ML-detected patterns...")
                    signatures = analyze_patterns_for_signature_generation()
                    if signatures:
                        deployed = generate_and_deploy_signatures(signatures)
                        if deployed > 0:
                            # Clear analyzed patterns to avoid duplicates
                            ml_detected_patterns.clear()
                time.sleep(PATTERN_ANALYSIS_INTERVAL)
            except Exception as e:
                print(f"[Pattern Analysis] Error: {e}")
                time.sleep(60)

# ---------------------------------------------------------------
# ASYNC EVENT PROCESSOR
# ---------------------------------------------------------------
def process_event(data):
    db = get_db()
    ts = data.get("timestamp", datetime.utcnow().isoformat() + "Z")
    rotate_db()

    # Normalize protocol
    proto_raw = str(data.get("protocol", "")).upper()
    proto_map = {"HTTPS": "HTTP", "SSL": "HTTP", "TCP": "TCP", "UDP": "UDP"}
    protocol = proto_map.get(proto_raw, proto_raw or "UNKNOWN")

    alert, reason, detection_source = False, "benign", "agent"
    score = 0.0

    # Stage 1: Agent heuristic
    if bool(data.get("alert")) or str(data.get("alert")).lower() in ("true", "1", "yes"):
        alert, reason, detection_source = True, f"Agent heuristic: {data.get('reason', 'unknown')}", "agent"
    # Stage 2: Signature match
    elif (sig := match_signature(data)):
        alert, reason, detection_source = True, f"Matched signature: {sig['pattern']} (Severity {sig.get('severity', 'N/A')})", "signature"
    # Stage 3: ML/Anomaly
    else:
        score = anomaly_score(data)
        url_l = str(data.get("url", "")).lower()
        if "malware" in url_l or int(data.get("port_dst", 0)) == 3389:
            score = max(score, 0.95)
            reason = "Heuristic override: known malicious indicator"
            detection_source = "heuristic"
            alert = True
        elif score >= ALERT_THRESHOLD:
            alert, reason, detection_source = True, f"Statistical anomaly (score={score:.2f})", "ml"
            
            # ML FEEDBACK MECHANISM: Extract patterns from ML-detected anomalies
            if signature_generation_enabled:
                pattern_data = extract_pattern_from_event(data, score)
                ml_detected_patterns.append(pattern_data)
                
                # Check third-party APIs for additional threat intelligence
                dst_ip = data.get("dst_ip") or data.get("ip", "")
                url = data.get("url", "")
                domain = None
                if url:
                    domain_match = re.search(r"https?://([^/]+)", url)
                    if domain_match:
                        domain = domain_match.group(1)
                
                if dst_ip or domain:
                    threat_intel = fetch_external_threat_intelligence(ip=dst_ip, url=url, domain=domain)
                    if threat_intel.get("reputation") == "malicious":
                        # Process external threat data and generate signatures
                        process_external_threat_data(threat_intel)

    region = data.get("region") or lookup_region(data.get("src_ip", ""))
    category = data.get("category") or enrich_category(data.get("url", ""))

    evt = {
        "ts": ts, "agent_id": data.get("agent_id", "unknown-agent"),
        "host": data.get("hostname") or data.get("host") or "unknown-host",
        "src_ip": data.get("src_ip", ""), "dst_ip": data.get("dst_ip", data.get("ip", "")),
        "url": enrich_url(data.get("url"), data.get("dst_ip"), data.get("port_dst")),
        "protocol": protocol, "bytes_sent": data.get("bytes_sent", 0),
        "bytes_recv": data.get("bytes_recv", 0), "region": region,
        "category": category, "alert": int(alert), "reason": reason,
        "detection_source": detection_source
    }

    # Retry up to 5 times if database is locked
    for attempt in range(5):
        try:
            event_store.save_event(evt)
            break
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                time.sleep(0.1)
            else:
                raise

    ui_evt = {
        "timestamp": ts, "agent_id": evt["agent_id"], "host": evt["host"],
        "src_ip": evt["src_ip"], "dst_ip": evt["dst_ip"], "protocol": evt["protocol"],
        "bytes_sent": float(evt["bytes_sent"]), "bytes_recv": float(evt["bytes_recv"]),
        "bytes_sent_formatted": readable_bytes(evt["bytes_sent"]), 
        "bytes_recv_formatted": readable_bytes(evt["bytes_recv"]),
        "region": evt["region"], "url": evt["url"], "category": evt["category"],
        "score": round(float(score), 3),
        "alert": bool(alert), "reason": reason,
        "detection_source": detection_source
    }

    socketio.emit("new_event", ui_evt)


def event_worker():
    with app.app_context():  # app context required for get_db()
        for evt in event_queue.consume():
            try:
                process_event(evt)
            except Exception as e:
                print("[!] Worker error:", e)



# ---------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------
@app.route("/health")
def health():
    uptime = round(time.time() - start_time, 1)
    return jsonify({"status":"ok","uptime_sec":uptime})

@app.route("/stats")
def stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    alerts = db.execute("SELECT COUNT(*) FROM events WHERE alert=1").fetchone()[0]
    agents = db.execute("SELECT COUNT(DISTINCT agent_id) FROM events").fetchone()[0]
    rows = db.execute("SELECT detection_source, COUNT(*) AS cnt FROM events GROUP BY detection_source").fetchall()
    breakdown = {r["detection_source"] or "unknown": r["cnt"] for r in rows}
    return jsonify({"total_events": total, "total_alerts": alerts, "unique_agents": agents, "breakdown": breakdown})

@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(force=True)
    # Validate via schema; accept legacy list for backward compatibility
    if isinstance(payload, list):
        events = payload
    else:
        batch = IngestBatch(events=payload if isinstance(payload, list) else payload)
        events = [e.dict() for e in batch.events]
    for event in events:
        event_queue.put(event)

    socketio.emit("ingest_ack", {"count": len(events), "ts": datetime.utcnow().isoformat() + "Z"})
    print(f"[CLOUD] Queued {len(events)} events for processing")
    return jsonify({"status": "queued", "count": len(events)}), 202


@app.route("/new_signature", methods=["POST"])
def new_signature():
    sig = request.get_json(force=True)
    if not {"type","pattern"}.issubset(sig.keys()):
        return jsonify({"error":"Missing required fields"}),400
    signature_store.save(SignatureRule(**sig))
    socketio.emit("sig_update", sig)
    return jsonify({"status":"ok"})
# ---------------------------------------------------------------
# SIGNATURE MANAGEMENT API (for Dashboard UI)
# ---------------------------------------------------------------
@app.route("/api/signatures")
def api_get_signatures():
    """Return all signatures as JSON for dashboard display."""
    sigs = [
        {
            "id": r.id,
            "type": r.type,
            "pattern": r.pattern,
            "severity": r.severity.capitalize() if r.severity else "Low",
            "source": r.source,
            "name": f"{r.type} → {r.pattern}"
        }
        for r in signature_store.fetch_all()
    ]
    return jsonify(sigs)

@app.route("/api/add_signature", methods=["POST"])
def api_add_signature():
    """Add new signature from dashboard form."""
    sig = request.get_json(force=True)
    # Accept flexible keys (name/rule/severity or type/pattern)
    sig_type = sig.get("type") or "payload_contains"
    pattern = sig.get("pattern") or sig.get("rule") or ""
    severity = sig.get("severity", "Low")
    source = sig.get("source", "manual")
    if not pattern:
        return jsonify({"error": "Pattern or rule is required"}), 400

    signature_store.save(SignatureRule(type=sig_type, pattern=pattern, severity=severity.lower(), source=source))
    socketio.emit("sig_update", sig)
    return jsonify({"status": "ok", "message": "Signature added"})

# ---------------------------------------------------------------
# FIREWALL RULES API - Send blocking rules to agents
# ---------------------------------------------------------------
firewall_rules = {}  # {agent_id: {"ips": [...], "domains": [...], "cidrs": [...]}}

@app.route("/api/firewall/rules", methods=["GET"])
def get_firewall_rules():
    """Get all firewall rules for agents"""
    agent_id = request.args.get("agent_id")
    if agent_id:
        rules = firewall_rules.get(agent_id, {"ips": [], "domains": [], "cidrs": []})
        return jsonify({"agent_id": agent_id, "rules": rules})
    return jsonify({"rules": firewall_rules})

@app.route("/api/firewall/block", methods=["POST"])
def block_ip_firewall():
    """Block an IP address and notify all agents or specific agent"""
    data = request.get_json(force=True)
    ip = data.get("ip")
    agent_id = data.get("agent_id")  # Optional: specific agent or "all"
    reason = data.get("reason", "Malicious activity detected")
    domain = data.get("domain")
    cidr = data.get("cidr")
    port = data.get("port")
    mode = (data.get("mode") or "drop").lower()
    if mode not in ("drop", "page", "allow"):
        mode = "drop"

    if not ip and not domain and not cidr:
        return jsonify({"error": "IP, domain, or CIDR required"}), 400

    targets = []
    if agent_id:
        targets.append(agent_id)
    else:
        # When no agent_id specified, apply to special "all" bucket
        targets.append("all")

    db = get_db()
    now = datetime.utcnow().isoformat() + "Z"

    for aid in targets:
        if aid not in firewall_rules or not isinstance(firewall_rules[aid], dict):
            firewall_rules[aid] = {"ips": [], "domains": [], "cidrs": []}
        rules = firewall_rules[aid]

        if ip and ip not in rules["ips"]:
            rules["ips"].append(ip)
            db.execute(
                "INSERT INTO firewall_rules (agent_id, rule_type, value, port, mode, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (aid, "ip", ip, port, mode, now),
            )

        if domain and domain not in rules["domains"]:
            rules["domains"].append(domain)
            db.execute(
                "INSERT INTO firewall_rules (agent_id, rule_type, value, port, mode, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (aid, "domain", domain, port, mode, now),
            )

        if cidr and cidr not in rules["cidrs"]:
            rules["cidrs"].append(cidr)
            db.execute(
                "INSERT INTO firewall_rules (agent_id, rule_type, value, port, mode, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (aid, "cidr", cidr, port, mode, now),
            )

    db.commit()

    # Emit firewall rule to agents via socketio
    socketio.emit("firewall_rule", {
        "action": "block",
        "ip": ip,
        "domain": domain,
        "cidr": cidr,
        "port": port,
        "mode": mode,
        "reason": reason,
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })
    
    return jsonify({"status": "blocked", "ip": ip, "domain": domain, "cidr": cidr, "port": port, "reason": reason})

@app.route("/api/firewall/unblock", methods=["POST"])
def unblock_ip_firewall():
    """Unblock an IP address"""
    data = request.get_json(force=True)
    ip = data.get("ip")
    domain = data.get("domain")
    cidr = data.get("cidr")
    agent_id = data.get("agent_id")

    if not ip and not domain and not cidr:
        return jsonify({"error": "IP, domain, or CIDR required"}), 400

    db = get_db()

    targets = [agent_id] if agent_id else list(firewall_rules.keys())
    for aid in targets:
        rules = firewall_rules.get(aid)
        if not isinstance(rules, dict):
            continue
        if ip and ip in rules.get("ips", []):
            rules["ips"].remove(ip)
            db.execute(
                "DELETE FROM firewall_rules WHERE agent_id=? AND rule_type='ip' AND value=?",
                (aid, ip),
            )
        if domain and domain in rules.get("domains", []):
            rules["domains"].remove(domain)
            db.execute(
                "DELETE FROM firewall_rules WHERE agent_id=? AND rule_type='domain' AND value=?",
                (aid, domain),
            )
        if cidr and cidr in rules.get("cidrs", []):
            rules["cidrs"].remove(cidr)
            db.execute(
                "DELETE FROM firewall_rules WHERE agent_id=? AND rule_type='cidr' AND value=?",
                (aid, cidr),
            )

    db.commit()

    socketio.emit("firewall_rule", {
        "action": "unblock",
        "ip": ip,
        "domain": domain,
        "cidr": cidr,
        "agent_id": agent_id,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })
    
    return jsonify({"status": "unblocked", "ip": ip, "domain": domain, "cidr": cidr})

@app.route("/api/firewall/summary", methods=["GET"])
def firewall_summary():
    """Get aggregated firewall statistics for dashboard"""
    db = get_db()
    rows = db.execute(
        "SELECT rule_type, COUNT(*) as cnt FROM firewall_rules GROUP BY rule_type"
    ).fetchall()
    total_ips = total_domains = total_cidrs = 0
    for r in rows:
        if r["rule_type"] == "ip":
            total_ips = r["cnt"]
        elif r["rule_type"] == "domain":
            total_domains = r["cnt"]
        elif r["rule_type"] == "cidr":
            total_cidrs = r["cnt"]
    total_rules = total_ips + total_domains + total_cidrs
    return jsonify({
        "total_rules": total_rules,
        "ips": total_ips,
        "domains": total_domains,
        "cidrs": total_cidrs
    })

@app.route("/api/firewall/rules/flat", methods=["GET"])
def firewall_rules_flat():
    """Return firewall rules as a flat list for UI"""
    db = get_db()
    rows = db.execute(
        "SELECT agent_id, rule_type, value, port, mode FROM firewall_rules ORDER BY id DESC"
    ).fetchall()
    flat = []
    for r in rows:
        scope = r["agent_id"] or "all"
        item = {
            "scope": scope,
            "type": r["rule_type"],
            "value": r["value"],
            "mode": r["mode"] or "drop",
        }
        if r["port"] is not None:
            item["port"] = r["port"]
        flat.append(item)
    return jsonify(flat)

# ---------------------------------------------------------------
# ENHANCED ANALYTICS ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/analytics/timeline")
def analytics_timeline():
    """Get timeline data for charts"""
    db = get_db()
    hours = []
    events_data = []
    alerts_data = []
    
    for i in range(24):
        hour = (datetime.now() - timedelta(hours=23-i)).strftime("%Y-%m-%d %H:00")
        count = db.execute("SELECT COUNT(*) FROM events WHERE ts LIKE ?", (f"{hour[:13]}%",)).fetchone()[0]
        alert_count = db.execute("SELECT COUNT(*) FROM events WHERE alert=1 AND ts LIKE ?", (f"{hour[:13]}%",)).fetchone()[0]
        hours.append(hour[-5:])  # Just HH:MM
        events_data.append(count)
        alerts_data.append(alert_count)
    
    return jsonify({
        "labels": hours,
        "events": events_data,
        "alerts": alerts_data
    })

@app.route("/api/analytics/protocols")
def analytics_protocols():
    """Get protocol distribution"""
    db = get_db()
    rows = db.execute("SELECT protocol, COUNT(*) as cnt FROM events GROUP BY protocol ORDER BY cnt DESC LIMIT 10").fetchall()
    return jsonify({r["protocol"]: r["cnt"] for r in rows})

@app.route("/api/analytics/top_threats")
def analytics_top_threats():
    """Get top threats by count"""
    db = get_db()
    rows = db.execute("SELECT reason, COUNT(*) as cnt FROM events WHERE alert=1 GROUP BY reason ORDER BY cnt DESC LIMIT 10").fetchall()
    return jsonify([{"threat": r["reason"], "count": r["cnt"]} for r in rows])

@app.route("/api/analytics/agent_activity")
def analytics_agent_activity():
    """Get agent activity metrics"""
    db = get_db()
    rows = db.execute("""
        SELECT agent_id, COUNT(*) as total, 
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts
        FROM events 
        GROUP BY agent_id 
        ORDER BY total DESC 
        LIMIT 20
    """).fetchall()
    return jsonify([{
        "agent_id": r["agent_id"],
        "total_events": r["total"],
        "alerts": r["alerts"]
    } for r in rows])

@app.route("/api/analytics/geographic")
def analytics_geographic():
    """Get geographic distribution"""
    db = get_db()
    rows = db.execute("SELECT region, COUNT(*) as cnt FROM events GROUP BY region ORDER BY cnt DESC LIMIT 20").fetchall()
    return jsonify({r["region"]: r["cnt"] for r in rows})

# ---------------------------------------------------------------
# THREAT INTELLIGENCE ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/threats/intel")
def threat_intel():
    """Get comprehensive threat intelligence"""
    db = get_db()
    
    # Top malicious IPs
    malicious_ips = db.execute("""
        SELECT dst_ip, COUNT(*) as cnt 
        FROM events 
        WHERE alert=1 
        GROUP BY dst_ip 
        ORDER BY cnt DESC 
        LIMIT 10
    """).fetchall()
    
    # Top malicious URLs
    malicious_urls = db.execute("""
        SELECT url, COUNT(*) as cnt 
        FROM events 
        WHERE alert=1 AND url != '' 
        GROUP BY url 
        ORDER BY cnt DESC 
        LIMIT 10
    """).fetchall()
    
    # Threat patterns
    threat_patterns = db.execute("""
        SELECT reason, COUNT(*) as cnt 
        FROM events 
        WHERE alert=1 
        GROUP BY reason 
        ORDER BY cnt DESC 
        LIMIT 10
    """).fetchall()
    
    return jsonify({
        "malicious_ips": [{"ip": r["dst_ip"], "count": r["cnt"]} for r in malicious_ips],
        "malicious_urls": [{"url": r["url"], "count": r["cnt"]} for r in malicious_urls],
        "threat_patterns": [{"pattern": r["reason"], "count": r["cnt"]} for r in threat_patterns],
        "last_updated": datetime.utcnow().isoformat() + "Z"
    })

@app.route("/api/threats/check_ip", methods=["POST"])
def check_ip_threat():
    """Check if an IP is known malicious"""
    data = request.get_json(force=True)
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP required"}), 400
    
    db = get_db()
    alerts = db.execute("SELECT COUNT(*) as cnt FROM events WHERE dst_ip=? AND alert=1", (ip,)).fetchone()[0]
    is_malicious = alerts > 0
    
    return jsonify({
        "ip": ip,
        "is_malicious": is_malicious,
        "alert_count": alerts,
        "threat_level": "high" if alerts > 10 else "medium" if alerts > 5 else "low" if alerts > 0 else "none"
    })

# ---------------------------------------------------------------
# DEVICE MANAGEMENT API
# ---------------------------------------------------------------
connected_agents = {}  # {agent_id: {socket_id, hostname, ip, last_seen, status}}

@socketio.on("agent_register")
def handle_agent_register(data):
    """Agent registers with cloud"""
    agent_id = data.get("agent_id")
    if agent_id:
        connected_agents[agent_id] = {
            "socket_id": request.sid,
            "hostname": data.get("hostname", "unknown"),
            "ip": data.get("ip", "unknown"),
            "os": data.get("os", "unknown"),
            "region": data.get("region", "unknown"),
            "last_seen": time.time(),
            "status": "online"
        }
        socketio.emit("agent_registered", {"agent_id": agent_id}, room=request.sid)
        print(f"[CLOUD] Agent registered: {agent_id} ({data.get('hostname')})")

@socketio.on("disconnect")
def handle_disconnect():
    """Handle agent disconnect"""
    for agent_id, info in list(connected_agents.items()):
        if info.get("socket_id") == request.sid:
            connected_agents[agent_id]["status"] = "offline"
            connected_agents[agent_id]["last_seen"] = time.time()
            print(f"[CLOUD] Agent disconnected: {agent_id} (socket {request.sid})")

@socketio.on("agent_heartbeat")
def handle_agent_heartbeat(data):
    """Update agent last_seen timestamp"""
    agent_id = data.get("agent_id")
    if agent_id and agent_id in connected_agents:
        connected_agents[agent_id]["last_seen"] = time.time()
        connected_agents[agent_id]["status"] = "online"

@app.route("/api/devices", methods=["GET"])
def get_devices():
    """Get all connected devices/agents"""
    # Update status based on last_seen
    current_time = time.time()
    for agent_id, info in connected_agents.items():
        if current_time - info["last_seen"] > 300:  # 5 minutes
            info["status"] = "offline"
        else:
            info["status"] = "online"
    
    devices = []
    for agent_id, info in connected_agents.items():
        db = get_db()
        stats = db.execute("""
            SELECT COUNT(*) as total, 
                   SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts
            FROM events WHERE agent_id=?
        """, (agent_id,)).fetchone()
        
        devices.append({
            "agent_id": agent_id,
            "hostname": info.get("hostname", "unknown"),
            "ip": info.get("ip", "unknown"),
            "os": info.get("os", "unknown"),
            "region": info.get("region", "unknown"),
            "status": info.get("status", "offline"),
            "last_seen": info.get("last_seen", 0),
            "socket_id": info.get("socket_id"),
            "total_events": stats[0] if stats else 0,
            "total_alerts": stats[1] if stats else 0
        })
    
    return jsonify(sorted(devices, key=lambda x: x["last_seen"], reverse=True))

@app.route("/api/devices/<agent_id>/send_notification", methods=["POST"])
def send_notification_to_device(agent_id):
    """Send notification to specific device"""
    data = request.get_json(force=True)
    title = data.get("title", "QuantumDefender")
    message = data.get("message", "")
    duration = data.get("duration", 5000)
    
    if agent_id not in connected_agents:
        return jsonify({"error": "Agent not found"}), 404
    
    socket_id = connected_agents[agent_id].get("socket_id")
    if socket_id:
        # Emit both formats for compatibility
        socketio.emit("notification", {
            "title": title,
            "message": message,
            "duration": duration
        }, room=socket_id)
        # Also emit as agent_command for consistency
        socketio.emit("agent_command", {
            "command": "show_notification",
            "params": {
                "title": title,
                "message": message,
                "duration": duration
            }
        }, room=socket_id)
        print(f"[CLOUD] Sent notification to agent {agent_id} (socket {socket_id})")
        return jsonify({"status": "sent", "agent_id": agent_id, "title": title, "message": message})
    
    return jsonify({"error": "Agent not connected"}), 400

@app.route("/api/devices/<agent_id>/drop_connection", methods=["POST"])
def drop_connection_device(agent_id):
    """Drop connection on specific device"""
    data = request.get_json(force=True)
    target_ip = data.get("ip")
    target_domain = data.get("domain")
    target_cidr = data.get("cidr")
    target_port = data.get("port")
    
    if not target_ip and not target_domain and not target_cidr:
        return jsonify({"error": "IP address, domain, or CIDR required"}), 400
    
    if agent_id not in connected_agents:
        return jsonify({"error": "Agent not found"}), 404
    
    socket_id = connected_agents[agent_id].get("socket_id")
    if socket_id:
        # Emit both formats for compatibility
        drop_data = {}
        if target_ip:
            drop_data["ip"] = target_ip
        if target_domain:
            drop_data["domain"] = target_domain
        if target_cidr:
            drop_data["cidr"] = target_cidr
        if target_port:
            drop_data["port"] = target_port
        
        socketio.emit("drop_connection", drop_data, room=socket_id)
        # Also emit as agent_command for consistency
        socketio.emit("agent_command", {
            "command": "drop_connection",
            "params": drop_data
        }, room=socket_id)
        print(f"[CLOUD] Sent drop_connection command to agent {agent_id} for {target_ip or target_domain or target_cidr}:{target_port or 'all'}")
        return jsonify({"status": "sent", "agent_id": agent_id, **drop_data})
    
    return jsonify({"error": "Agent not connected"}), 400

@app.route("/api/devices/<agent_id>/update_config", methods=["POST"])
def update_device_config(agent_id):
    """Update configuration on specific device"""
    data = request.get_json(force=True)
    
    if not data:
        return jsonify({"error": "Configuration data required"}), 400
    
    if agent_id not in connected_agents:
        return jsonify({"error": "Agent not found"}), 404
    
    socket_id = connected_agents[agent_id].get("socket_id")
    if socket_id:
        socketio.emit("agent_command", {
            "command": "update_config",
            "params": data
        }, room=socket_id)
        print(f"[CLOUD] Sent update_config command to agent {agent_id}: {data}")
        return jsonify({"status": "sent", "agent_id": agent_id, "config": data})
    
    return jsonify({"error": "Agent not connected"}), 400

@app.route("/api/devices/<agent_id>/restart_capture", methods=["POST"])
def restart_capture_device(agent_id):
    """Restart capture on specific device"""
    if agent_id not in connected_agents:
        return jsonify({"error": "Agent not found"}), 404
    
    socket_id = connected_agents[agent_id].get("socket_id")
    if socket_id:
        socketio.emit("agent_command", {
            "command": "restart_capture",
            "params": {}
        }, room=socket_id)
        print(f"[CLOUD] Sent restart_capture command to agent {agent_id}")
        return jsonify({"status": "sent", "agent_id": agent_id, "message": "Restart capture command sent"})
    
    return jsonify({"error": "Agent not connected"}), 400

@app.route("/api/devices/<agent_id>/info", methods=["GET"])
def get_device_info(agent_id):
    """Get detailed info about a device"""
    if agent_id not in connected_agents:
        return jsonify({"error": "Agent not found"}), 404
    
    info = connected_agents[agent_id].copy()
    db = get_db()
    
    # Get recent events
    recent = db.execute("""
        SELECT * FROM events 
        WHERE agent_id=? 
        ORDER BY ts DESC 
        LIMIT 10
    """, (agent_id,)).fetchall()
    
    # Get statistics
    stats = db.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts,
            COUNT(DISTINCT dst_ip) as unique_destinations,
            SUM(bytes_sent) as total_bytes_sent,
            SUM(bytes_recv) as total_bytes_recv
        FROM events WHERE agent_id=?
    """, (agent_id,)).fetchone()
    
    info["statistics"] = {
        "total_events": stats[0] if stats else 0,
        "total_alerts": stats[1] if stats else 0,
        "unique_destinations": stats[2] if stats else 0,
        "total_bytes_sent": stats[3] if stats else 0,
        "total_bytes_recv": stats[4] if stats else 0
    }
    
    info["recent_events"] = [dict(row) for row in recent]
    
    return jsonify(info)

@app.route("/")
def home():
    return "<meta http-equiv='refresh' content='0;url=/ui'>"

@app.route("/ui")
def ui():
    return render_template("index.html")

# ---------------------------------------------------------------
# STARTUP TASKS
# ---------------------------------------------------------------
def periodic_stats():
    with app.app_context():
        while True:
            try:
                db = get_db()
                total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                alerts = db.execute("SELECT COUNT(*) FROM events WHERE alert=1").fetchone()[0]
                socketio.emit("stats_update", {"total": total, "alerts": alerts})
            except Exception as e:
                print("[!] Stats broadcast error:", e)
            time.sleep(15)


# ---------------------------------------------------------------
# ENHANCED ANALYTICS ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/analytics/enhanced")
def analytics_enhanced():
    """Get enhanced analytics with time range and agent filtering"""
    time_range = request.args.get('time_range', '24h')
    agent_filter = request.args.get('agent', 'all')
    
    db = get_db()
    
    # Calculate time delta
    if time_range == '1h':
        delta = timedelta(hours=1)
    elif time_range == '6h':
        delta = timedelta(hours=6)
    elif time_range == '7d':
        delta = timedelta(days=7)
    elif time_range == '30d':
        delta = timedelta(days=30)
    else:
        delta = timedelta(hours=24)
    
    since = datetime.now(timezone.utc) - delta
    since_str = since.strftime("%Y-%m-%d %H:%M:%S")
    
    # Build query
    query = "SELECT * FROM events WHERE ts >= ?"
    params = [since_str]
    
    if agent_filter != 'all':
        query += " AND agent_id = ?"
        params.append(agent_filter)
    
    # Get totals
    total_events = db.execute(f"SELECT COUNT(*) FROM ({query})", params).fetchone()[0]
    total_alerts = db.execute(f"SELECT COUNT(*) FROM ({query} AND alert=1)", params).fetchone()[0]
    
    # Get average threat score (using alert count as proxy)
    avg_score = db.execute(f"SELECT AVG(CASE WHEN alert=1 THEN 0.9 ELSE 0.1 END) FROM ({query})", params).fetchone()[0] or 0.0
    
    # Get unique IPs
    unique_ips = db.execute(f"SELECT COUNT(DISTINCT dst_ip) FROM ({query})", params).fetchone()[0]
    
    # Get top destinations
    top_dest = db.execute(f"""
        SELECT dst_ip as destination, COUNT(*) as cnt, 
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alert_count
        FROM ({query})
        GROUP BY dst_ip
        ORDER BY cnt DESC
        LIMIT 10
    """, params).fetchall()
    
    # Get peak activity by hour
    peak_activity = db.execute(f"""
        SELECT strftime('%H', ts) as hour, COUNT(*) as cnt
        FROM ({query})
        GROUP BY hour
        ORDER BY hour
    """, params).fetchall()
    
    return jsonify({
        "total_events": total_events,
        "total_alerts": total_alerts,
        "avg_threat_score": float(avg_score),
        "unique_ips": unique_ips,
        "events_change": 0.0,  # Could calculate from previous period
        "alerts_change": 0.0,
        "top_destinations": [{"destination": r["destination"], "count": r["cnt"], "alert_count": r["alert_count"]} for r in top_dest],
        "peak_activity": [{"hour": r["hour"] + ":00", "count": r["cnt"]} for r in peak_activity]
    })

@app.route("/api/analytics/export")
def analytics_export():
    """Export analytics data"""
    time_range = request.args.get('time_range', '24h')
    # Similar logic to enhanced, return full dataset
    return jsonify({"message": "Export functionality", "time_range": time_range})

# ---------------------------------------------------------------
# ENHANCED THREAT INTELLIGENCE ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/threats/check", methods=["POST"])
def threats_check():
    """Check threat for IP or URL"""
    data = request.get_json(force=True)
    input_val = data.get("input", "")
    
    if not input_val:
        return jsonify({"error": "Input required"}), 400
    
    db = get_db()
    
    # Check if it's an IP or URL
    is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', input_val)
    
    if is_ip:
        alerts = db.execute("SELECT COUNT(*) as cnt FROM events WHERE dst_ip=? AND alert=1", (input_val,)).fetchone()[0]
        first_seen = db.execute("SELECT MIN(ts) FROM events WHERE dst_ip=?", (input_val,)).fetchone()[0]
        last_seen = db.execute("SELECT MAX(ts) FROM events WHERE dst_ip=?", (input_val,)).fetchone()[0]
    else:
        alerts = db.execute("SELECT COUNT(*) as cnt FROM events WHERE url LIKE ? AND alert=1", (f"%{input_val}%",)).fetchone()[0]
        first_seen = db.execute("SELECT MIN(ts) FROM events WHERE url LIKE ?", (f"%{input_val}%",)).fetchone()[0]
        last_seen = db.execute("SELECT MAX(ts) FROM events WHERE url LIKE ?", (f"%{input_val}%",)).fetchone()[0]
    
    threat_level = "high" if alerts > 10 else "medium" if alerts > 5 else "low" if alerts > 0 else "none"
    
    return jsonify({
        "input": input_val,
        "threat_level": threat_level,
        "alert_count": alerts,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "related_threats": []
    })

@app.route("/api/threats/malicious_ips")
def threats_malicious_ips():
    """Get list of malicious IPs"""
    db = get_db()
    rows = db.execute("""
        SELECT dst_ip as ip, COUNT(*) as cnt,
               MIN(ts) as first_seen, MAX(ts) as last_seen
        FROM events
        WHERE alert=1
        GROUP BY dst_ip
        ORDER BY cnt DESC
        LIMIT 50
    """).fetchall()
    
    return jsonify([{
        "ip": r["ip"],
        "count": r["cnt"],
        "threat_level": "high" if r["cnt"] > 10 else "medium" if r["cnt"] > 5 else "low",
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"]
    } for r in rows])

@app.route("/api/threats/suspicious_urls")
def threats_suspicious_urls():
    """Get list of suspicious URLs"""
    db = get_db()
    rows = db.execute("""
        SELECT url, COUNT(*) as cnt,
               MIN(ts) as first_seen, MAX(ts) as last_seen
        FROM events
        WHERE alert=1 AND url != ''
        GROUP BY url
        ORDER BY cnt DESC
        LIMIT 50
    """).fetchall()
    
    return jsonify([{
        "url": r["url"],
        "count": r["cnt"],
        "threat_level": "high" if r["cnt"] > 10 else "medium" if r["cnt"] > 5 else "low",
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"]
    } for r in rows])

@app.route("/api/threats/patterns")
def threats_patterns():
    """Get threat patterns"""
    db = get_db()
    rows = db.execute("""
        SELECT reason as pattern, COUNT(*) as cnt,
               MAX(ts) as last_seen
        FROM events
        WHERE alert=1 AND reason != ''
        GROUP BY reason
        ORDER BY cnt DESC
        LIMIT 20
    """).fetchall()
    
    return jsonify([{
        "pattern": r["pattern"],
        "count": r["cnt"],
        "severity": "High" if r["cnt"] > 10 else "Medium" if r["cnt"] > 5 else "Low",
        "last_seen": r["last_seen"]
    } for r in rows])

@app.route("/api/threats/history")
def threats_history():
    """Get threat history"""
    limit = request.args.get('limit', 50)
    db = get_db()
    rows = db.execute("""
        SELECT id, ts as timestamp, reason as threat, dst_ip as ip,
               agent_id, 0.9 as score
        FROM events
        WHERE alert=1
        ORDER BY ts DESC
        LIMIT ?
    """, (limit,)).fetchall()
    
    return jsonify([{
        "event_id": r["id"],
        "timestamp": r["timestamp"],
        "threat": r["threat"],
        "ip": r["ip"],
        "agent_id": r["agent_id"],
        "score": r["score"]
    } for r in rows])

@app.route("/api/threats/stats")
def threats_stats():
    """Get threat statistics"""
    db = get_db()
    critical = db.execute("SELECT COUNT(*) FROM events WHERE alert=1 AND (reason LIKE '%critical%' OR reason LIKE '%high%')").fetchone()[0]
    active_ips = db.execute("SELECT COUNT(DISTINCT dst_ip) FROM events WHERE alert=1").fetchone()[0]
    suspicious_urls = db.execute("SELECT COUNT(DISTINCT url) FROM events WHERE alert=1 AND url != ''").fetchone()[0]
    
    return jsonify({
        "critical": critical,
        "active_ips": active_ips,
        "suspicious_urls": suspicious_urls
    })

@app.route("/api/threats/export")
def threats_export():
    """Export threat intelligence data"""
    db = get_db()
    threats = db.execute("SELECT * FROM events WHERE alert=1 ORDER BY ts DESC LIMIT 1000").fetchall()
    return jsonify([dict(r) for r in threats])

# ---------------------------------------------------------------
# ENHANCED AGENTS ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/agents/enhanced")
def agents_enhanced():
    """Get enhanced agent statistics"""
    db = get_db()
    total = db.execute("SELECT COUNT(DISTINCT agent_id) FROM events").fetchone()[0]
    
    # Count online/offline based on recent activity (last 5 minutes)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    online = db.execute("SELECT COUNT(DISTINCT agent_id) FROM events WHERE ts >= ?", (cutoff,)).fetchone()[0]
    offline = total - online
    
    # Calculate average health (based on alert ratio)
    health_data = db.execute("""
        SELECT agent_id, 
               COUNT(*) as total,
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts
        FROM events
        GROUP BY agent_id
    """).fetchall()
    
    if health_data:
        avg_health = sum([100 * (1 - (r["alerts"] / max(r["total"], 1))) for r in health_data]) / len(health_data)
    else:
        avg_health = 100
    
    return jsonify({
        "total": total,
        "online": online,
        "offline": offline,
        "avg_health": round(avg_health, 1)
    })

@app.route("/api/agents/export")
def agents_export():
    """Export agent data"""
    db = get_db()
    agents = db.execute("""
        SELECT agent_id, COUNT(*) as total_events,
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as total_alerts,
               MIN(ts) as first_seen, MAX(ts) as last_seen
        FROM events
        GROUP BY agent_id
    """).fetchall()
    return jsonify([dict(r) for r in agents])

# ---------------------------------------------------------------
# ENHANCED SIGNATURES ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/signatures/stats")
def signatures_stats():
    """Get signature statistics"""
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    active = db.execute("SELECT COUNT(*) FROM signatures WHERE id IN (SELECT DISTINCT id FROM signatures)").fetchone()[0]  # All are active for now
    high_severity = db.execute("SELECT COUNT(*) FROM signatures WHERE severity='High'").fetchone()[0]
    
    # Count matches today (approximate)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    matches_today = db.execute("SELECT COUNT(*) FROM events WHERE alert=1 AND ts LIKE ?", (f"{today}%",)).fetchone()[0]
    
    return jsonify({
        "total": total,
        "active": active,
        "matches_today": matches_today,
        "high_severity": high_severity
    })

@app.route("/api/signatures/test", methods=["POST"])
def signatures_test():
    """Test a signature rule against test data"""
    data = request.get_json(force=True)
    rule = data.get("rule", "")
    test_data = data.get("test_data", "")
    
    if not rule or not test_data:
        return jsonify({"error": "Rule and test_data required"}), 400
    
    try:
        import re
        pattern = re.compile(rule)
        match = pattern.search(test_data)
        
        if match:
            return jsonify({
                "matched": True,
                "groups": list(match.groups()) if match.groups() else []
            })
        else:
            return jsonify({"matched": False})
    except Exception as e:
        return jsonify({"matched": False, "error": str(e)})

@app.route("/api/signatures/import", methods=["POST"])
def signatures_import():
    """Import signatures from JSON"""
    data = request.get_json(force=True)
    db = get_db()
    imported = 0
    
    if isinstance(data, list):
        for sig in data:
            try:
                db.execute("""
                    INSERT INTO signatures (type, pattern, severity, source)
                    VALUES (?, ?, ?, ?)
                """, (sig.get("type", "url"), sig.get("pattern", ""), sig.get("severity", "Medium"), "imported"))
                imported += 1
            except:
                pass
    db.commit()
    
    return jsonify({"imported": imported})

@app.route("/api/signatures/export")
def signatures_export():
    """Export all signatures"""
    db = get_db()
    sigs = db.execute("SELECT * FROM signatures").fetchall()
    return jsonify([dict(r) for r in sigs])

# ---------------------------------------------------------------
# ENHANCED DEVICE MANAGEMENT ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/devices/stats")
def devices_stats():
    """Get device statistics"""
    total = len(connected_agents)
    active_connections = sum([len(agent.get("connections", [])) for agent in connected_agents.values()])

    db = get_db()
    # Count all firewall rules stored in SQL
    blocked_count = db.execute("SELECT COUNT(*) FROM firewall_rules").fetchone()[0]
    total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    return jsonify({
        "total": total,
        "active_connections": active_connections,
        "blocked_ips": blocked_count,
        "total_events": total_events
    })

@app.route("/api/devices/export")
def devices_export():
    """Export device data"""
    db = get_db()
    fw_rows = db.execute(
        "SELECT agent_id, rule_type, value, port, mode, created_at FROM firewall_rules"
    ).fetchall()
    serialized_fw = [
        {
            "agent_id": r["agent_id"],
            "type": r["rule_type"],
            "value": r["value"],
            "port": r["port"],
            "mode": r["mode"] or "drop",
            "created_at": r["created_at"],
        }
        for r in fw_rows
    ]
    return jsonify({
        "devices": list(connected_agents.values()),
        "firewall_rules": serialized_fw
    })

# ---------------------------------------------------------------
# BULK ACTIONS ENDPOINT
# ---------------------------------------------------------------
@app.route("/api/bulk/execute", methods=["POST"])
def bulk_execute():
    """Execute bulk actions"""
    data = request.get_json(force=True)
    action = data.get("action")
    items = data.get("items", [])
    
    processed = 0
    
    if action == "block_ip":
        for item in items:
            try:
                # Add to firewall rules (in-memory and SQL) with default 'drop' mode
                if "all" not in firewall_rules:
                    firewall_rules["all"] = {"ips": [], "domains": [], "cidrs": []}
                if item not in firewall_rules["all"]["ips"]:
                    firewall_rules["all"]["ips"].append(item)
                    db = get_db()
                    db.execute(
                        "INSERT INTO firewall_rules (agent_id, rule_type, value, port, mode, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        ("all", "ip", item, None, "drop", datetime.utcnow().isoformat() + "Z"),
                    )
                    db.commit()
                # Emit to all agents
                socketio.emit("firewall_rule", {
                    "action": "block",
                    "ip": item,
                    "agent_id": "all",
                    "reason": "Bulk block from dashboard",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
                processed += 1
            except Exception as e:
                print(f"[!] Bulk block failed for {item}: {e}")
                pass
    elif action == "send_notification":
        for item in items:
            try:
                if item in connected_agents:
                    socketio.emit("notification", {
                        "title": "Bulk Notification",
                        "message": "This is a bulk notification"
                    }, room=connected_agents[item]["socket_id"])
                    processed += 1
            except:
                pass
    elif action == "restart_capture":
        for item in items:
            try:
                if item in connected_agents:
                    socketio.emit("agent_command", {
                        "type": "restart_capture"
                    }, room=connected_agents[item]["socket_id"])
                    processed += 1
            except:
                pass
    
    return jsonify({"processed": processed, "total": len(items)})

# ---------------------------------------------------------------
# REAL-TIME CONNECTION MONITORING API
# ---------------------------------------------------------------
@app.route("/api/connections/active")
def get_active_connections():
    """Get all active connections across all agents"""
    db = get_db()
    # Get recent connections (last 5 minutes)
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    connections = db.execute("""
        SELECT agent_id, src_ip, dst_ip, protocol, port_dst, 
               SUM(bytes_sent) as total_bytes_sent,
               SUM(bytes_recv) as total_bytes_recv,
               COUNT(*) as packet_count,
               MAX(ts) as last_seen
        FROM events
        WHERE ts >= ?
        GROUP BY agent_id, src_ip, dst_ip, protocol, port_dst
        ORDER BY last_seen DESC
        LIMIT 100
    """, (cutoff,)).fetchall()
    
    return jsonify([{
        "agent_id": r["agent_id"],
        "src_ip": r["src_ip"],
        "dst_ip": r["dst_ip"],
        "protocol": r["protocol"],
        "port": r["port_dst"],
        "bytes_sent": r["total_bytes_sent"],
        "bytes_recv": r["total_bytes_recv"],
        "packet_count": r["packet_count"],
        "last_seen": r["last_seen"]
    } for r in connections])

@app.route("/api/connections/health")
def get_connection_health():
    """Get connection health metrics"""
    db = get_db()
    # Last hour metrics
    hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    
    total_connections = db.execute("""
        SELECT COUNT(DISTINCT dst_ip) FROM events WHERE ts >= ?
    """, (hour_ago,)).fetchone()[0]
    
    suspicious_connections = db.execute("""
        SELECT COUNT(DISTINCT dst_ip) FROM events 
        WHERE ts >= ? AND alert=1
    """, (hour_ago,)).fetchone()[0]
    
    top_destinations = db.execute("""
        SELECT dst_ip, COUNT(*) as cnt, 
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts
        FROM events WHERE ts >= ?
        GROUP BY dst_ip
        ORDER BY cnt DESC
        LIMIT 10
    """, (hour_ago,)).fetchall()
    
    return jsonify({
        "total_unique_connections": total_connections,
        "suspicious_connections": suspicious_connections,
        "health_score": max(0, 100 - (suspicious_connections / max(total_connections, 1) * 100)),
        "top_destinations": [{
            "ip": r["dst_ip"],
            "connection_count": r["cnt"],
            "alert_count": r["alerts"]
        } for r in top_destinations]
    })

# ---------------------------------------------------------------
# ADVANCED THREAT INTELLIGENCE & CORRELATION
# ---------------------------------------------------------------
@app.route("/api/threats/correlation")
def threat_correlation():
    """Get threat correlation analysis"""
    db = get_db()
    # Last 24 hours
    day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    
    # Find correlated threats (same IP, multiple agents)
    correlated = db.execute("""
        SELECT dst_ip, COUNT(DISTINCT agent_id) as agent_count,
               COUNT(*) as event_count,
               GROUP_CONCAT(DISTINCT reason) as reasons
        FROM events
        WHERE ts >= ? AND alert=1
        GROUP BY dst_ip
        HAVING agent_count > 1
        ORDER BY agent_count DESC, event_count DESC
        LIMIT 20
    """, (day_ago,)).fetchall()
    
    # Threat patterns over time
    patterns = db.execute("""
        SELECT strftime('%H', ts) as hour, reason, COUNT(*) as cnt
        FROM events
        WHERE ts >= ? AND alert=1
        GROUP BY hour, reason
        ORDER BY hour, cnt DESC
    """, (day_ago,)).fetchall()
    
    return jsonify({
        "correlated_threats": [{
            "ip": r["dst_ip"],
            "affected_agents": r["agent_count"],
            "event_count": r["event_count"],
            "reasons": r["reasons"].split(",") if r["reasons"] else []
        } for r in correlated],
        "threat_patterns": [{
            "hour": r["hour"],
            "reason": r["reason"],
            "count": r["cnt"]
        } for r in patterns]
    })

@app.route("/api/threats/timeline")
def threat_timeline():
    """Get threat timeline for visualization"""
    db = get_db()
    hours = request.args.get('hours', 24, type=int)
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    
    timeline = db.execute("""
        SELECT strftime('%Y-%m-%d %H:00', ts) as time_slot,
               COUNT(*) as total_events,
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts,
               COUNT(DISTINCT agent_id) as unique_agents
        FROM events
        WHERE ts >= ?
        GROUP BY time_slot
        ORDER BY time_slot
    """, (cutoff,)).fetchall()
    
    return jsonify([{
        "time": r["time_slot"],
        "total_events": r["total_events"],
        "alerts": r["alerts"],
        "unique_agents": r["unique_agents"]
    } for r in timeline])

# ---------------------------------------------------------------
# DEVICE PERFORMANCE METRICS
# ---------------------------------------------------------------
@app.route("/api/devices/<agent_id>/performance")
def get_device_performance(agent_id):
    """Get device performance metrics"""
    db = get_db()
    # Last hour
    hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    
    metrics = db.execute("""
        SELECT 
            COUNT(*) as total_events,
            SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts,
            AVG(bytes_sent + bytes_recv) as avg_bytes_per_event,
            MAX(bytes_sent + bytes_recv) as max_bytes_per_event,
            COUNT(DISTINCT dst_ip) as unique_destinations,
            COUNT(DISTINCT protocol) as unique_protocols
        FROM events
        WHERE agent_id=? AND ts >= ?
    """, (agent_id, hour_ago)).fetchone()
    
    # Get recent system metrics if available
    recent_events = db.execute("""
        SELECT system_metrics FROM events
        WHERE agent_id=? AND ts >= ?
        ORDER BY ts DESC
        LIMIT 1
    """, (agent_id, hour_ago)).fetchone()
    
    system_metrics = {}
    if recent_events and recent_events[0]:
        try:
            system_metrics = json.loads(recent_events[0]) if isinstance(recent_events[0], str) else recent_events[0]
        except:
            pass
    
    return jsonify({
        "agent_id": agent_id,
        "time_range": "last_hour",
        "event_metrics": {
            "total_events": metrics[0] or 0,
            "alerts": metrics[1] or 0,
            "avg_bytes_per_event": float(metrics[2] or 0),
            "max_bytes_per_event": float(metrics[3] or 0),
            "unique_destinations": metrics[4] or 0,
            "unique_protocols": metrics[5] or 0
        },
        "system_metrics": system_metrics,
        "health_score": max(0, 100 - ((metrics[1] or 0) / max(metrics[0] or 1, 1) * 100))
    })

@app.route("/api/devices/performance/summary")
def get_all_devices_performance():
    """Get performance summary for all devices"""
    db = get_db()
    hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    
    devices = db.execute("""
        SELECT agent_id,
               COUNT(*) as total_events,
               SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts,
               AVG(bytes_sent + bytes_recv) as avg_bytes,
               COUNT(DISTINCT dst_ip) as unique_destinations
        FROM events
        WHERE ts >= ?
        GROUP BY agent_id
        ORDER BY total_events DESC
    """, (hour_ago,)).fetchall()
    
    return jsonify([{
        "agent_id": r["agent_id"],
        "total_events": r["total_events"],
        "alerts": r["alerts"],
        "avg_bytes_per_event": float(r["avg_bytes"] or 0),
        "unique_destinations": r["unique_destinations"],
        "health_score": max(0, 100 - ((r["alerts"] or 0) / max(r["total_events"] or 1, 1) * 100))
    } for r in devices])

# ---------------------------------------------------------------
# AUTOMATED RESPONSE RULES ENGINE
# ---------------------------------------------------------------
automated_rules = []  # Store automated response rules

@app.route("/api/automation/rules", methods=["GET"])
def get_automation_rules():
    """Get all automated response rules"""
    return jsonify(automated_rules)

@app.route("/api/automation/rules", methods=["POST"])
def add_automation_rule():
    """Add new automated response rule"""
    rule = request.get_json(force=True)
    rule["id"] = len(automated_rules) + 1
    rule["enabled"] = rule.get("enabled", True)
    rule["created_at"] = datetime.utcnow().isoformat() + "Z"
    automated_rules.append(rule)
    return jsonify({"status": "ok", "rule": rule})

@app.route("/api/automation/rules/<int:rule_id>", methods=["DELETE"])
def delete_automation_rule(rule_id):
    """Delete automated response rule"""
    global automated_rules
    automated_rules = [r for r in automated_rules if r.get("id") != rule_id]
    return jsonify({"status": "ok"})

@app.route("/api/automation/rules/<int:rule_id>/toggle", methods=["POST"])
def toggle_automation_rule(rule_id):
    """Toggle automation rule on/off"""
    for rule in automated_rules:
        if rule.get("id") == rule_id:
            rule["enabled"] = not rule.get("enabled", True)
            return jsonify({"status": "ok", "rule": rule})
    return jsonify({"error": "Rule not found"}), 404

# ---------------------------------------------------------------
# ADVANCED ANALYTICS ENDPOINTS
# ---------------------------------------------------------------
@app.route("/api/analytics/trends")
def analytics_trends():
    """Get trend analysis"""
    db = get_db()
    days = request.args.get('days', 7, type=int)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    
    trends = db.execute("""
        SELECT 
            DATE(ts) as date,
            COUNT(*) as total_events,
            SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts,
            COUNT(DISTINCT agent_id) as unique_agents,
            COUNT(DISTINCT dst_ip) as unique_destinations
        FROM events
        WHERE ts >= ?
        GROUP BY date
        ORDER BY date
    """, (cutoff,)).fetchall()
    
    return jsonify([{
        "date": r["date"],
        "total_events": r["total_events"],
        "alerts": r["alerts"],
        "unique_agents": r["unique_agents"],
        "unique_destinations": r["unique_destinations"]
    } for r in trends])

@app.route("/api/analytics/predictions")
def analytics_predictions():
    """Get threat prediction based on historical data"""
    db = get_db()
    # Simple prediction based on recent trends
    recent = db.execute("""
        SELECT 
            strftime('%H', ts) as hour,
            SUM(CASE WHEN alert=1 THEN 1 ELSE 0 END) as alerts
        FROM events
        WHERE ts >= datetime('now', '-7 days')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    
    # Calculate average alerts per hour
    avg_alerts = sum(r["alerts"] for r in recent) / max(len(recent), 1)
    current_hour = datetime.now().hour
    
    # Find similar hours in history
    similar_hours = [r for r in recent if abs(int(r["hour"]) - current_hour) <= 2]
    predicted = sum(r["alerts"] for r in similar_hours) / max(len(similar_hours), 1) if similar_hours else avg_alerts
    
    return jsonify({
        "predicted_alerts_next_hour": int(predicted),
        "confidence": min(100, len(similar_hours) * 10),
        "based_on": "historical_patterns",
        "current_hour": current_hour
    })

# ---------------------------------------------------------------
# API ENDPOINTS FOR ML FEEDBACK & SIGNATURE GENERATION
# ---------------------------------------------------------------
@app.route("/api/ml/feedback/stats", methods=["GET"])
def ml_feedback_stats():
    """Get ML feedback and signature generation statistics"""
    db = get_db()
    ml_detections = db.execute("SELECT COUNT(*) FROM events WHERE detection_source='ml'").fetchone()[0]
    ml_generated_sigs = db.execute("SELECT COUNT(*) FROM signatures WHERE source='ml_feedback'").fetchone()[0]
    third_party_sigs = db.execute("SELECT COUNT(*) FROM signatures WHERE source IN ('abuseipdb', 'virustotal', 'alienvault')").fetchone()[0]
    
    return jsonify({
        "ml_detections": ml_detections,
        "ml_generated_signatures": ml_generated_sigs,
        "third_party_signatures": third_party_sigs,
        "patterns_in_queue": len(ml_detected_patterns),
        "signature_generation_enabled": signature_generation_enabled
    })

@app.route("/api/ml/feedback/toggle", methods=["POST"])
def toggle_ml_feedback():
    """Enable/disable ML feedback and signature generation"""
    global signature_generation_enabled
    data = request.get_json(force=True)
    signature_generation_enabled = data.get("enabled", True)
    return jsonify({
        "status": "ok",
        "signature_generation_enabled": signature_generation_enabled
    })

@app.route("/api/ml/feedback/analyze_now", methods=["POST"])
def trigger_pattern_analysis():
    """Manually trigger pattern analysis and signature generation"""
    try:
        signatures = analyze_patterns_for_signature_generation()
        deployed = generate_and_deploy_signatures(signatures)
        return jsonify({
            "status": "ok",
            "signatures_generated": len(signatures),
            "signatures_deployed": deployed
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/third_party/configure", methods=["POST"])
def configure_third_party_apis():
    """Configure third-party API integrations"""
    data = request.get_json(force=True)
    api_name = data.get("api_name")
    enabled = data.get("enabled", False)
    api_key = data.get("api_key", "")
    
    if api_name in THIRD_PARTY_APIS:
        THIRD_PARTY_APIS[api_name]["enabled"] = enabled
        if api_key:
            THIRD_PARTY_APIS[api_name]["api_key"] = api_key
        return jsonify({
            "status": "ok",
            "api_name": api_name,
            "enabled": enabled
        })
    return jsonify({"error": "Unknown API"}), 400

@app.route("/api/third_party/status", methods=["GET"])
def third_party_api_status():
    """Get status of third-party API integrations"""
    status = {}
    for api_name, config in THIRD_PARTY_APIS.items():
        status[api_name] = {
            "enabled": config["enabled"],
            "configured": bool(config.get("api_key"))
        }
    return jsonify(status)

@app.route("/api/signatures/generated", methods=["GET"])
def get_generated_signatures():
    """Get all auto-generated signatures (ML and third-party)"""
    db = get_db()
    ml_sigs = db.execute("SELECT * FROM signatures WHERE source='ml_feedback' ORDER BY id DESC").fetchall()
    third_party_sigs = db.execute("SELECT * FROM signatures WHERE source IN ('abuseipdb', 'virustotal', 'alienvault') ORDER BY id DESC").fetchall()
    
    return jsonify({
        "ml_generated": [dict(r) for r in ml_sigs],
        "third_party_generated": [dict(r) for r in third_party_sigs],
        "total_auto_generated": len(ml_sigs) + len(third_party_sigs)
    })

@app.route("/api/signatures/matcher/stats", methods=["GET"])
def get_signature_matcher_stats():
    """Get signature matcher statistics and status"""
    db = get_db()
    total_sigs = db.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    
    stats = {
        "total_signatures": total_sigs,
        "optimized_matcher_enabled": cloud_matcher is not None,
        "matcher_type": "Aho-Corasick" if cloud_matcher else "Linear Search",
        "last_update": sig_last_update,
        "cache_size": len(sig_cache)
    }
    
    # Try to get additional stats from matcher if available
    if cloud_matcher:
        try:
            stats["matcher_loaded"] = len(cloud_matcher.signatures) if hasattr(cloud_matcher, 'signatures') else 0
        except Exception:
            pass
    
    return jsonify(stats)

if __name__ == "__main__":
    with app.app_context():
        init_db()
        # Hydrate in-memory firewall_rules cache from SQL for backwards compatibility
        try:
            db = get_db()
            rows = db.execute(
                "SELECT agent_id, rule_type, value FROM firewall_rules"
            ).fetchall()
            for r in rows:
                aid = r["agent_id"] or "all"
                if aid not in firewall_rules or not isinstance(firewall_rules.get(aid), dict):
                    firewall_rules[aid] = {"ips": [], "domains": [], "cidrs": []}
                if r["rule_type"] == "ip" and r["value"] not in firewall_rules[aid]["ips"]:
                    firewall_rules[aid]["ips"].append(r["value"])
                elif r["rule_type"] == "domain" and r["value"] not in firewall_rules[aid]["domains"]:
                    firewall_rules[aid]["domains"].append(r["value"])
                elif r["rule_type"] == "cidr" and r["value"] not in firewall_rules[aid]["cidrs"]:
                    firewall_rules[aid]["cidrs"].append(r["value"])

            # Ensure a default soft-block rule for reddit.com exists (block with page)
            existing = db.execute(
                "SELECT COUNT(*) AS cnt FROM firewall_rules WHERE rule_type='domain' AND value='reddit.com'"
            ).fetchone()
            if not existing or existing["cnt"] == 0:
                now = datetime.utcnow().isoformat() + "Z"
                db.execute(
                    "INSERT INTO firewall_rules (agent_id, rule_type, value, port, mode, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    ("all", "domain", "reddit.com", None, "page", now),
                )
                db.commit()
                # Keep in-memory cache consistent
                if "all" not in firewall_rules or not isinstance(firewall_rules.get("all"), dict):
                    firewall_rules["all"] = {"ips": [], "domains": [], "cidrs": []}
                if "reddit.com" not in firewall_rules["all"]["domains"]:
                    firewall_rules["all"]["domains"].append("reddit.com")
                # Notify connected agents so they apply the rule immediately
                socketio.emit("firewall_rule", {
                    "action": "block",
                    "ip": None,
                    "domain": "reddit.com",
                    "cidr": None,
                    "port": None,
                    "mode": "page",
                    "reason": "Default policy: block reddit.com with page",
                    "agent_id": "all",
                    "timestamp": now,
                })
        except Exception as e:
            print(f"[Cloud] ⚠️ Failed to hydrate firewall_rules from SQL: {e}")
        # Initialize signature matcher with existing signatures
        if cloud_matcher:
            try:
                initial_sigs = [r.dict() for r in signature_store.fetch_all()]
                cloud_matcher.load_signatures(initial_sigs)
                print(f"[Cloud] ✅ Loaded {len(initial_sigs)} signatures into optimized matcher")
            except Exception as e:
                print(f"[Cloud] ⚠️ Error loading initial signatures: {e}")
    
    threading.Thread(target=event_worker, daemon=True).start()
    threading.Thread(target=periodic_stats, daemon=True).start()
    threading.Thread(target=periodic_pattern_analysis, daemon=True).start()
    
    # Get network IP for remote access
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        network_ip = s.getsockname()[0]
        s.close()
    except:
        network_ip = "localhost"
    
    print(f"[+] QuantumDefender Cloud v9.0 running")
    print(f"[+] Local access:  http://127.0.0.1:{PORT}/ui")
    print(f"[+] Network access: http://{network_ip}:{PORT}/ui")
    print(f"[+] Agent endpoint: http://{network_ip}:{PORT}/analyze")
    print("[+] Async ingestion active — waiting for agent data...")
    print("[+] ML Feedback & Signature Generation: ENABLED")
    print("[+] Third-Party API Integration: Available")
    print(f"[+] Pattern Analysis Interval: {PATTERN_ANALYSIS_INTERVAL}s")
    if cloud_matcher:
        print("[+] Optimized Aho-Corasick Signature Matcher: ENABLED")
    else:
        print("[+] Signature Matching: Using fallback (linear search)")
    print(f"\n[!] Make sure Windows Firewall allows port {PORT} for network access")
    socketio.run(app, host=HOST, port=PORT, allow_unsafe_werkzeug=True)
