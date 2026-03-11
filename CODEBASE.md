# CODEBASE.md — QuantumDefender IDS

> **Status**: Active Development (v9.0) | Academic Research Project
> **Author**: Ali Kadir Bulut — Katowice Institute of Information Technologies
> **Defense Target**: October 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Component Reference](#3-component-reference)
4. [Data Flow](#4-data-flow)
5. [Configuration](#5-configuration)
6. [Database Schema](#6-database-schema)
7. [API Reference](#7-api-reference)
8. [Dependencies](#8-dependencies)
9. [Testing](#9-testing)
10. [Shortfalls & Known Issues](#10-shortfalls--known-issues)
11. [Optimization Roadmap](#11-optimization-roadmap)
12. [Development Setup](#12-development-setup)

---

## 1. Project Overview

**QuantumDefender** is a hybrid cloud-based Intrusion Detection System (IDS) that combines:

- **Edge detection** (Windows Agent): Low-latency Aho-Corasick signature matching on live network traffic
- **Cloud intelligence** (Flask Backend): ML-based anomaly detection using ONNX inference + threat intel enrichment
- **Self-evolving signatures**: ML-detected anomalies feed back into new rule generation, deployed to agents via hot-reload

### Core Innovation

```
Packet → Local Signature Match (Aho-Corasick, ~1ms) → Cloud ML Inference (ONNX, ~10ms)
     ↓                                                          ↓
Known threats blocked immediately              Zero-day anomalies detected + patterns mined
                                                        ↓
                                         New signatures auto-generated & deployed to agents
                                         (hot-reload, no restart required)
```

---

## 2. Architecture

### System Diagram

```
┌──────────────────────────────────────────────────────┐
│                WINDOWS AGENT (Client)                 │
│                                                        │
│  [WinDivert Kernel Driver]                            │
│         │  raw packets                                 │
│         ▼                                              │
│  [Aho-Corasick Signature Engine]  ◄── hot-reload      │
│    - O(n+m+z) complexity                               │
│    - Pattern types: IP, domain, port, string, regex   │
│    - RWLock atomic rebuild on signature update         │
│         │  serialized event batch (20 events / 2s)    │
│         ▼                                              │
│  [TelemetrySender] ─── HTTP POST ──────────────────── ┼──►
│                                                        │
│  [RuleUpdater] ◄── GET /api/signatures (60s poll) ─── ┼──◄
│  [PySide6 UI]  (main.py / agent_mod.py)               │
└──────────────────────────────────────────────────────┘
         │                             ▲
         │ JSON batch                  │ updated signatures
         ▼                             │
┌──────────────────────────────────────────────────────┐
│              CLOUD BACKEND (Flask + Socket.IO)        │
│                                                        │
│  POST /analyze                                         │
│         │                                              │
│         ▼                                              │
│  [InMemoryQueue] (async batch queue)                  │
│         │                                              │
│         ▼                                              │
│  [Cloud Signature Matcher] (Aho-Corasick)             │
│         │                                              │
│         ▼                                              │
│  [OnnxModelRunner] → score > 0.85 = ALERT             │
│         │                                              │
│         ▼                                              │
│  [Threat Intel Enrichment]                            │
│    - Reverse DNS (600s cache)                         │
│    - Geo-IP via ipapi.co (cached)                     │
│    - AbuseIPDB / VirusTotal / AlienVault (disabled)   │
│         │                                              │
│         ▼                                              │
│  [SQLiteEventStore] (WAL mode, 50K event cap)         │
│         │                                              │
│         ▼                                              │
│  [SignatureGeneratorService] → mine patterns          │
│         │                                              │
│         ▼                                              │
│  [Socket.IO] → live broadcast to dashboard            │
└──────────────────────────────────────────────────────┘
         │
         ├──► AbuseIPDB / VirusTotal / AlienVault (planned)
         └──► Web Dashboard (GET /)
```

---

## 3. Component Reference

### Agent-Side

| File | Role | Notes |
|------|------|-------|
| `main.py` | PySide6 GUI launcher | Standalone UI entry point |
| `agent_mod.py` | Modular GUI launcher | Near-duplicate of main.py (see §10) |
| `agent.py` | Headless agent | Original 3,093-line monolith |
| `capture.py` | Packet capture + event serialization | Uses WinDivert; fallback import chains |
| `telemetry.py` | Batch sender | 20 events or 2s timeout, daemon thread |
| `utils.py` | Socket/process introspection | `find_process_for_socket`, `extract_url` |
| `agent/traffic_monitor/` | WinDivert integration | Kernel-level packet intercept |
| `agent/signature_engine/` | Aho-Corasick engine | Pattern types: IP, domain, port, string, regex |
| `agent/transport/http.py` | HTTP transport | Bearer token auth; TLS optional (off by default) |
| `agent/rule_updater/updater.py` | Signature fetcher | Polls cloud `/api/signatures` every 60s |
| `agent/telemetry.py` | (Duplicate) | See `telemetry.py` root |

### Cloud-Side

| File | Role | Notes |
|------|------|-------|
| `mock_cloud.py` | Flask app + all services | 2,354-line monolith (see §10) |
| `cloud/app.py` | Alternate Flask app | Partial duplicate of mock_cloud.py |
| `cloud/storage/sqlite_store.py` | SQLite event/signature stores | WAL mode, db_lock for writes |
| `cloud/ingestion/queue.py` | InMemoryQueue | Swap-ready for Kafka/Redis |
| `cloud/services/anomaly/model_runner.py` | ONNX inference | Requires lite_model.onnx |
| `cloud/services/signature_matcher.py` | Cloud Aho-Corasick | Thread-safety issue (see §10) |
| `cloud/services/signature_generator/service.py` | Pattern miner | Scaffolded, TODO |
| `cloud/services/signature_distribution/service.py` | Rule distributor | Serves `/api/signatures` |

### Test / Simulation

| File | Role | Notes |
|------|------|-------|
| `tests/unit/test_signature_engine.py` | Unit tests | Only test file; 12 tests |
| `sophisticated_test_suite.py` | Integration sim | No assertions |
| `advanced_test_runner.py` | Test runner | Integration only |
| `attack.py` | Attack simulator | 3 lines, no assertions |
| `sim_sig_attack.py` | Signature attack sim | No assertions |

---

## 4. Data Flow

### Happy-Path Detection Pipeline

```
1. WinDivert captures raw packet
2. Extract: src_ip, dst_ip, protocol, ports, payload
3. Aho-Corasick signature match (agent-side)
   ├─ HIT  → alert logged, event flagged, counter++
   └─ MISS → continue
4. Serialize event to ML feature vector
   (Destination_Port, Total_Fwd_Packets, Total_Length_of_Fwd_Packets, ...)
5. TelemetrySender: accumulate until batch_size=20 or timeout=2s
6. HTTP POST → cloud /analyze

7. [Cloud] Validate JSON schema (Pydantic)
8. [Cloud] InMemoryQueue → consumer thread
9. [Cloud] Cloud Aho-Corasick signature match (secondary)
10. [Cloud] ONNX inference → anomaly score [0.0–1.0]
    ├─ score > 0.85 → ALERT
    │   ├─ Enrich: reverse DNS, geo-IP, AbuseIPDB (if enabled)
    │   ├─ Persist to SQLite events table
    │   ├─ Broadcast via Socket.IO to dashboard
    │   └─ Optionally: POST /api/devices/<id>/drop_connection (firewall block)
    └─ score ≤ 0.85 → persist as normal
11. [Cloud] Mine patterns from high-confidence anomalies
12. [Cloud] Generate new signatures → SQLite signatures table
13. [Agent] Background RuleUpdater fetches /api/signatures (60s poll)
14. [Agent] Engine.hot_reload() → atomic Aho-Corasick rebuild via RWLock
```

### Signature Hot-Reload (No Restart)

```
[Cloud] New signature added to DB
      ↓ (up to 60s)
[Agent RuleUpdater] GET /api/signatures
      ↓
engine.hot_reload(new_rules)
      ↓
RWLock.write_acquire()
  Build new ahocorasick.Automaton()
  self._string_automaton = new_automaton  ← atomic swap
RWLock.write_release()
      ↓
All subsequent match() calls use new rules immediately
```

---

## 5. Configuration

### Agent Configuration (`config.json` / `agent_config.json`)

```json
{
  "CLOUD_URL": "http://127.0.0.1:5000/analyze",
  "BATCH_SIZE": 20,
  "SEND_INTERVAL": 2.0,
  "FILTER": "(tcp.DstPort == 80 or tcp.DstPort == 443)",
  "ENABLE_FIREWALL_BLOCK": false
}
```

**Environment overrides** (take priority over JSON):

| Variable | Default | Description |
|----------|---------|-------------|
| `QD_CLOUD_URL` | `http://127.0.0.1:5000/analyze` | Cloud endpoint |
| `QD_BATCH_SIZE` | `20` | Events per HTTP batch |
| `QD_SEND_INTERVAL` | `2.0` | Seconds between flushes |
| `QD_FILTER` | TCP 80/443 | WinDivert filter string |
| `QD_AUTH_TOKEN` | `""` | Bearer token for cloud API |
| `QD_SIGNATURE_URL` | derived | Signature fetch endpoint |
| `QD_VERIFY_TLS` | `false` | TLS certificate verification |

### Cloud Configuration (`mock_cloud.py` lines 47–54)

```python
HOST = "0.0.0.0"          # Binds all interfaces
PORT = 5000
DB_PATH = "cloud_store.db"
ONNX_MODEL = "lite_model.onnx"  # REQUIRED — hard crash if missing
ALERT_THRESHOLD = 0.85
SIGNATURE_REFRESH = 60     # Seconds between sig cache refresh
MAX_EVENTS = 50000         # Rotation cap
BATCH_COMMIT_SIZE = 20
```

> **No environment variable support exists for the cloud.** All values are hardcoded. See §11 for fix.

---

## 6. Database Schema

**File**: `cloud_store.db` (SQLite, WAL mode)

### `events`
```sql
CREATE TABLE events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT,           -- ISO 8601
    agent_id        TEXT,
    host            TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    url             TEXT,
    protocol        TEXT,
    bytes_sent      INTEGER,
    bytes_recv      INTEGER,
    region          TEXT,
    category        TEXT,
    alert           BOOLEAN,
    reason          TEXT,
    detection_source TEXT
);
```

### `signatures`
```sql
CREATE TABLE signatures (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    type     TEXT,   -- string | ip_equals | domain_match | port_equals | regex_contains
    pattern  TEXT,
    severity TEXT,   -- low | medium | high
    source   TEXT    -- manual | ml_generated | third_party
);
```

### `firewall_rules`
```sql
CREATE TABLE firewall_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT,
    rule_type  TEXT,   -- ip | domain | port
    value      TEXT,
    port       INTEGER,
    mode       TEXT,   -- drop | block
    created_at TEXT
);
```

---

## 7. API Reference

**Base URL**: `http://localhost:5000`

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `POST` | `/analyze` | Ingest event batch | None ⚠️ |
| `GET` | `/api/signatures` | Fetch all signatures | None ⚠️ |
| `GET` | `/api/threats/intel` | Threat intel data | None ⚠️ |
| `GET` | `/health` | Health check | None |
| `POST` | `/new_signature` | Add signature manually | None ⚠️ |
| `POST` | `/api/devices/<agent_id>/drop_connection` | Firewall block | None ⚠️ |
| `GET` | `/api/ml/feedback/stats` | ML performance metrics | None ⚠️ |
| `POST` | `/api/ml/feedback/analyze_now` | Trigger pattern analysis | None ⚠️ |
| `GET` | `/` | Web dashboard (HTML) | None |

> ⚠️ = No authentication. Any client can access. See §10.

### `/analyze` Payload Schema (Pydantic)

```python
class NetworkEvent(BaseModel):
    agent_id: str
    host: str
    src_ip: str
    dst_ip: str
    protocol: str
    port_dst: int
    url: Optional[str]
    bytes_sent: Optional[int]
    bytes_recv: Optional[int]
    # ML feature fields
    Destination_Port: Optional[int]
    Total_Fwd_Packets: Optional[int]
    Total_Length_of_Fwd_Packets: Optional[float]
```

---

## 8. Dependencies

### `requirements.txt` (Current — Incomplete)

```
pydivert
PySide6
requests
psutil
qdarktheme
winotify
pyahocorasick>=2.0.0
pydantic>=2.0.0
```

### Full Required Dependencies (Not All Listed)

| Package | Used For | Missing from requirements.txt |
|---------|----------|-------------------------------|
| `flask` | Cloud API | ❌ |
| `flask-socketio` | Real-time dashboard | ❌ |
| `onnxruntime` | ML inference | ❌ |
| `numpy` | Feature vectors | ❌ |
| `python-dotenv` | Env config | ❌ (not yet used) |
| `pydivert` | Kernel packet capture | ✅ |
| `PySide6` | Agent UI | ✅ |
| `pyahocorasick` | Pattern matching | ✅ |
| `pydantic` | Schema validation | ✅ |
| `requests` | HTTP client | ✅ |
| `psutil` | Process introspection | ✅ |
| `qdarktheme` | UI dark theme | ✅ |
| `winotify` | Windows notifications | ✅ |

---

## 9. Testing

### What Exists

```
tests/
└── unit/
    └── test_signature_engine.py   ← 12 tests, signature engine only
```

**Coverage estimate**: ~5% (signature engine only)

### Test Files That Are NOT Unit Tests

| File | What It Actually Is |
|------|---------------------|
| `attack.py` | 3-line HTTP request script, no assertions |
| `sim_sig_attack.py` | Attack simulator, no assertions |
| `sophisticated_test_suite.py` | Integration scenario runner, no assertions |
| `advanced_test_runner.py` | Integration runner wrapper |

### Run Tests

```bash
cd C:\Users\aliga\PyCharmMiscProject
pytest tests/ -v --cov=agent --cov=cloud
```

---

## 10. Shortfalls & Known Issues

> Severity: 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low

---

### SECURITY

#### 🔴 S1 — No Authentication on Any API Endpoint
**Files**: `mock_cloud.py:770–794`, `cloud/app.py:55–110`
Every endpoint is open to the internet. Any attacker can:
- Inject false events to poison the detection model
- Add malicious signatures to block legitimate traffic
- Exfiltrate all stored threat intelligence
- Trigger firewall blocks against legitimate IPs

**Fix**: Implement API key authentication (short-term) or JWT (long-term). See §11-OPT-1.

#### 🔴 S2 — TLS Disabled by Default
**File**: `agent/transport/http.py:11`
```python
def __init__(self, url, token=None, verify_tls=False, ...):
```
Agent-to-cloud traffic is unencrypted and certificate verification is off by default. Detection data and credentials transmitted in plaintext.

**Fix**: Flip default to `verify_tls=True`; enforce HTTPS in cloud.

#### 🔴 S3 — No Input Validation or Size Limits
**File**: `mock_cloud.py:772`
```python
payload = request.get_json(force=True)  # accepts ANY JSON, any size
```
Attackers can send malformed JSON to crash the app or multi-GB payloads to OOM the server.

**Fix**: Add `max_content_length` to Flask config; validate with Pydantic on every endpoint.

#### 🔴 S4 — No Rate Limiting
**File**: `mock_cloud.py:770`
Unlimited requests accepted. A single machine can DoS the entire detection backend.

**Fix**: Add `flask-limiter` with per-IP and per-agent-ID limits.

#### 🟠 S5 — CORS Wildcard
**Files**: `mock_cloud.py:63`, `cloud/app.py:20`
```python
socketio = SocketIO(app, cors_allowed_origins="*")
```
Any origin can connect to the Socket.IO server and receive live threat data.

**Fix**: Restrict to dashboard domain.

#### 🟠 S6 — Hardcoded Heuristic (RDP = Malicious)
**File**: `mock_cloud.py:674`
```python
if "malware" in url_l or int(data.get("port_dst", 0)) == 3389:
    score = max(score, 0.95)
```
Port 3389 (RDP) is treated as 95% malicious. This generates false positives in any Windows enterprise environment. Heuristics should be configurable, not hardcoded.

---

### ARCHITECTURE

#### 🔴 A1 — Three Near-Duplicate Agent Implementations
**Files**: `agent.py` (3,093 lines), `main.py` (~350 lines), `agent_mod.py` (~315 lines)

`_make_card()`, `_metric_chip()`, `_set_status_chip()` are defined identically in both `main.py:144–189` and `agent_mod.py:172–217`. All three files implement the same detection pipeline.

**Impact**: Any bug fix must be made in 3 places. Any feature addition requires 3 implementations.

**Fix**: Single `agent_core.py` module for detection logic; `main.py` becomes a thin UI shell.

#### 🔴 A2 — Monolithic `mock_cloud.py` (2,354 lines)
Every cloud concern in one file: routes, signature matching, ML inference, threat intel, signature generation, database access, Socket.IO broadcasting.

**Fix**: Split into logical modules (see §11-OPT-6).

#### 🟠 A3 — Duplicate Module Hierarchy (Root vs `agent/`)
`capture.py` exists at root AND `agent/` implicitly. `telemetry.py` at root AND `agent/telemetry.py`. Unclear which is canonical.

#### 🟠 A4 — Cloud Has No Duplicate of Agent's Aho-Corasick Implementation
**File**: `cloud/services/signature_matcher.py:36–58`
The cloud signature matcher doesn't have an atomic hot-reload guard. While matching, another thread can call `load_signatures()` and corrupt the automaton.

**Fix**: Apply same RWLock pattern used in agent signature engine.

#### 🟠 A5 — SQLite Not Suitable at Scale
`check_same_thread=False` bypasses SQLite's own safety checks. WAL helps but SQLite's write-lock will serialize all writes under load. Not viable at 10K events/sec target.

**Fix**: Abstract behind interface now; migrate to PostgreSQL.

#### 🟡 A6 — Fragile Circular Import Fallback Chains
**File**: `capture.py:4–35`
```python
try:
    from .utils import ...
except Exception:       # swallows ALL exceptions!
    from utils import ...
try:
    from agent.app import build_transport
except Exception:
    import importlib.util  # dynamic loading at runtime
```
Swallowing `Exception` (not just `ImportError`) hides real bugs. Dynamic module loading at runtime breaks static analysis and IDE support.

---

### PERFORMANCE

#### 🟠 P1 — N+1 Query in Signature Generation
**File**: `mock_cloud.py:469–474`
```python
for sig in signatures:
    existing = signature_store.fetch_all()  # called EVERY iteration!
```
For 100 new signatures → 100 full table scans. Should fetch once and build a set.

#### 🟠 P2 — Regex Compiled on Every Match
**File**: `mock_cloud.py:279`
```python
if ptype == "regex_contains" and re.search(pat, body):
```
`re.search()` compiles the regex every call. With thousands of events per second and dozens of regex signatures, this is a major CPU sink.

**Fix**: Pre-compile patterns in `load_rules()` using `re.compile()`.

#### 🟠 P3 — Blocking External API Calls in Event Pipeline
**File**: `mock_cloud.py:516–596`
AbuseIPDB / VirusTotal / AlienVault called synchronously in the event processing path with 5s timeouts each. Even when disabled, the control flow still evaluates the conditional every event.

**Fix**: Run threat intel enrichment in a separate async worker pool, decoupled from the main processing pipeline.

#### 🟠 P4 — Signature Refresh Called on Every Match Operation
**File**: `mock_cloud.py:255`
`refresh_signatures()` is called inside `match_signature()` (invoked per-event). The TTL check (`time.time() - sig_last_update > 60`) is fast, but `fetch_all()` on a busy DB is not. A background thread should handle refresh.

#### 🟡 P5 — DNS Cache Has No TTL or Expiry
**File**: `mock_cloud.py:175–182`
```python
DNS_CACHE[domain] = resolved  # stays forever
```
If a domain's DNS changes, the system uses stale data indefinitely. Cache should expire entries after 600s.

#### 🟡 P6 — `json` Imported Inside Function
**File**: `agent/signature_engine/aho_corasick_engine.py:258`
```python
try:
    import json  # imported inside function body!
```
Module-level imports are cached; function-level imports re-resolve on every call.

---

### RESILIENCE

#### 🟠 R1 — Failed Event Batches Are Silently Dropped
**File**: `telemetry.py:62–67`
```python
except Exception as e:
    self.log(f"⚠️ Send failed: {e}")  # event batch lost forever
```
No retry, no dead-letter queue, no local fallback storage.

**Fix**: Implement exponential backoff retry (3 attempts); on persistent failure, write batch to local disk queue.

#### 🟠 R2 — ONNX Model Missing = Hard Crash
**File**: `mock_cloud.py:145–153`
```python
except Exception as e:
    raise SystemExit(f"❌ Failed to load model: {e}")
```
If `lite_model.onnx` is missing or corrupted, the entire cloud backend refuses to start. Detection is completely unavailable.

**Fix**: Fall back to signature-only detection mode when model unavailable; expose `/api/model/upload` to load model at runtime.

#### 🟡 R3 — Config Values Not Validated
**File**: `agent.py:104–108`
```python
cfg["BATCH_SIZE"] = int(cfg.get("BATCH_SIZE", 20))
```
`int("hello")` raises `ValueError`. `int(-1)` produces a nonsensical batch size. No range checks.

---

### CONCURRENCY

#### 🟠 C1 — Race Condition on Global `sig_cache`
**File**: `mock_cloud.py:213–248`
```python
sig_cache, sig_last_update = [], 0  # global mutable
def refresh_signatures():
    global sig_cache, sig_last_update
    sig_cache = [...]   # no lock!
```
Two threads can simultaneously detect a stale cache and both call `fetch_all()`, both overwriting `sig_cache`. Under high load this causes duplicate DB queries and inconsistent cache state.

**Fix**: Use `threading.Lock()` around the check-and-refresh block.

#### 🟡 C2 — Daemon Threads Killed Without Cleanup
**File**: `capture.py:66`
```python
threading.Thread(target=self.rule_updater.fetch_and_update, daemon=True).start()
```
Daemon threads are killed instantly when the main thread exits. In-flight HTTP requests and batch sends are abandoned mid-transmission.

**Fix**: Use a `threading.Event` shutdown signal and join threads on exit.

---

### CODE QUALITY

#### 🟡 Q1 — Double Import of `threading` and `time`
**File**: `mock_cloud.py:19, 23`
`threading` and `time` imported twice. `math` imported but never used.

#### 🟡 Q2 — Third-Party APIs Are Dead Code
**File**: `mock_cloud.py:498–596`
All integrations are `"enabled": False`. The 80-line enrichment function is dead code that runs conditionally on every alert but always exits early.

#### 🟡 Q3 — Two Conflicting Config Files
`config.json` and `agent_config.json` exist with overlapping keys but different structure. No single source of truth.

#### 🟢 Q4 — No Type Hints on Cloud Functions
`mock_cloud.py` functions have no type annotations. Combined with the file's size, this makes comprehension very difficult.

#### 🟢 Q5 — Inconsistent Logging (`print()` vs `self.log()` vs `logging`)
Cloud uses `print()`. Agent uses `self.log()` (Qt signal). No structured logging anywhere.

---

### DEPLOYMENT & DEPENDENCIES

#### 🔴 D1 — `requirements.txt` Is Missing Half Its Dependencies
Flask, Flask-SocketIO, onnxruntime, numpy are all required but not listed. A clean `pip install -r requirements.txt` produces a broken installation.

#### 🟠 D2 — No Dockerfile or Deployment Config
No containerization, no process manager config (systemd/supervisord), no startup scripts.

#### 🟠 D3 — No Version Pinning
Only `pyahocorasick>=2.0.0` and `pydantic>=2.0.0` are pinned. A dependency update can silently break the project.

---

### TESTING

#### 🔴 T1 — ~5% Test Coverage
Only the Aho-Corasick signature engine has tests. The cloud backend, API endpoints, ML pipeline, storage layer, event processing, agent-cloud communication, and firewall response engine have zero tests.

#### 🟠 T2 — Attack Simulators Are Not Tests
`attack.py`, `sim_sig_attack.py`, `sophisticated_test_suite.py` contain no assertions. They don't prove anything about correctness.

---

## 11. Optimization Roadmap

Priority order based on impact and urgency.

---

### OPT-1 🔴 Add Authentication (Week 1)

**Option A (fast)**: Static API key in `Authorization: Bearer <key>` header

```python
# mock_cloud.py
API_KEY = os.environ["QD_API_KEY"]  # required env var

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token or not hmac.compare_digest(token, API_KEY):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/analyze", methods=["POST"])
@require_api_key
def analyze():
    ...
```

**Option B (proper)**: JWT with per-agent credentials using `PyJWT`

---

### OPT-2 🔴 Fix `requirements.txt`

Replace current file with:

```
flask>=3.0.0
flask-socketio>=5.3.0
onnxruntime>=1.17.0
numpy>=1.26.0
pydivert>=2.1.0
PySide6>=6.6.0
requests>=2.31.0
psutil>=5.9.0
qdarktheme>=2.1.0
winotify>=1.1.0
pyahocorasick>=2.0.0
pydantic>=2.0.0
python-dotenv>=1.0.0
pytest>=8.0.0
pytest-cov>=4.0.0
```

---

### OPT-3 🔴 Fix Duplicate Agent Implementations

Merge the three agent files into one coherent structure:

```
agent/
├── core.py          ← detection logic, shared by both modes
├── ui/
│   └── window.py    ← PySide6 window (thin shell, imports core)
├── headless.py      ← CLI entry point (imports core)
└── ...
```

`main.py` and `agent_mod.py` become 20-line launchers that import from `agent/ui/window.py`.

---

### OPT-4 🔴 Split `mock_cloud.py` Into Modules

Target structure:

```
cloud/
├── app.py                          ← Flask app factory, routes only
├── config.py                       ← All config via os.environ + defaults
├── services/
│   ├── event_processor.py          ← Core event handling pipeline
│   ├── anomaly/
│   │   └── model_runner.py         ← ONNX inference (already exists)
│   ├── threat_intelligence.py      ← Geo, DNS, AbuseIPDB
│   ├── signature_matcher.py        ← Cloud Aho-Corasick (fix thread safety)
│   ├── signature_generator/        ← Pattern mining (exists, unfinished)
│   └── signature_distribution/     ← Rule serving (exists)
├── storage/
│   ├── sqlite_store.py             ← (already exists)
│   └── base.py                     ← Abstract interface for swap-in
├── queue/
│   └── ingestion.py                ← (already exists)
└── realtime/
    └── broadcaster.py              ← Socket.IO isolation
```

---

### OPT-5 🟠 Fix Performance Issues

**Pre-compile regex signatures** (immediate, high impact):

```python
# In load_rules() / refresh_signatures():
compiled_patterns = {}
for sig in sig_cache:
    if sig["type"] == "regex_contains":
        try:
            compiled_patterns[sig["pattern"]] = re.compile(sig["pattern"])
        except re.error:
            pass

# In match_signature():
if ptype == "regex_contains":
    compiled = compiled_patterns.get(pat)
    if compiled and compiled.search(body):
        return sig
```

**Fix N+1 signature deduplication** (immediate):

```python
def generate_and_deploy_signatures(signatures):
    existing = {(s.pattern, s.type) for s in signature_store.fetch_all()}  # once
    for sig in signatures:
        if (sig["pattern"], sig["type"]) not in existing:
            signature_store.add(sig)
```

**Move signature refresh to background thread**:

```python
def _refresh_worker():
    while not _shutdown.is_set():
        _do_refresh()
        time.sleep(SIGNATURE_REFRESH)

threading.Thread(target=_refresh_worker, daemon=True).start()
```

---

### OPT-6 🟠 Add Rate Limiting

```bash
pip install flask-limiter
```

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address, app=app, default_limits=["1000 per minute"])

@app.route("/analyze", methods=["POST"])
@limiter.limit("500 per minute")
def analyze():
    ...
```

---

### OPT-7 🟠 Add Telemetry Retry with Local Fallback

```python
# telemetry.py
import json, pathlib

DEAD_LETTER_PATH = pathlib.Path("dead_letter_queue")

def _send_batch(self, batch):
    for attempt in range(3):
        try:
            self.transport.send_batch(batch)
            return
        except Exception as e:
            self.log(f"Send attempt {attempt+1} failed: {e}")
            time.sleep(2 ** attempt)   # 1s, 2s, 4s backoff
    # All retries exhausted → write to disk
    DEAD_LETTER_PATH.mkdir(exist_ok=True)
    fname = DEAD_LETTER_PATH / f"batch_{time.time_ns()}.json"
    fname.write_text(json.dumps(batch))
    self.log(f"Batch written to dead letter: {fname}")
```

---

### OPT-8 🟠 Centralize Configuration

Create `cloud/config.py`:

```python
import os
from dataclasses import dataclass

@dataclass
class CloudConfig:
    host: str = os.getenv("QD_HOST", "0.0.0.0")
    port: int = int(os.getenv("QD_PORT", "5000"))
    db_path: str = os.getenv("QD_DB_PATH", "cloud_store.db")
    onnx_model: str = os.getenv("QD_ONNX_MODEL", "lite_model.onnx")
    alert_threshold: float = float(os.getenv("QD_ALERT_THRESHOLD", "0.85"))
    signature_refresh: int = int(os.getenv("QD_SIG_REFRESH", "60"))
    max_events: int = int(os.getenv("QD_MAX_EVENTS", "50000"))
    api_key: str = os.getenv("QD_API_KEY", "")

config = CloudConfig()
```

---

### OPT-9 🟠 Expand Test Coverage to 80%+

Priority test targets:

```
tests/
├── unit/
│   ├── test_signature_engine.py        ← exists, extend
│   ├── test_event_processor.py         ← NEW
│   ├── test_onnx_model_runner.py       ← NEW
│   ├── test_sqlite_store.py            ← NEW
│   └── test_telemetry_sender.py        ← NEW
├── integration/
│   ├── test_analyze_endpoint.py        ← NEW (Flask test client)
│   ├── test_signature_distribution.py  ← NEW
│   └── test_agent_cloud_pipeline.py    ← NEW
└── conftest.py                         ← NEW (fixtures, mock cloud)
```

Run with:

```bash
pytest tests/ -v --cov=agent --cov=cloud --cov-report=html
```

---

### OPT-10 🟡 Add Structured Logging

Replace all `print()` and `self.log()` with:

```bash
pip install structlog
```

```python
import structlog
log = structlog.get_logger()

log.info("event_analyzed", score=0.91, src_ip="1.2.3.4", alert=True)
log.error("model_inference_failed", exc_info=True)
```

---

### OPT-11 🟡 ONNX Model Fallback Mode

```python
try:
    sess = ort.InferenceSession(ONNX_MODEL)
    ML_AVAILABLE = True
    log.info("model_loaded", path=ONNX_MODEL)
except Exception as e:
    ML_AVAILABLE = False
    log.warning("model_unavailable", reason=str(e), fallback="signature_only")

def run_inference(features):
    if not ML_AVAILABLE:
        return 0.0  # fall back to signature-only scoring
    return sess.run(None, {"input": features})[0][0][1]
```

---

### OPT-12 🟡 Fix `cloud/services/signature_matcher.py` Thread Safety

Apply RWLock to cloud signature matcher to match agent engine:

```python
# cloud/services/signature_matcher.py
from threading import Lock

class CloudSignatureMatcher:
    def __init__(self):
        self._lock = Lock()
        self._automaton = None
        ...

    def load_signatures(self, signatures):
        new_automaton = self._build_automaton(signatures)  # build outside lock
        with self._lock:
            self._automaton = new_automaton  # atomic swap

    def match(self, event):
        with self._lock:
            auto = self._automaton
        if auto:
            return self._match_with(auto, event)
```

---

### OPT-13 🟢 Containerize with Docker

`Dockerfile` for cloud:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "mock_cloud.py"]
```

`docker-compose.yml`:

```yaml
version: "3.9"
services:
  cloud:
    build: .
    ports:
      - "5000:5000"
    environment:
      - QD_API_KEY=${QD_API_KEY}
      - QD_ALERT_THRESHOLD=0.85
    volumes:
      - ./cloud_store.db:/app/cloud_store.db
      - ./lite_model.onnx:/app/lite_model.onnx
```

---

## 12. Development Setup

### Prerequisites

- Python 3.11+
- Windows 10/11 (agent requires WinDivert)
- WinDivert driver installed (for packet capture)
- `lite_model.onnx` file required for cloud ML

### Install

```bash
cd C:\Users\aliga\PyCharmMiscProject
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt   # NOTE: currently incomplete, see OPT-2
```

### Run Cloud Backend

```bash
set QD_API_KEY=your-secret-key
python mock_cloud.py
# → http://localhost:5000
```

### Run Agent (GUI)

```bash
python main.py
```

### Run Agent (Headless)

```bash
python agent_mod.py
```

### Run Tests

```bash
pytest tests/ -v
```

---

## Issue Count Summary

| Severity | Count | Categories |
|----------|-------|------------|
| 🔴 Critical | 8 | No auth, no TLS, broken deps, agent duplication, monolith, dropped events, hard crash on missing model, 5% test coverage |
| 🟠 High | 13 | CORS wildcard, thread safety, N+1 queries, regex recompile, blocking APIs, race conditions, no rate limiting, no retry |
| 🟡 Medium | 9 | DNS TTL, dead code, config inconsistency, daemon threads, duplicate imports, config validation, no Docker |
| 🟢 Low | 4 | Type hints, logging inconsistency, dead letter hints, docstrings |

**Total open issues: 34**

---

*Generated: 2026-03-12 | For internal use — not for distribution*
