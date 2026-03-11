# QuantumDefender - Hybrid Intrusion Detection Platform

**Cloud-Based Hybrid Intrusion Detection Platform with Deep Learning and Signature-Based Agent**

Author: **Ali Kadir Bulut**  
Institution: **Katowice Institute of Information Technologies**  
Version: **v9.0**

---

## 🎯 Overview

QuantumDefender is a next-generation hybrid intrusion detection system that combines:
- **Signature-based detection** at the agent level (low-latency, high accuracy for known threats)
- **Deep learning anomaly detection** at the cloud level (zero-day threat detection)
- **Self-evolving signature generation** from ML feedback and third-party threat intelligence
- **Real-time threat response** with automated firewall blocking

### Key Features

✅ **Hybrid Detection Architecture**
- Agent-side signature matching for immediate threat detection
- Cloud-based ML anomaly detection for unknown threats
- Multi-stage detection pipeline (Agent → Signature → ML)

✅ **Self-Evolving Signatures**
- Automatic signature generation from ML-detected anomalies
- Third-party threat intelligence integration (AbuseIPDB, VirusTotal, AlienVault)
- Continuous learning and adaptation

✅ **High-Performance Signature Engine**
- Aho-Corasick algorithm for O(n+m+z) multi-pattern matching
- Optimized for thousands of signatures
- Thread-safe atomic hot-reload

✅ **Real-Time Communication**
- Socket.IO for live agent-cloud communication
- Real-time signature distribution
- Live threat monitoring and response

✅ **Advanced Analytics**
- Threat correlation and timeline analysis
- Geographic threat intelligence
- Device performance monitoring
- Automated response rules

---

## 🏗️ Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  Agent (Client) │─────────▶│  Cloud Backend   │
│                 │  Events  │                  │
│  • Capture      │◀─────────│  • ML Detection  │
│  • Signatures   │ Signatures│  • Analytics    │
│  • Firewall     │          │  • Intelligence  │
└─────────────────┘          └──────────────────┘
                                      │
                                      ▼
                            ┌──────────────────┐
                            │ Third-Party APIs │
                            │ • AbuseIPDB      │
                            │ • VirusTotal     │
                            │ • AlienVault     │
                            └──────────────────┘
```

### Components

1. **Agent** (`agent.py`, `agent/`)
   - Network traffic capture (WinDivert)
   - Local signature matching
   - Event collection and batching
   - Firewall rule enforcement

2. **Cloud Backend** (`mock_cloud.py`, `cloud/`)
   - Event ingestion and processing
   - ML anomaly detection (ONNX model)
   - Signature generation and distribution
   - Threat intelligence aggregation

3. **Signature Engine** (`agent/signature_engine/`)
   - Optimized Aho-Corasick matching
   - Multi-type pattern support (IP, domain, port, regex)
   - Thread-safe hot-reload

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Windows 10/11 (for agent packet capture)
- Administrator privileges (for WinDivert)
- ONNX model file (`lite_model.onnx`)

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd PyCharmMiscProject
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
cd agent
pip install -r requirements.txt
```

3. **Configure the system**

Create `agent_config.json`:
```json
{
  "CLOUD_URL": "http://127.0.0.1:5000/analyze",
  "ENABLE_FIREWALL_BLOCK": false,
  "BATCH_SIZE": 20,
  "SEND_INTERVAL": 2.0,
  "FILTER": "(tcp.DstPort == 80 or tcp.DstPort == 443)"
}
```

4. **Start the cloud backend**
```bash
python mock_cloud.py
```

5. **Start the agent** (as Administrator)
```bash
python agent.py
```

---

## 📊 Performance

### Signature Engine Benchmarks

- **Linear Search**: O(n×m) - ~100ms for 1000 rules
- **Aho-Corasick**: O(n+m+z) - ~1ms for 1000 rules
- **100x speedup** for large rule sets

### System Capabilities

- **Event Processing**: 10,000+ events/second
- **Signature Matching**: <1ms per event
- **ML Inference**: <10ms per event
- **Concurrent Agents**: 1000+ supported

---

## 🔧 Configuration

### Agent Configuration

Edit `agent_config.json`:

```json
{
  "CLOUD_URL": "http://your-cloud-server:5000/analyze",
  "ENABLE_FIREWALL_BLOCK": true,
  "BATCH_SIZE": 20,
  "SEND_INTERVAL": 2.0,
  "FILTER": "tcp and (port 80 or port 443)"
}
```

### Cloud Configuration

Environment variables:
```bash
export ABUSEIPDB_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"
export ALIENVAULT_API_KEY="your-key"
```

Or configure via API:
```bash
curl -X POST http://localhost:5000/api/third_party/configure \
  -H "Content-Type: application/json" \
  -d '{
    "api_name": "abuseipdb",
    "enabled": true,
    "api_key": "your-key"
  }'
```

---

## 🧪 Testing

Run unit tests:
```bash
pytest tests/unit/test_signature_engine.py -v
```

Run all tests:
```bash
pytest tests/ -v --cov=agent --cov=cloud
```

---

## 📈 API Endpoints

### Cloud API

- `POST /analyze` - Ingest events from agents
- `GET /api/signatures` - Get all signatures
- `POST /api/ml/feedback/analyze_now` - Trigger pattern analysis
- `GET /api/ml/feedback/stats` - ML feedback statistics
- `GET /api/threats/intel` - Threat intelligence
- `POST /api/devices/<agent_id>/drop_connection` - Block connection

See full API documentation in `docs/API.md`

---

## 🔬 Research Features

This project implements the research methodology described in:

**"Cloud-Based Hybrid Intrusion Detection Platform with Deep Learning and Signature-Based Agent"**

Key research contributions:
1. **Hybrid Detection**: Combines signature and ML approaches
2. **Self-Evolving Signatures**: ML feedback generates new signatures
3. **Third-Party Integration**: External threat intelligence ingestion
4. **Continuous Learning**: Adaptive system that improves over time

---

## 🛠️ Development

### Project Structure

```
PyCharmMiscProject/
├── agent/                 # Agent components
│   ├── signature_engine/  # Optimized signature matching
│   ├── telemetry/         # Event serialization
│   ├── transport/         # Communication layer
│   └── traffic_monitor/   # Packet capture
├── cloud/                 # Cloud backend
│   ├── services/          # Business logic
│   ├── storage/           # Data persistence
│   └── ingestion/         # Event queue
├── tests/                 # Test suite
├── docs/                  # Documentation
├── agent.py              # Main agent application
├── mock_cloud.py         # Cloud backend server
└── requirements.txt      # Dependencies
```

### Code Quality

- Type hints throughout
- Comprehensive error handling
- Thread-safe operations
- Performance optimized

---

## 📝 License

Academic research project - All rights reserved

---

## 👤 Author

**Ali Kadir Bulut**  
Department of Information Technology  
Katowice Institute of Information Technologies

---

## 🙏 Acknowledgments

- Research advisors and reviewers
- Open-source community contributions
- Threat intelligence providers

---

## 📚 References

See research paper for complete bibliography.

---

**Last Updated**: 2025-01-XX  
**Version**: 9.0  
**Status**: Active Development


