#!/usr/bin/env python3
"""
QuantumDefender Sophisticated Test Suite
Simulates realistic attack patterns, signature matching, ML anomalies, and threat correlation.
"""
import requests
import random
import time
import string
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any

API_URL = "http://192.168.1.24:5000/analyze"

# ============================================================
# ATTACK PATTERNS & PAYLOADS
# ============================================================

# SQL Injection patterns (will trigger signature matching)
SQL_INJECTION_PATTERNS = [
    "admin' OR '1'='1",
    "1' UNION SELECT * FROM users--",
    "'; DROP TABLE users--",
    "' OR 1=1--",
    "admin'--",
    "1' OR '1'='1'--",
    "'; EXEC xp_cmdshell('dir')--",
]

# XSS patterns
XSS_PATTERNS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
]

# Malware indicators
MALWARE_INDICATORS = [
    "malware.exe",
    "trojan.bat",
    "virus.dll",
    "backdoor.php",
    "ransomware.encrypted",
    "keylogger.log",
]

# Suspicious IPs (for threat correlation)
SUSPICIOUS_IPS = [
    "185.220.101.0",  # Known malicious
    "45.146.164.0",
    "192.0.2.0",
    "198.51.100.0",
]

# Suspicious domains
SUSPICIOUS_DOMAINS = [
    "malware.test",
    "phishing.example",
    "botnet.network",
    "c2.server",
    "exploit.host",
]

# Normal/benign patterns
NORMAL_PATTERNS = [
    "index.html",
    "api/users",
    "login",
    "dashboard",
    "static/css/style.css",
]

# ============================================================
# AGENT SIMULATION
# ============================================================

class AgentSimulator:
    def __init__(self, agent_id: str, hostname: str, ip: str):
        self.agent_id = agent_id
        self.hostname = hostname
        self.ip = ip
        self.event_count = 0
        self.alert_count = 0
        self.last_seen = datetime.now()
        
    def generate_event(self, attack_type: str = "normal", **kwargs) -> Dict[str, Any]:
        """Generate a realistic event based on attack type"""
        self.event_count += 1
        self.last_seen = datetime.now()
        
        base_event = {
            "agent_id": self.agent_id,
            "host": self.hostname,
            "src_ip": self.ip,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "bytes_sent": random.randint(100, 100000),
            "bytes_recv": random.randint(100, 50000),
            "region": random.choice(["US", "EU", "ASIA", "Unknown"]),
        }
        
        if attack_type == "sql_injection":
            base_event.update({
                "dst_ip": random.choice(["192.168.1.100", "10.0.0.50"]),
                "protocol": "HTTP",
                "url": f"http://example.com/login?user={random.choice(SQL_INJECTION_PATTERNS)}",
                "detection_source": "signature",
                "score": random.uniform(0.85, 0.98),
                "alert": True,
                "reason": "SQL Injection Pattern Detected",
            })
            self.alert_count += 1
            
        elif attack_type == "xss":
            base_event.update({
                "dst_ip": random.choice(["192.168.1.100", "10.0.0.50"]),
                "protocol": "HTTP",
                "url": f"http://example.com/search?q={random.choice(XSS_PATTERNS)}",
                "detection_source": "signature",
                "score": random.uniform(0.80, 0.95),
                "alert": True,
                "reason": "XSS Pattern Detected",
            })
            self.alert_count += 1
            
        elif attack_type == "malware":
            base_event.update({
                "dst_ip": random.choice(SUSPICIOUS_IPS),
                "protocol": "HTTP",
                "url": f"http://{random.choice(SUSPICIOUS_DOMAINS)}/{random.choice(MALWARE_INDICATORS)}",
                "detection_source": "ml",
                "score": random.uniform(0.90, 0.99),
                "alert": True,
                "reason": "Malware Indicator Detected",
            })
            self.alert_count += 1
            
        elif attack_type == "suspicious_ip":
            base_event.update({
                "dst_ip": random.choice(SUSPICIOUS_IPS),
                "protocol": random.choice(["HTTP", "HTTPS", "TCP"]),
                "url": f"http://{random.choice(SUSPICIOUS_DOMAINS)}/",
                "detection_source": "threat_intel",
                "score": random.uniform(0.75, 0.90),
                "alert": True,
                "reason": "Suspicious IP Address",
            })
            self.alert_count += 1
            
        elif attack_type == "port_scan":
            base_event.update({
                "dst_ip": random.choice(["192.168.1.100", "10.0.0.50"]),
                "protocol": "TCP",
                "port": random.randint(1, 65535),
                "url": None,
                "detection_source": "ml",
                "score": random.uniform(0.70, 0.85),
                "alert": random.choice([True, False]),
                "reason": "Port Scan Pattern" if random.random() > 0.7 else None,
            })
            if base_event.get("alert"):
                self.alert_count += 1
                
        elif attack_type == "data_exfiltration":
            base_event.update({
                "dst_ip": random.choice(SUSPICIOUS_IPS),
                "protocol": "HTTPS",
                "url": f"https://{random.choice(SUSPICIOUS_DOMAINS)}/upload",
                "bytes_sent": random.randint(1000000, 10000000),  # Large upload
                "bytes_recv": random.randint(100, 1000),
                "detection_source": "ml",
                "score": random.uniform(0.85, 0.95),
                "alert": True,
                "reason": "Potential Data Exfiltration",
            })
            self.alert_count += 1
            
        elif attack_type == "correlated_threat":
            # Multiple agents hitting same suspicious IP
            base_event.update({
                "dst_ip": random.choice(SUSPICIOUS_IPS),
                "protocol": "HTTP",
                "url": f"http://{random.choice(SUSPICIOUS_DOMAINS)}/",
                "detection_source": "correlation",
                "score": random.uniform(0.90, 0.99),
                "alert": True,
                "reason": "Correlated Threat Pattern",
            })
            self.alert_count += 1
            
        else:  # normal
            base_event.update({
                "dst_ip": random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"]),
                "protocol": random.choice(["HTTP", "HTTPS", "DNS"]),
                "url": f"http://example.com/{random.choice(NORMAL_PATTERNS)}",
                "detection_source": "none",
                "score": random.uniform(0.1, 0.3),
                "alert": False,
            })
        
        return base_event

# ============================================================
# TEST SCENARIOS
# ============================================================

class TestScenario:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.agents: List[AgentSimulator] = []
        self.stats = defaultdict(int)
        
    def setup_agents(self, count: int = 3):
        """Create simulated agents"""
        for i in range(count):
            agent_id = f"agent-{random.randint(1000, 9999)}"
            hostname = f"host-{random.choice(string.ascii_uppercase)}{random.randint(1, 100)}"
            ip = f"192.168.1.{random.randint(10, 250)}"
            self.agents.append(AgentSimulator(agent_id, hostname, ip))
    
    def send_event(self, event: Dict[str, Any]) -> bool:
        """Send event to cloud server"""
        try:
            response = requests.post(API_URL, json=[event], timeout=5)
            if response.status_code == 200:
                self.stats['sent'] += 1
                if event.get('alert'):
                    self.stats['alerts'] += 1
                return True
            else:
                self.stats['errors'] += 1
                print(f"❌ Error: HTTP {response.status_code}")
                return False
        except Exception as e:
            self.stats['errors'] += 1
            print(f"❌ Exception: {e}")
            return False
    
    def run(self):
        """Run the test scenario"""
        raise NotImplementedError
    
    def print_stats(self):
        """Print scenario statistics"""
        print(f"\n📊 Statistics:")
        print(f"   Events sent: {self.stats['sent']}")
        print(f"   Alerts: {self.stats['alerts']}")
        print(f"   Errors: {self.stats['errors']}")
        if self.stats['sent'] > 0:
            alert_rate = (self.stats['alerts'] / self.stats['sent']) * 100
            print(f"   Alert rate: {alert_rate:.1f}%")
        print()

# ============================================================
# SPECIFIC TEST SCENARIOS
# ============================================================

class SignatureMatchingTest(TestScenario):
    """Test signature-based detection"""
    def __init__(self):
        super().__init__(
            "Signature Matching Test",
            "Tests SQL injection and XSS pattern detection"
        )
        self.setup_agents(2)
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"🧪 {self.name}")
        print(f"{self.description}")
        print(f"{'='*60}\n")
        
        for i in range(20):
            agent = random.choice(self.agents)
            attack_type = random.choice(["sql_injection", "xss", "normal"])
            event = agent.generate_event(attack_type)
            
            print(f"[{i+1}/20] {attack_type.upper()}: {event.get('url', 'N/A')[:50]}")
            self.send_event(event)
            time.sleep(0.5)
        
        self.print_stats()

class MLAnomalyTest(TestScenario):
    """Test ML-based anomaly detection"""
    def __init__(self):
        super().__init__(
            "ML Anomaly Detection Test",
            "Tests machine learning anomaly detection with unusual patterns"
        )
        self.setup_agents(3)
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"🧪 {self.name}")
        print(f"{self.description}")
        print(f"{'='*60}\n")
        
        # Send normal traffic first
        print("📊 Phase 1: Baseline normal traffic...")
        for i in range(10):
            agent = random.choice(self.agents)
            event = agent.generate_event("normal")
            self.send_event(event)
            time.sleep(0.3)
        
        time.sleep(1)
        
        # Send anomalies
        print("\n🚨 Phase 2: Anomalous patterns...")
        anomaly_types = ["malware", "data_exfiltration", "port_scan"]
        for i in range(15):
            agent = random.choice(self.agents)
            attack_type = random.choice(anomaly_types)
            event = agent.generate_event(attack_type)
            
            print(f"[{i+1}/15] {attack_type.upper()}: Score={event.get('score', 0):.2f}")
            self.send_event(event)
            time.sleep(0.4)
        
        self.print_stats()

class ThreatCorrelationTest(TestScenario):
    """Test threat correlation across multiple agents"""
    def __init__(self):
        super().__init__(
            "Threat Correlation Test",
            "Tests correlation of threats across multiple agents hitting same target"
        )
        self.setup_agents(5)
        self.target_ip = random.choice(SUSPICIOUS_IPS)
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"🧪 {self.name}")
        print(f"{self.description}")
        print(f"Target IP: {self.target_ip}")
        print(f"{'='*60}\n")
        
        # Multiple agents hit same suspicious IP
        print("🔗 Simulating correlated threat...")
        for i in range(25):
            agent = random.choice(self.agents)
            # Higher chance of correlated threat
            attack_type = "correlated_threat" if random.random() > 0.3 else "suspicious_ip"
            event = agent.generate_event(attack_type)
            event["dst_ip"] = self.target_ip  # Force same target
            
            print(f"[{i+1}/25] Agent {agent.agent_id} → {self.target_ip}")
            self.send_event(event)
            time.sleep(0.3)
        
        self.print_stats()

class MixedTrafficTest(TestScenario):
    """Mixed normal and malicious traffic"""
    def __init__(self):
        super().__init__(
            "Mixed Traffic Test",
            "Realistic mix of normal and malicious traffic patterns"
        )
        self.setup_agents(4)
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"🧪 {self.name}")
        print(f"{self.description}")
        print(f"{'='*60}\n")
        
        attack_types = [
            "normal", "normal", "normal",  # 60% normal
            "sql_injection", "xss", "malware", "suspicious_ip"
        ]
        
        for i in range(50):
            agent = random.choice(self.agents)
            attack_type = random.choice(attack_types)
            event = agent.generate_event(attack_type)
            
            status = "🚨 ALERT" if event.get('alert') else "✅ OK"
            print(f"[{i+1}/50] {status} {attack_type}: {event.get('url', 'N/A')[:40]}")
            self.send_event(event)
            time.sleep(0.2)
        
        self.print_stats()

class BurstAttackTest(TestScenario):
    """Simulate burst attack scenario"""
    def __init__(self):
        super().__init__(
            "Burst Attack Test",
            "Simulates rapid-fire attack scenario"
        )
        self.setup_agents(3)
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"🧪 {self.name}")
        print(f"{self.description}")
        print(f"{'='*60}\n")
        
        print("💥 Sending burst of attacks...")
        events = []
        for i in range(30):
            agent = random.choice(self.agents)
            attack_type = random.choice(["sql_injection", "xss", "malware"])
            event = agent.generate_event(attack_type)
            events.append(event)
        
        # Send all at once
        try:
            response = requests.post(API_URL, json=events, timeout=10)
            if response.status_code == 200:
                self.stats['sent'] = len(events)
                self.stats['alerts'] = sum(1 for e in events if e.get('alert'))
                print(f"✅ Sent {len(events)} events in burst")
            else:
                print(f"❌ Error: HTTP {response.status_code}")
        except Exception as e:
            print(f"❌ Exception: {e}")
        
        self.print_stats()

# ============================================================
# MAIN TEST RUNNER
# ============================================================

def run_all_tests():
    """Run all test scenarios"""
    scenarios = [
        SignatureMatchingTest(),
        MLAnomalyTest(),
        ThreatCorrelationTest(),
        MixedTrafficTest(),
        BurstAttackTest(),
    ]
    
    print("\n" + "="*60)
    print("🚀 QuantumDefender Sophisticated Test Suite")
    print("="*60)
    print(f"\nTarget: {API_URL}")
    print(f"Scenarios: {len(scenarios)}")
    
    input("\nPress ENTER to start testing...")
    
    for scenario in scenarios:
        try:
            scenario.run()
            time.sleep(2)  # Pause between scenarios
        except KeyboardInterrupt:
            print("\n\n⚠️  Test interrupted by user")
            break
        except Exception as e:
            print(f"\n❌ Error in {scenario.name}: {e}")
            continue
    
    print("\n" + "="*60)
    print("✅ Test suite completed!")
    print("="*60)
    print("\n📊 Check your cloud dashboard to see:")
    print("   - Events in Live Feed")
    print("   - Alerts and threat detection")
    print("   - Agent activity")
    print("   - Threat correlation")
    print("   - Analytics and statistics")

def run_single_test(test_name: str):
    """Run a single test scenario"""
    tests = {
        "signature": SignatureMatchingTest,
        "ml": MLAnomalyTest,
        "correlation": ThreatCorrelationTest,
        "mixed": MixedTrafficTest,
        "burst": BurstAttackTest,
    }
    
    if test_name.lower() not in tests:
        print(f"❌ Unknown test: {test_name}")
        print(f"Available: {', '.join(tests.keys())}")
        return
    
    scenario = tests[test_name.lower()]()
    scenario.run()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Run specific test
        run_single_test(sys.argv[1])
    else:
        # Run all tests
        run_all_tests()

