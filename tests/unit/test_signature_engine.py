"""
Unit tests for optimized signature engine with Aho-Corasick.
"""
import pytest
from agent.schemas import SignatureRule
from agent.signature_engine.aho_corasick_engine import OptimizedSignatureEngine


@pytest.fixture
def sample_rules():
    """Sample signature rules for testing"""
    return [
        SignatureRule(
            id="1",
            type="payload_contains",
            pattern="malware",
            severity="high",
            source="test"
        ),
        SignatureRule(
            id="2",
            type="ip_equals",
            pattern="192.168.1.100",
            severity="medium",
            source="test"
        ),
        SignatureRule(
            id="3",
            type="domain_match",
            pattern="evil.com",
            severity="high",
            source="test"
        ),
        SignatureRule(
            id="4",
            type="port_equals",
            pattern="3389",
            severity="medium",
            source="test"
        ),
        SignatureRule(
            id="5",
            type="regex_contains",
            pattern=r"exploit.*payload",
            severity="high",
            source="test"
        ),
    ]


@pytest.fixture
def engine(sample_rules):
    """Create and load engine with sample rules"""
    eng = OptimizedSignatureEngine()
    eng.load_rules(sample_rules)
    return eng


def test_string_pattern_matching(engine):
    """Test basic string pattern matching"""
    payload = {"url": "http://example.com/malware.exe", "host": "example.com"}
    match = engine.match(payload)
    assert match is not None
    assert match.id == "1"
    assert match.pattern == "malware"


def test_ip_matching(engine):
    """Test IP address matching"""
    payload = {"dst_ip": "192.168.1.100", "src_ip": "10.0.0.1"}
    match = engine.match(payload)
    assert match is not None
    assert match.id == "2"
    assert match.type == "ip_equals"


def test_domain_matching(engine):
    """Test domain matching"""
    payload = {"url": "https://evil.com/payload", "host": "evil.com"}
    match = engine.match(payload)
    assert match is not None
    assert match.id == "3"
    assert match.type == "domain_match"


def test_port_matching(engine):
    """Test port matching"""
    payload = {"port_dst": 3389, "protocol": "TCP"}
    match = engine.match(payload)
    assert match is not None
    assert match.id == "4"
    assert match.type == "port_equals"


def test_regex_matching(engine):
    """Test regex pattern matching"""
    payload = {"url": "http://test.com", "payload": "exploit code payload"}
    match = engine.match(payload)
    assert match is not None
    assert match.id == "5"
    assert match.type == "regex_contains"


def test_no_match(engine):
    """Test when no patterns match"""
    payload = {"url": "http://safe.com", "dst_ip": "10.0.0.1", "port_dst": 80}
    match = engine.match(payload)
    assert match is None


def test_match_all(engine):
    """Test finding all matching rules"""
    payload = {
        "url": "http://evil.com/malware.exe",
        "dst_ip": "192.168.1.100",
        "port_dst": 3389
    }
    matches = engine.match_all(payload)
    assert len(matches) >= 3  # Should match domain, IP, and port
    match_ids = {m.id for m in matches}
    assert "1" in match_ids or "3" in match_ids  # malware or evil.com
    assert "2" in match_ids  # IP
    assert "4" in match_ids  # Port


def test_case_insensitive_matching(engine):
    """Test case-insensitive pattern matching"""
    payload = {"url": "http://example.com/MALWARE.exe", "host": "EXAMPLE.COM"}
    match = engine.match(payload)
    assert match is not None
    assert match.pattern.lower() == "malware"


def test_hot_reload(engine):
    """Test atomic hot-reload of rules"""
    new_rules = [
        SignatureRule(
            id="6",
            type="payload_contains",
            pattern="virus",
            severity="high",
            source="test"
        )
    ]
    
    # Reload rules
    engine.hot_reload(new_rules)
    
    # Test old rule doesn't match
    payload1 = {"url": "http://test.com/malware"}
    assert engine.match(payload1) is None
    
    # Test new rule matches
    payload2 = {"url": "http://test.com/virus"}
    match = engine.match(payload2)
    assert match is not None
    assert match.id == "6"


def test_get_stats(engine):
    """Test statistics retrieval"""
    stats = engine.get_stats()
    assert "total_rules" in stats
    assert stats["total_rules"] == 5
    assert "aho_corasick_enabled" in stats
    assert "ip_patterns" in stats
    assert "domain_patterns" in stats
    assert "port_patterns" in stats
    assert "regex_patterns" in stats


def test_thread_safety(engine):
    """Test thread-safe operations"""
    import threading
    import time
    
    results = []
    errors = []
    
    def match_worker():
        try:
            for i in range(100):
                payload = {"url": f"http://test{i}.com/malware"}
                match = engine.match(payload)
                results.append(match is not None)
                time.sleep(0.001)
        except Exception as e:
            errors.append(e)
    
    # Create multiple threads
    threads = [threading.Thread(target=match_worker) for _ in range(5)]
    
    # Start all threads
    for t in threads:
        t.start()
    
    # Reload rules while matching
    time.sleep(0.1)
    new_rules = [
        SignatureRule(id="7", type="payload_contains", pattern="test", severity="low", source="test")
    ]
    engine.hot_reload(new_rules)
    
    # Wait for completion
    for t in threads:
        t.join()
    
    # Verify no errors occurred
    assert len(errors) == 0
    assert len(results) == 500  # 5 threads * 100 iterations


def test_performance_large_rule_set():
    """Performance test with large number of rules"""
    # Create 1000 rules
    rules = [
        SignatureRule(
            id=str(i),
            type="payload_contains",
            pattern=f"pattern{i}",
            severity="low",
            source="test"
        )
        for i in range(1000)
    ]
    
    engine = OptimizedSignatureEngine()
    engine.load_rules(rules)
    
    # Test matching performance
    import time
    start = time.time()
    for i in range(100):
        payload = {"url": f"http://test.com/pattern{i}"}
        engine.match(payload)
    elapsed = time.time() - start
    
    # Should complete 100 matches in reasonable time (< 1 second)
    assert elapsed < 1.0, f"Performance test failed: {elapsed:.3f}s for 100 matches"
    print(f"Performance: {elapsed:.3f}s for 100 matches with 1000 rules")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


