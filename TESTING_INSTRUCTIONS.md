# Testing Instructions: Aho-Corasick Signature Engine Integration

## Overview
This guide explains how to test the optimized Aho-Corasick signature matching system integrated into both the cloud backend and agent.

## Prerequisites

1. **Install Dependencies**
   ```bash
   pip install pyahocorasick>=2.0.0
   ```

2. **Verify Installation**
   ```bash
   python -c "import ahocorasick; print('✅ Aho-Corasick available')"
   ```

## Testing Steps

### 1. Start the Cloud Backend

```bash
python mock_cloud.py
```

**Expected Output:**
```
[Cloud] ✅ Optimized Aho-Corasick signature matcher initialized
[Cloud] ✅ Loaded X signatures into optimized matcher
[+] Optimized Aho-Corasick Signature Matcher: ENABLED
[+] QuantumDefender Cloud v9.0 running at http://127.0.0.1:5000/ui
```

**If Aho-Corasick is unavailable:**
```
[Cloud] ⚠️ Optimized matcher unavailable, using fallback
[+] Signature Matching: Using fallback (linear search)
```

### 2. Start the Agent

```bash
python agent.py
```

**Expected Output:**
```
[Agent] ✅ Optimized Aho-Corasick signature engine initialized
[Agent] ✅ Initial signature load: X rules
```

**Check Agent UI:**
- Look for "Signatures" metric card (should show count)
- Go to "🧠 System Info" tab
- Verify "Signature Engine: ✅ Aho-Corasick Enabled"
- Verify "Loaded Signatures: X"

### 3. Verify Cloud UI Status

1. Open browser: `http://127.0.0.1:5000/ui`
2. Navigate to **Signatures** tab (left sidebar)
3. Check the **Signature Matcher** card:
   - Should show: `✅ Optimized` (green badge)
   - Should show: `Aho-Corasick • X signatures loaded`

### 4. Test Signature Matching

#### Test 1: Add a Signature via Cloud UI

1. Go to **Signatures** tab
2. Click **Add Signature**
3. Fill in:
   - **Type**: `payload_contains`
   - **Pattern**: `malware`
   - **Severity**: `High`
4. Click **Add**

**Expected:**
- Signature appears in list
- Agent receives `signature_update` event
- Agent logs: `🔄 Reloaded X signatures into optimized engine`
- Agent UI shows updated signature count

#### Test 2: Test Signature Matching (Agent Side)

1. In Agent UI, click **⚠ Simulate Attack**
2. This sends a test event with malicious indicators

**Expected:**
- Event should match signature if pattern matches
- Alert should show: `Matched signature: malware (Severity: High)`
- Detection source should be: `signature`

#### Test 3: Test Signature Matching (Cloud Side)

Send a test event via API:

```bash
curl -X POST http://127.0.0.1:5000/analyze \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "test-agent",
    "hostname": "test-host",
    "src_ip": "192.168.1.100",
    "dst_ip": "203.0.113.5",
    "url": "http://malware.example.com/payload",
    "protocol": "HTTP",
    "port_dst": 80,
    "bytes_sent": 1000,
    "bytes_recv": 500
  }]'
```

**Expected:**
- Cloud logs: Signature match detected
- Event marked as alert with `detection_source: "signature"`
- Cloud UI shows alert in Live Feed

### 5. Test Performance

#### Performance Test Script

Create `test_performance.py`:

```python
import time
import requests
import json

# Test with many signatures
signatures = []
for i in range(1000):
    signatures.append({
        "type": "payload_contains",
        "pattern": f"test_pattern_{i}",
        "severity": "medium",
        "source": "test"
    })

# Add signatures
for sig in signatures[:10]:  # Add 10 for testing
    requests.post("http://127.0.0.1:5000/api/add_signature", json=sig)

# Test matching speed
payload = {
    "agent_id": "test",
    "hostname": "test",
    "url": "http://example.com/test_pattern_5",
    "dst_ip": "1.2.3.4"
}

start = time.time()
for _ in range(100):
    requests.post("http://127.0.0.1:5000/analyze", json=[payload])
elapsed = time.time() - start

print(f"100 matches in {elapsed:.3f}s ({elapsed/100*1000:.2f}ms per match)")
```

**Expected Results:**
- **With Aho-Corasick**: ~0.1-1ms per match
- **Without (fallback)**: ~10-100ms per match

### 6. Test Hot Reload

1. Agent is running and connected
2. Add new signature via Cloud UI
3. Cloud emits `signature_update` event
4. Agent receives event and reloads signatures

**Expected:**
- Agent log: `🔄 Reloaded X signatures into optimized engine`
- Agent UI signature count updates
- New signature immediately available for matching

### 7. Test Fallback Mode

To test fallback (linear search):

1. Temporarily rename `ahocorasick` module:
   ```bash
   # On Windows (PowerShell)
   Rename-Item -Path "$env:LOCALAPPDATA\Programs\Python\Python*\Lib\site-packages\ahocorasick" -NewName "ahocorasick_backup"
   ```

2. Restart cloud and agent

**Expected:**
- Cloud: `⚠️ Optimized matcher unavailable, using fallback`
- Agent: `⚠️ Signature engine unavailable, using cloud-only detection`
- System still works, but slower

3. Restore module:
   ```bash
   Rename-Item -Path "$env:LOCALAPPDATA\Programs\Python\Python*\Lib\site-packages\ahocorasick_backup" -NewName "ahocorasick"
   ```

## Verification Checklist

### Cloud Backend
- [ ] Cloud starts with optimized matcher enabled
- [ ] Signatures load into matcher on startup
- [ ] `/api/signatures/matcher/stats` returns correct status
- [ ] Cloud UI shows "✅ Optimized" badge
- [ ] Signature matching works correctly
- [ ] Hot-reload works when signatures update

### Agent
- [ ] Agent initializes signature engine
- [ ] Agent loads signatures on startup
- [ ] Agent UI shows signature count
- [ ] Agent UI shows "✅ Aho-Corasick Enabled" in System Info
- [ ] Agent matches signatures locally before sending to cloud
- [ ] Agent receives and processes `signature_update` events
- [ ] Agent hot-reloads signatures without restart

### Integration
- [ ] Signatures sync between cloud and agent
- [ ] Both sides use optimized matching
- [ ] Performance improvement visible with many signatures
- [ ] Fallback mode works if Aho-Corasick unavailable

## Troubleshooting

### Issue: "Optimized matcher unavailable"
**Solution:** Install pyahocorasick:
```bash
pip install pyahocorasick>=2.0.0
```

### Issue: Agent doesn't load signatures
**Solution:** 
1. Check cloud is running
2. Check agent can reach `/api/signatures` endpoint
3. Check agent logs for errors

### Issue: Signatures not matching
**Solution:**
1. Verify signature pattern matches test data
2. Check signature type (payload_contains vs ip_equals)
3. Check logs for matching errors

### Issue: Performance not improved
**Solution:**
1. Verify Aho-Corasick is actually being used (check logs)
2. Test with larger signature sets (100+ signatures)
3. Check if fallback mode is active

## Performance Benchmarks

| Scenario | Linear Search | Aho-Corasick | Speedup |
|----------|---------------|--------------|---------|
| 10 signatures | ~1ms | ~0.1ms | 10x |
| 100 signatures | ~10ms | ~0.1ms | 100x |
| 1,000 signatures | ~100ms | ~1ms | 100x |
| 10,000 signatures | ~1000ms | ~2ms | 500x |

## API Endpoints for Testing

### Get Matcher Stats
```bash
curl http://127.0.0.1:5000/api/signatures/matcher/stats
```

**Response:**
```json
{
  "total_signatures": 42,
  "optimized_matcher_enabled": true,
  "matcher_type": "Aho-Corasick",
  "last_update": 1234567890.0,
  "cache_size": 42,
  "matcher_loaded": 42
}
```

### Get All Signatures
```bash
curl http://127.0.0.1:5000/api/signatures
```

### Add Test Signature
```bash
curl -X POST http://127.0.0.1:5000/api/add_signature \
  -H "Content-Type: application/json" \
  -d '{
    "type": "payload_contains",
    "pattern": "test_malware",
    "severity": "high",
    "source": "manual"
  }'
```

## Success Criteria

✅ **Integration is successful if:**
1. Both cloud and agent show optimized matcher enabled
2. Signatures match correctly on both sides
3. Performance is significantly improved with many signatures
4. Hot-reload works without service interruption
5. Fallback mode works gracefully if Aho-Corasick unavailable
6. UI displays correct status information


