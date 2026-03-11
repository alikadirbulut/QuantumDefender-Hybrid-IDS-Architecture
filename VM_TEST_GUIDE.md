# VM Agent Connection Test Guide

## Quick Setup for Testing from VM (192.168.1.24)

### Step 1: Find Your Host Machine IP

On your **host machine** (where the cloud server runs), find your IP:

**Windows:**
```powershell
ipconfig | findstr /i "IPv4"
```

Look for the IP in your local network (usually starts with 192.168.x.x)

**Example output:**
```
IPv4 Address. . . . . . . . . . . . : 192.168.1.100
```

### Step 2: Start the Cloud Server

On your **host machine**, make sure the cloud server is running:

```bash
python mock_cloud.py
```

You should see:
```
[+] QuantumDefender Cloud v9.0 running at http://127.0.0.1:5000/ui
```

The server binds to `0.0.0.0:5000`, so it's accessible from the network.

### Step 3: Test Connection from VM

On your **VM (192.168.1.24)**, run the test script:

```bash
python test_vm_connection.py
```

Or specify the cloud server IP directly:
```bash
python test_vm_connection.py http://192.168.1.100:5000/analyze
```

**Expected output:**
```
✅ Health check passed!
✅ Test event sent successfully!
✅ UI endpoint accessible!
```

### Step 4: Update Agent Config on VM

On your **VM**, edit the agent configuration file:

**File:** `agent_config.json` or `config.json`

```json
{
  "CLOUD_URL": "http://192.168.1.100:5000/analyze",
  "BATCH_SIZE": 20,
  "SEND_INTERVAL": 2,
  "FILTER": "tcp and (port 80 or port 443)"
}
```

**Replace `192.168.1.100` with your actual host machine IP!**

### Step 5: Start the Agent on VM

On your **VM**, start the agent (as Administrator):

```bash
python agent.py
```

### Step 6: Verify in Cloud Dashboard

1. Open your browser on the **host machine**
2. Navigate to: `http://localhost:5000/ui` (or `http://192.168.1.100:5000/ui`)
3. You should see:
   - Events appearing in the Live Feed
   - Agent showing up in the Agents section
   - Real-time metrics updating

## Troubleshooting

### Connection Refused
- **Check:** Is the cloud server running?
- **Check:** Is Windows Firewall blocking port 5000?
- **Fix:** Add firewall rule or temporarily disable firewall for testing

### Connection Timeout
- **Check:** Are both machines on the same network?
- **Check:** Can you ping the host machine from the VM?
- **Test:** `ping 192.168.1.100` from VM

### No Events Appearing
- **Check:** Agent logs for connection errors
- **Check:** Cloud server logs for incoming requests
- **Verify:** Agent config has correct CLOUD_URL

### Firewall Configuration

**Windows Firewall - Allow Port 5000:**

```powershell
# Run as Administrator
New-NetFirewallRule -DisplayName "QuantumDefender Cloud" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

Or use Windows Firewall GUI:
1. Windows Defender Firewall → Advanced Settings
2. Inbound Rules → New Rule
3. Port → TCP → Specific Ports: 5000
4. Allow the connection
5. Apply to all profiles

## Quick Test Commands

**From VM, test connectivity:**
```bash
# Test if port is open
telnet 192.168.1.100 5000

# Or with PowerShell on Windows
Test-NetConnection -ComputerName 192.168.1.100 -Port 5000
```

**From VM, send test event manually:**
```bash
curl -X POST http://192.168.1.100:5000/analyze \
  -H "Content-Type: application/json" \
  -d '[{
    "agent_id": "test-agent",
    "host": "test-vm",
    "src_ip": "192.168.1.24",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "url": "http://test.com",
    "bytes_sent": 1024,
    "bytes_recv": 2048,
    "timestamp": "2024-01-01T12:00:00Z"
  }]'
```

## What to Expect

Once connected, you should see:

1. **In Cloud Dashboard:**
   - Agent appears in "Agents" section
   - Events streaming in "Live Feed"
   - Metrics updating in real-time
   - Agent status showing as "active"

2. **In Agent UI (on VM):**
   - Cloud status showing as "Connected"
   - Events being sent successfully
   - No connection errors in logs

## Network Diagram

```
┌─────────────────────┐         ┌─────────────────────┐
│   Host Machine      │         │   VM (192.168.1.24) │
│   (192.168.1.100)  │◄────────┤                     │
│                     │         │   Agent Running     │
│  Cloud Server       │         │                     │
│  Port 5000          │         │  Sends Events       │
│  mock_cloud.py      │         │  to Cloud           │
└─────────────────────┘         └─────────────────────┘
         │
         │ Browser
         ▼
   http://localhost:5000/ui
   (Dashboard)
```



