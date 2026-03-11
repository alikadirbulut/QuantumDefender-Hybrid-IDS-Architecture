#!/usr/bin/env python3
"""
Quick test script to verify VM agent connection to cloud server.
Run this on your VM (192.168.1.24) to test connectivity.
"""
import requests
import json
import socket
import sys

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def test_cloud_connection(cloud_url):
    """Test connection to cloud server"""
    print(f"\n{'='*60}")
    print(f"Testing connection to: {cloud_url}")
    print(f"{'='*60}\n")
    
    # Test 1: Health check
    print("1. Testing /health endpoint...")
    try:
        health_url = cloud_url.replace("/analyze", "/health")
        response = requests.get(health_url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Health check passed!")
            print(f"   Status: {data.get('status')}")
            print(f"   Uptime: {data.get('uptime_sec', 0):.1f}s")
        else:
            print(f"   ❌ Health check failed: HTTP {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Connection refused! Is the cloud server running?")
        print(f"   Make sure the cloud server is running on the target machine.")
        return False
    except requests.exceptions.Timeout:
        print(f"   ❌ Connection timeout! Check firewall settings.")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False
    
    # Test 2: Send test event
    print("\n2. Sending test event...")
    try:
        test_event = {
            "agent_id": "test-vm-agent",
            "host": socket.gethostname(),
            "src_ip": get_local_ip(),
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "url": "http://test.example.com/test",
            "bytes_sent": 1024,
            "bytes_recv": 2048,
            "timestamp": "2024-01-01T12:00:00Z",
            "region": "Test Region",
            "detection_source": "test"
        }
        
        response = requests.post(cloud_url, json=[test_event], timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Test event sent successfully!")
            print(f"   Response: {data}")
        else:
            print(f"   ❌ Failed to send event: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"   ❌ Error sending event: {e}")
        return False
    
    # Test 3: Check UI endpoint
    print("\n3. Testing UI endpoint...")
    try:
        ui_url = cloud_url.replace("/analyze", "/ui")
        response = requests.get(ui_url, timeout=5)
        if response.status_code == 200:
            print(f"   ✅ UI endpoint accessible!")
            print(f"   Open in browser: {ui_url}")
        else:
            print(f"   ⚠️  UI endpoint returned: HTTP {response.status_code}")
    except Exception as e:
        print(f"   ⚠️  UI check failed: {e}")
    
    print(f"\n{'='*60}")
    print("✅ All tests passed! Your agent should be able to connect.")
    print(f"{'='*60}\n")
    return True

if __name__ == "__main__":
    # Default cloud URL - change this to your cloud server IP
    if len(sys.argv) > 1:
        cloud_url = sys.argv[1]
    else:
        # Prompt for cloud server IP
        print("\n" + "="*60)
        print("QuantumDefender VM Connection Test")
        print("="*60)
        print(f"\nYour VM IP: {get_local_ip()}")
        print("\nEnter the IP address of the machine running the cloud server")
        print("(e.g., 192.168.1.100 or the IP of your host machine)")
        cloud_ip = input("\nCloud Server IP: ").strip()
        
        if not cloud_ip:
            print("❌ No IP provided. Exiting.")
            sys.exit(1)
        
        cloud_url = f"http://{cloud_ip}:5000/analyze"
    
    if not test_cloud_connection(cloud_url):
        print("\n❌ Connection test failed!")
        print("\nTroubleshooting:")
        print("1. Make sure the cloud server is running: python mock_cloud.py")
        print("2. Check firewall settings on the cloud server")
        print("3. Verify the IP address is correct")
        print("4. Ensure both machines are on the same network")
        sys.exit(1)
    
    print("\n📝 Next steps:")
    print(f"1. Update your agent config.json with:")
    print(f'   "CLOUD_URL": "{cloud_url}"')
    print("2. Start your agent on the VM")
    print("3. Check the cloud dashboard for incoming events")



