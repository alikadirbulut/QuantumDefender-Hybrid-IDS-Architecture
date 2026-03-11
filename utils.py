import re, psutil, subprocess

def block_ip(ip, enable=False):
    if not enable:
        return
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name=QuantumDefender_Block_{ip}",
        "dir=out", "action=block", f"remoteip={ip}"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def find_process_for_socket(local_ip, local_port):
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.laddr:
                continue
            if (c.laddr.ip, c.laddr.port) == (local_ip, local_port):
                if c.pid:
                    p = psutil.Process(c.pid)
                    return {"pid": c.pid, "name": p.name(), "exe": p.exe(), "user": p.username()}
    except Exception:
        pass
    return {}

def extract_url(payload: str):
    try:
        urls = re.findall(r"(https?://[^\s\"']+|Host:\s?[^\r\n]+)", payload, flags=re.IGNORECASE)
        urls = [u.replace("Host:", "").strip() for u in urls]
        if urls:
            return urls[0][:150]
    except Exception:
        pass
    return None

def readable_bytes(num):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"
