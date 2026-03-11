import requests, time
URLS = [
  "http://127.0.0.1:8000/index.html",
  "http://127.0.0.1:8000/malware.txt",   # contains "malware" — triggers heuristic
  "http://127.0.0.1:8000/login"
]
for i in range(500):
    url = URLS[i % len(URLS)]
    try:
        requests.get(url, timeout=2)
    except Exception:
        pass
    time.sleep(0.2)
