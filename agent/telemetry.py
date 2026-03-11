import threading, requests, time

class TelemetrySender:
    def __init__(self, cloud_url, log_func=None):
        self.cloud_url = cloud_url
        self.log = log_func or (lambda x: None)
        self.buffer = []
        self.last_send = time.time()

    def add_event(self, event):
        self.buffer.append(event)
        if len(self.buffer) >= 20 or (time.time() - self.last_send > 2):
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        batch = self.buffer[:]
        self.buffer.clear()
        self.last_send = time.time()
        threading.Thread(target=self._send_batch, args=(batch,), daemon=True).start()

    def _send_batch(self, batch):
        try:
            r = requests.post(self.cloud_url, json=batch, timeout=5)
            if r.ok:
                self.log(f"📤 Sent {len(batch)} events to cloud.")
            else:
                self.log(f"⚠️ Cloud error {r.status_code}")
        except Exception as e:
            self.log(f"⚠️ Send failed: {e}")
