# post_server.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        print(f"[HTTP SERVER] Received POST {self.path} length={len(body)}")
        # optionally save body to file:
        # with open("last_upload.bin", "wb") as f: f.write(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Simple test server")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 80), Handler)
    print("Listening on 0.0.0.0:80 (accepts POST)...")
    server.serve_forever()
