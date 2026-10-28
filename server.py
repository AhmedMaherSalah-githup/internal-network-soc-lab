from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime, timezone

class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "method": "GET",
            "path": self.path,
            "status": 200
        }

        print(json.dumps(event), flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "message": "Internal SOC Lab",
            "path": self.path
        }).encode())

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8080), LabHandler).serve_forever()
