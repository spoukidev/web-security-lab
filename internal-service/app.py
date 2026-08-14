"""Controlled mock internal service used only by the later SSRF lab."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class InternalHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        payload = json.dumps({"service": "internal-mock", "message": "lab-only response"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _: str, *__: object) -> None:
        """Keep local demo output focused."""


HTTPServer(("0.0.0.0", 8000), InternalHandler).serve_forever()
