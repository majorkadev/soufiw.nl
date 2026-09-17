#!/usr/bin/env python3
"""
Neverlose HTTP Server - Port 30031

Replicates the Express.js HTTP server for the Neverlose binary.
This handles MakeRequest (vtable slot 0) and QueryLuaLibrary (vtable slot 4) calls.
WebSocket-based fn3 (vtable slot 3) and GetSerial (vtable slot 1) are handled by wss_server.py.

Discovered routes (via static XOR decryption of nl.bin):
  GET /api/config                                    - Client config (404 on crack server)
  GET /api/getavatar?size=100&token=<TOKEN>           - User avatar (ONLY working HTTP route on crack server)
  GET /api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo - Crash log (404 on crack server)
  GET /lua/<name>?token=T&cheat=csgo&build=B         - Lua library fetch (404 on crack server)

Crack server probe results (2026-02-22):
  - Only /api/getavatar returns 200 (PNG image, ~19-29KB depending on size param)
  - All other routes return Express-style 404
  - Token param is ignored (works without it)
  - Server header: X-Powered-By: Express

Usage:
  nix-shell -p python3 --run "python3 server/http_server.py"
"""

import json
import sys
import logging
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

HOST = "0.0.0.0"
PORT = 30031

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("http")

# Spoofed serial (from Requestor.cpp)
SPOOFED_SERIAL = (
    "g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA"
    "2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Fr"
    "g1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2"
    "YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNH"
    "r0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7Iq"
    "sylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXS"
    "iWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2"
    "JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCd"
    "xy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6I"
    "pkVUBIUVup+4JvWFseL5UkPOQqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb"
    "7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE="
)

# Request log for analysis
REQUEST_LOG = []

# Lua scripts directory (serve from here if available)
LUA_DIR = Path(__file__).parent / "lua"

# Avatar image (dumped from crack server at 145.239.80.134:30031)
DATA_DIR = Path(__file__).parent / "data"
AVATAR_FILE = DATA_DIR / "avatar.png"


class NLRequestHandler(BaseHTTPRequestHandler):
    server_version = "Express"

    def log_message(self, format, *args):
        pass

    def _log_request(self, method):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        body = None
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            raw = self.rfile.read(content_length)
            try:
                body = json.loads(raw)
            except Exception:
                body = raw.hex() if len(raw) < 1024 else f"<{len(raw)} bytes>"

        entry = {
            "method": method,
            "path": parsed.path,
            "query": params,
            "headers": dict(self.headers),
            "body": body,
            "user_agent": self.headers.get("User-Agent", ""),
            "timestamp": time.time(),
        }
        REQUEST_LOG.append(entry)

        log.info(f"  {method} {self.path}")
        if params:
            log.info(f"    params: {params}")
        if body:
            log.info(f"    body: {json.dumps(body) if isinstance(body, dict) else body}")

        return parsed, params, body

    def _send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _send_binary(self, code, data, content_type="application/octet-stream"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(data)

    def _send_express_404(self, method):
        html = (
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
            "<meta charset=\"utf-8\">\n<title>Error</title>\n"
            "</head>\n<body>\n"
            f"<pre>Cannot {method} {self.path}</pre>\n"
            "</body>\n</html>\n"
        )
        body = html.encode()
        self.send_response(404)
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "Express")
        self.send_header("Connection", "keep-alive")
        self.send_header("Keep-Alive", "timeout=5")
        self.end_headers()
        self.wfile.write(body)

    def _route(self, method):
        parsed, params, body = self._log_request(method)
        path = parsed.path.rstrip("/") or "/"
        token = params.get("token", [None])[0]
        cheat = params.get("cheat", [None])[0]
        build = params.get("build", [None])[0]

        # =====================================================================
        # Route: /api/config
        # Source: Confirmed via Unicorn emulation (vtable_site1_MakeRequest)
        # Caller: Function 0x415890C0 via MakeRequest (vtable slot 0)
        # The client fetches initial configuration on startup.
        # =====================================================================
        if path == "/api/config":
            log.info("    -> MakeRequest(/api/config)")
            self._send_json(200, {
                "status": "ok",
                "version": "2.0",
                "update": False,
                "config": {
                    "glow": True,
                    "esp": True,
                    "aimbot": True,
                    "misc": True,
                },
            })
            return

        # =====================================================================
        # Route: /api/getavatar
        # Source: XOR decryption of function 0x415890C0
        # Caller: MakeRequest (vtable slot 0)
        # Full route: api/getavatar?size=100&token=<TOKEN>
        # Response: Avatar image data (PNG/JPEG) or URL
        # The function also references JSON fields: Message, Sender, Type, Time, Msg
        # suggesting the response may include chat message data alongside avatar.
        # =====================================================================
        if path in ("/api/getavatar", "/getavatar"):
            size = params.get("size", ["100"])[0]
            log.info(f"    -> MakeRequest(/api/getavatar, size={size}, token={token})")
            # Serve the real avatar dumped from crack server
            if AVATAR_FILE.exists():
                avatar_data = AVATAR_FILE.read_bytes()
                self._send_binary(200, avatar_data, "image/png")
            else:
                # Fallback: minimal 1x1 transparent PNG
                png_1x1 = (
                    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
                    b'\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89'
                    b'\x00\x00\x00\nIDATx\x9cb\x00\x00\x00\x02\x00\x01'
                    b"\xe5'\xde\xfc\x00\x00\x00\x00IEND\xaeB`\x82"
                )
                self._send_binary(200, png_1x1, "image/png")
            return

        # =====================================================================
        # Route: /api/sendlog
        # Source: XOR decryption of function 0x415ECC45
        # Caller: fn3 (vtable slot 3) — but sends HTTP request
        # Full route: api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo
        # The dump parameter contains register values (eax=, ebp=, etc.)
        # This is the crash/error reporting endpoint.
        # =====================================================================
        if path in ("/api/sendlog", "/sendlog"):
            a = params.get("a", [None])[0]
            cont = params.get("cont", [None])[0]
            dump = params.get("dump", [None])[0]
            log.info(f"    -> api/sendlog (token={token}, a={a}, build={build}, "
                     f"cont={cont}, dump={dump}, cheat={cheat})")
            self._send_json(200, {"status": "ok"})
            return

        # =====================================================================
        # Route: /lua/<name>
        # Source: QueryLuaLibrary (vtable slot 4)
        # Caller: Various lua script loading functions
        # The client requests lua libraries by name.
        # Requestor.cpp returns the library name as-is (placeholder).
        # =====================================================================
        if path.startswith("/lua/"):
            libname = path[5:]
            log.info(f"    -> QueryLuaLibrary({libname})")
            # Try to serve from lua directory if it exists
            lua_file = LUA_DIR / f"{libname}.lua"
            if lua_file.exists():
                content = lua_file.read_text()
                log.info(f"    -> Serving {lua_file} ({len(content)} bytes)")
                self._send_text(200, content)
            else:
                # Return empty script (won't crash)
                self._send_text(200, f"-- lua library: {libname}\n")
            return

        # =====================================================================
        # Route: POST with JSON body (GetSerial fallback)
        # Source: Requestor.cpp GetSerial function
        # The client may POST auth requests to HTTP as fallback.
        # Request: {"params":{"hash":"...","hash2":"..."},"type":4}
        # Response: base64-encoded serial string
        # =====================================================================
        if body and isinstance(body, dict) and body.get("type") == 4 and method == "POST":
            log.info("    -> GetSerial (type 4 auth request via HTTP)")
            self._send_text(200, SPOOFED_SERIAL)
            return

        # =====================================================================
        # Catch-all: log unknown routes for discovery
        # =====================================================================
        log.info(f"    -> UNKNOWN ROUTE (logging for analysis)")
        self._send_express_404(method)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def do_OPTIONS(self):
        self._route("OPTIONS")

    def do_HEAD(self):
        self._route("HEAD")


def main():
    # Create lua directory
    LUA_DIR.mkdir(exist_ok=True)

    server = HTTPServer((HOST, PORT), NLRequestHandler)
    log.info(f"Neverlose HTTP server on http://{HOST}:{PORT}/")
    log.info(f"  Serial: {SPOOFED_SERIAL[:40]}...")
    log.info("")
    log.info("Discovered HTTP routes (via MakeRequest, vtable slot 0):")
    log.info("  GET /api/config")
    log.info("  GET /api/getavatar?size=100&token=<TOKEN>")
    log.info("  GET /api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo")
    log.info("  GET /lua/<name>?token=T&cheat=csgo&build=B")
    log.info("")
    log.info("Note: Most requests use WebSocket (fn3, vtable slot 3) via wss_server.py")
    log.info("  WebSocket JSON types: {\"type\":0..5, \"params\":{...}}")
    log.info("")
    log.info("Waiting for requests...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("\nShutting down...")
        if REQUEST_LOG:
            log_path = Path(__file__).parent / "request_log.json"
            with open(log_path, "w") as f:
                json.dump(REQUEST_LOG, f, indent=2)
            log.info(f"Saved {len(REQUEST_LOG)} requests to {log_path}")
        server.server_close()


if __name__ == "__main__":
    main()
