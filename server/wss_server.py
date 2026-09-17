#!/usr/bin/env python3
"""
Neverlose WSS Server - Port 30030

Handles the WebSocket protocol used by GetSerial (vtable slot 1) and fn3 (vtable slot 3).

Protocol (probed from crack server at 145.239.80.134:30030, 2026-02-22):
  1. Client connects via WSS (TLS)
  2. Server waits for client's FIRST message (any content, even empty string)
  3. Server responds with 3 frames:
     - Text: Auth JSON {"Type":"Auth","Message":"...","Data":"..."}
     - Binary: 385,360-byte encrypted module blob
     - Binary: 80-byte encrypted key blob
  4. Server does NOT respond to any subsequent messages
     (types 0-9 all timeout on the crack server)

  The crack server is purely a payload delivery system — it does not process
  auth, serial, or data requests. Those are handled by our Requestor.cpp hooks.

Usage:
  nix-shell -p "python3.withPackages (ps: [ps.websockets])" openssl --run "python3 server/wss_server.py"
"""

import asyncio
import ssl
import json
import os
import sys
import logging
import time
import ipaddress
from pathlib import Path

try:
    import websockets
except ImportError:
    print("Missing websockets. Run with:")
    print('  nix-shell -p "python3.withPackages (ps: [ps.websockets])" openssl --run "python3 server/wss_server.py"')
    sys.exit(1)

HOST = "0.0.0.0"
PORT = 30030

AUTH_MESSAGE = "fz8XfUGGBvylN7IW"
AUTH_DATA = "5aAxpFpna5QqvYMv"

DATA_DIR = Path(__file__).parent / "data"
CERT_FILE = Path(__file__).parent / "cert.pem"
KEY_FILE = Path(__file__).parent / "key.pem"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("wss")

# Load payloads at startup
MODULE_BLOB = (DATA_DIR / "module.bin").read_bytes()
KEY_BLOB = (DATA_DIR / "key.bin").read_bytes()

assert len(MODULE_BLOB) == 385360, f"module.bin size mismatch: {len(MODULE_BLOB)}"
assert len(KEY_BLOB) == 80, f"key.bin size mismatch: {len(KEY_BLOB)}"

# Message log for analysis
MSG_LOG = []


async def handle_client(ws):
    addr = ws.remote_address
    log.info(f"[+] Connection from {addr[0]}:{addr[1]}")
    msg_num = 0

    try:
        # Wait for client's first message before sending anything
        first_msg = await ws.recv()
        timestamp = time.time()
        msg_num += 1

        if isinstance(first_msg, str):
            log.info(f"  [C->S] #{msg_num} text ({len(first_msg)}B): {first_msg[:200]}")
            MSG_LOG.append({"dir": "C->S", "type": "text", "data": first_msg, "time": timestamp})
        else:
            log.info(f"  [C->S] #{msg_num} binary ({len(first_msg)}B): {first_msg[:32].hex()}")
            MSG_LOG.append({"dir": "C->S", "type": "binary", "size": len(first_msg), "hex": first_msg[:64].hex(), "time": timestamp})

        # Frame 1: Auth JSON
        auth = json.dumps({"Type": "Auth", "Message": AUTH_MESSAGE, "Data": AUTH_DATA})
        await ws.send(auth)
        log.info(f"  [S->C] Auth JSON ({len(auth)}B): {auth}")

        # Frame 2: Encrypted module payload
        await ws.send(MODULE_BLOB)
        log.info(f"  [S->C] Module blob ({len(MODULE_BLOB):,}B)")

        # Frame 3: Encrypted key material
        await ws.send(KEY_BLOB)
        log.info(f"  [S->C] Key blob ({len(KEY_BLOB)}B): {KEY_BLOB.hex()}")

        log.info(f"  [S->C] All 3 frames sent, listening for client messages...")

        # After initial 3 frames, the crack server ignores all further messages.
        async for msg in ws:
            timestamp = time.time()
            msg_num += 1

            if isinstance(msg, str):
                log.info(f"  [C->S] #{msg_num} text ({len(msg)}B): {msg[:200]}")
                MSG_LOG.append({"dir": "C->S", "type": "text", "data": msg, "time": timestamp})
            else:
                log.info(f"  [C->S] #{msg_num} binary ({len(msg)}B): {msg[:32].hex()}")
                MSG_LOG.append({"dir": "C->S", "type": "binary", "size": len(msg), "hex": msg[:64].hex(), "time": timestamp})

    except websockets.ConnectionClosed as e:
        log.info(f"  [!] Connection closed: code={e.code} reason={e.reason}")
    except Exception as e:
        log.error(f"  [!] Error: {e}")

    log.info(f"[-] Disconnected {addr[0]}:{addr[1]} (total messages: {msg_num})")


def generate_cert():
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    log.info("Generating self-signed TLS certificate...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256())
        )
        KEY_FILE.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        # Fallback: use stdlib ssl to generate via temporary context trick
        import subprocess
        import tempfile
        # Last resort: try openssl command
        ret = os.system(
            f'openssl req -x509 -newkey rsa:2048 -keyout "{KEY_FILE}" -out "{CERT_FILE}" '
            f'-days 365 -nodes -subj "/CN=127.0.0.1" 2>/dev/null'
        )
        if ret != 0:
            print("Failed to generate TLS certificate.")
            print("Install the 'cryptography' package: pip install cryptography")
            sys.exit(1)


async def main():
    generate_cert()

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(CERT_FILE, KEY_FILE)

    async with websockets.serve(
        handle_client,
        HOST,
        PORT,
        ssl=ssl_ctx,
        max_size=50 * 1024 * 1024,
        ping_interval=None,
    ):
        log.info(f"Neverlose WSS server on wss://{HOST}:{PORT}/")
        log.info(f"  Auth Message: {AUTH_MESSAGE}")
        log.info(f"  Auth Data:    {AUTH_DATA}")
        log.info(f"  Module blob:  {len(MODULE_BLOB):,} bytes")
        log.info(f"  Key blob:     {len(KEY_BLOB)} bytes")
        log.info("")
        log.info("Protocol (matches crack server behavior):")
        log.info("  1. Client connects via WSS")
        log.info("  2. Server waits for client's first message (any content)")
        log.info("  3. Server sends: Auth JSON + module blob + key blob")
        log.info("  4. Server ignores all subsequent messages")
        log.info("")
        log.info("Update setup_hooks.cpp getaddrinfo hook to point here:")
        log.info('  *ppNodeName = "127.0.0.1";')
        log.info('  *ppServiceName = "30030";')
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
