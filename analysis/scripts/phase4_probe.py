#!/usr/bin/env python3
"""
Phase 4B: Active Server Probing
Probes the server at 145.239.80.134 to understand HTTP and WebSocket protocols.
Dumps ALL binary WebSocket messages to files for full inspection.
"""

import json
import os
import socket
import ssl
import sys
import time
import asyncio
import traceback
import hashlib
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

OUTPUT_PATH = "/tmp/nl_analysis/output/phase4_server_probe.json"
WS_DUMP_DIR = "/tmp/nl_analysis/output/ws_dumps"
SERVER_IP = "145.239.80.134"
HTTP_PORT = 30031
WS_PORT = 30030
TIMEOUT = 15

results = {
    "server": SERVER_IP,
    "http_port": HTTP_PORT,
    "ws_port": WS_PORT,
    "http_probes": [],
    "ws_probes": [],
    "tls_info": {},
    "port_scan": {},
    "errors": [],
    "ws_dump_files": [],
}

# Ensure dump directory exists
os.makedirs(WS_DUMP_DIR, exist_ok=True)

dump_counter = 0

def save_ws_message(msg, label="msg"):
    """Save a WebSocket message to disk. Returns the file path."""
    global dump_counter
    dump_counter += 1
    if isinstance(msg, bytes):
        ext = "bin"
        fname = f"{dump_counter:03d}_{label}.{ext}"
        path = os.path.join(WS_DUMP_DIR, fname)
        with open(path, "wb") as f:
            f.write(msg)
        # Also save full hex dump
        hex_path = os.path.join(WS_DUMP_DIR, f"{dump_counter:03d}_{label}.hex")
        with open(hex_path, "w") as f:
            for i in range(0, len(msg), 16):
                chunk = msg[i:i+16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                f.write(f"{i:08X}  {hex_part:<48s}  {ascii_part}\n")
    else:
        ext = "txt"
        fname = f"{dump_counter:03d}_{label}.{ext}"
        path = os.path.join(WS_DUMP_DIR, fname)
        with open(path, "w") as f:
            f.write(msg)

    results["ws_dump_files"].append({
        "file": path,
        "label": label,
        "size": len(msg),
        "type": "binary" if isinstance(msg, bytes) else "text",
        "sha256": hashlib.sha256(msg if isinstance(msg, bytes) else msg.encode()).hexdigest(),
    })
    print(f"    Saved: {fname} ({len(msg)} bytes)")
    return path


def probe_port(host, port, timeout=5):
    """Check if a port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def probe_tls(host, port, timeout=5):
    """Check if a port speaks TLS and get certificate info."""
    info = {"tls": False, "error": None}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                info["tls"] = True
                info["cipher"] = ssock.cipher()
                info["version"] = ssock.version()
                try:
                    cert_dict = ssock.getpeercert()
                    if cert_dict:
                        info["cert_subject"] = str(cert_dict.get("subject", ""))
                        info["cert_issuer"] = str(cert_dict.get("issuer", ""))
                        info["cert_notBefore"] = cert_dict.get("notBefore", "")
                        info["cert_notAfter"] = cert_dict.get("notAfter", "")
                except Exception:
                    pass
                # Get raw cert in DER
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    cert_path = os.path.join(WS_DUMP_DIR, f"server_cert_port{port}.der")
                    with open(cert_path, "wb") as f:
                        f.write(cert_der)
                    info["cert_der_path"] = cert_path
                    info["cert_sha256"] = hashlib.sha256(cert_der).hexdigest()
    except ssl.SSLError as e:
        info["error"] = f"SSL error: {str(e)}"
    except ConnectionRefusedError:
        info["error"] = "Connection refused"
    except socket.timeout:
        info["error"] = "Connection timed out"
    except Exception as e:
        info["error"] = str(e)
    return info


def raw_http_probe(host, port, method="GET", path="/", headers=None, body=None, use_tls=False):
    """Send a raw HTTP request and capture the full response."""
    result = {
        "method": method,
        "path": path,
        "status": None,
        "headers": {},
        "body": None,
        "error": None,
        "raw_response_preview": None,
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))

        req = f"{method} {path} HTTP/1.1\r\n"
        req += f"Host: {host}:{port}\r\n"
        if headers:
            for k, v in headers.items():
                req += f"{k}: {v}\r\n"
        if body:
            req += f"Content-Length: {len(body)}\r\n"
        req += "\r\n"
        if body:
            req += body

        sock.send(req.encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            except socket.timeout:
                break

        sock.close()

        if response:
            # Save full raw response
            safe_path = path.replace("/", "_").strip("_") or "root"
            dump_path = os.path.join(WS_DUMP_DIR, f"http_{method}_{safe_path}.raw")
            with open(dump_path, "wb") as f:
                f.write(response)

            result["raw_response_preview"] = response[:4096].decode("latin-1")
            try:
                header_end = response.find(b"\r\n\r\n")
                if header_end > 0:
                    header_part = response[:header_end].decode("latin-1")
                    body_part = response[header_end + 4:]
                    lines = header_part.split("\r\n")
                    if lines:
                        status_line = lines[0]
                        parts = status_line.split(" ", 2)
                        if len(parts) >= 2:
                            result["status"] = int(parts[1])
                        for line in lines[1:]:
                            if ": " in line:
                                k, v = line.split(": ", 1)
                                result["headers"][k] = v
                    result["body"] = body_part[:8192].decode("latin-1", errors="replace")
                    result["body_size"] = len(body_part)
            except Exception as e:
                result["error"] = f"Parse error: {str(e)}"
        else:
            result["error"] = "No response received"

    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


def http_probing():
    """Probe the HTTP endpoint."""
    print("[Phase 4B] HTTP Probing...")

    routes_to_try = ["/", "/api/", "/auth/", "/serial/", "/lua/", "/config/",
                     "/user/", "/v1/", "/ws/", "/health", "/status",
                     "/api/v1/", "/api/auth/", "/api/serial/",
                     "/api/lua/library", "/api/config/get"]

    try:
        with open("/tmp/nl_analysis/output/phase1_results.json", "r") as f:
            phase1 = json.load(f)
            for cat in ["http_route", "api_endpoint"]:
                for entry in phase1.get("string_categories", {}).get(cat, []):
                    route = entry["string"]
                    if route.startswith("/") and route not in routes_to_try:
                        routes_to_try.append(route)
    except Exception:
        pass

    # Check TLS first
    for port in [HTTP_PORT, WS_PORT]:
        print(f"  Checking TLS on port {port}...")
        tls_info = probe_tls(SERVER_IP, port)
        results["tls_info"][str(port)] = tls_info
        print(f"    TLS: {tls_info['tls']}, Error: {tls_info.get('error', 'none')}")

    use_tls = results["tls_info"].get(str(HTTP_PORT), {}).get("tls", False)

    for route in routes_to_try[:30]:
        print(f"  GET {route} ...")
        probe = raw_http_probe(SERVER_IP, HTTP_PORT, "GET", route,
                               headers={"User-Agent": "NLR/1.0"},
                               use_tls=use_tls)
        results["http_probes"].append(probe)
        if probe["status"]:
            print(f"    Status: {probe['status']}")
        elif probe["error"]:
            print(f"    Error: {probe['error']}")
        time.sleep(0.3)

    # POST requests
    post_bodies = [
        '{"type":4,"params":{"hash":"test","hash2":"test"}}',
        '{"serial":"test"}',
        '{}',
    ]
    for body in post_bodies:
        print(f"  POST / with body: {body[:50]}...")
        probe = raw_http_probe(SERVER_IP, HTTP_PORT, "POST", "/",
                               headers={"User-Agent": "NLR/1.0",
                                        "Content-Type": "application/json"},
                               body=body, use_tls=use_tls)
        results["http_probes"].append(probe)
        if probe["status"]:
            print(f"    Status: {probe['status']}")
        time.sleep(0.3)


async def ws_full_session(uri, ssl_context, session_name, messages_to_send, listen_time=10):
    """Run a full WebSocket session: connect, send messages, capture ALL responses."""
    probe = {
        "uri": uri,
        "session": session_name,
        "connected": False,
        "handshake_headers": {},
        "messages": [],
        "error": None,
    }
    print(f"\n  [{session_name}] Connecting to {uri}...")

    try:
        extra_headers = {"User-Agent": "NLR/1.0"}

        async with websockets.connect(
            uri,
            additional_headers=extra_headers,
            ssl=ssl_context,
            open_timeout=TIMEOUT,
            close_timeout=5,
            ping_timeout=20,
            max_size=10 * 1024 * 1024,  # 10MB max message size
        ) as ws:
            probe["connected"] = True
            print(f"    Connected!")

            if hasattr(ws, 'response_headers'):
                probe["handshake_headers"] = dict(ws.response_headers)

            # Listen for server greeting
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                label = f"{session_name}_server_greeting"
                fpath = save_ws_message(msg, label)
                probe["messages"].append({
                    "direction": "recv",
                    "label": label,
                    "type": "binary" if isinstance(msg, bytes) else "text",
                    "size": len(msg),
                    "dump_file": fpath,
                    "content_preview": msg[:512].hex() if isinstance(msg, bytes) else msg[:1024],
                })
            except asyncio.TimeoutError:
                probe["messages"].append({"direction": "info", "note": "no server greeting"})

            # Send each message and capture response
            for i, (msg_data, msg_label) in enumerate(messages_to_send):
                try:
                    # Save what we're sending
                    send_label = f"{session_name}_send_{i}_{msg_label}"
                    save_ws_message(msg_data, send_label)

                    if isinstance(msg_data, bytes):
                        await ws.send(msg_data)
                        sent_repr = f"binary ({len(msg_data)} bytes): {msg_data[:64].hex()}"
                    else:
                        await ws.send(msg_data)
                        sent_repr = msg_data[:200]

                    print(f"    Sent: {msg_label}")

                    # Collect ALL responses (server might send multiple frames)
                    response_count = 0
                    while True:
                        try:
                            resp = await asyncio.wait_for(ws.recv(), timeout=5)
                            response_count += 1
                            recv_label = f"{session_name}_recv_{i}_{msg_label}_resp{response_count}"
                            fpath = save_ws_message(resp, recv_label)

                            entry = {
                                "direction": "recv",
                                "in_response_to": msg_label,
                                "label": recv_label,
                                "type": "binary" if isinstance(resp, bytes) else "text",
                                "size": len(resp),
                                "dump_file": fpath,
                            }
                            if isinstance(resp, bytes):
                                entry["full_hex"] = resp.hex()
                                entry["content_preview"] = resp[:256].hex()
                            else:
                                entry["content"] = resp
                            probe["messages"].append(entry)

                            # After first response, try to get more with shorter timeout
                        except asyncio.TimeoutError:
                            if response_count == 0:
                                probe["messages"].append({
                                    "direction": "info",
                                    "note": f"no response to {msg_label}",
                                })
                            break
                        except Exception as e:
                            probe["messages"].append({
                                "direction": "error",
                                "note": f"error receiving response to {msg_label}: {str(e)}",
                            })
                            break

                except websockets.exceptions.ConnectionClosed as e:
                    probe["messages"].append({
                        "direction": "error",
                        "note": f"connection closed after sending {msg_label}: code={e.code} reason={e.reason}",
                    })
                    break
                except Exception as e:
                    probe["messages"].append({
                        "direction": "error",
                        "note": f"error sending {msg_label}: {str(e)}",
                    })

            # Final: listen for any trailing messages
            print(f"    Listening for {listen_time}s for additional messages...")
            end_time = asyncio.get_event_loop().time() + listen_time
            trailing_count = 0
            while asyncio.get_event_loop().time() < end_time:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=2)
                    trailing_count += 1
                    label = f"{session_name}_trailing_{trailing_count}"
                    fpath = save_ws_message(msg, label)
                    entry = {
                        "direction": "recv",
                        "label": label,
                        "type": "binary" if isinstance(msg, bytes) else "text",
                        "size": len(msg),
                        "dump_file": fpath,
                    }
                    if isinstance(msg, bytes):
                        entry["full_hex"] = msg.hex()
                    else:
                        entry["content"] = msg
                    probe["messages"].append(entry)
                except asyncio.TimeoutError:
                    continue
                except websockets.exceptions.ConnectionClosed:
                    probe["messages"].append({"direction": "info", "note": "connection closed by server"})
                    break

    except ConnectionRefusedError:
        probe["error"] = "Connection refused"
    except asyncio.TimeoutError:
        probe["error"] = "Connection timed out"
    except Exception as e:
        probe["error"] = str(e)
        probe["traceback"] = traceback.format_exc()

    print(f"    Session done. {len(probe['messages'])} message events.")
    return probe


async def ws_probing():
    """Comprehensive WebSocket probing with full binary dumps."""
    print("\n[Phase 4B] WebSocket Probing (full dumps)...")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Session 1: Auth flow with type 4
    session1 = await ws_full_session(
        f"wss://{SERVER_IP}:{WS_PORT}/",
        ssl_context,
        "auth_flow",
        [
            ('{"params":{"hash":"test","hash2":"test"},"type":4}', "auth_type4"),
        ],
        listen_time=5,
    )
    results["ws_probes"].append(session1)

    await asyncio.sleep(1)

    # Session 2: Try various message types
    session2 = await ws_full_session(
        f"wss://{SERVER_IP}:{WS_PORT}/",
        ssl_context,
        "type_exploration",
        [
            ('{"type":1}', "type1"),
            ('{"type":2}', "type2"),
            ('{"type":3}', "type3"),
            ('{"type":4,"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="}}', "auth_real_hash"),
            ('{"type":5}', "type5"),
            ('{"type":6}', "type6"),
            ('{"type":7}', "type7"),
            ('{"type":8}', "type8"),
            ('{"type":9}', "type9"),
            ('{"type":10}', "type10"),
        ],
        listen_time=5,
    )
    results["ws_probes"].append(session2)

    await asyncio.sleep(1)

    # Session 3: Binary protocol exploration
    session3 = await ws_full_session(
        f"wss://{SERVER_IP}:{WS_PORT}/",
        ssl_context,
        "binary_proto",
        [
            (b'\x04\x00\x00\x00', "binary_4"),
            (b'\x01\x00\x00\x00', "binary_1"),
            (b'\x00\x00\x00\x00', "binary_0"),
            (b'\x02\x00\x00\x00', "binary_2"),
            (b'\x03\x00\x00\x00', "binary_3"),
            (b'\x05\x00\x00\x00', "binary_5"),
        ],
        listen_time=5,
    )
    results["ws_probes"].append(session3)

    await asyncio.sleep(1)

    # Session 4: Auth then send various requests to see what an authenticated session looks like
    session4 = await ws_full_session(
        f"wss://{SERVER_IP}:{WS_PORT}/",
        ssl_context,
        "post_auth",
        [
            ('{"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="},"type":4}', "auth"),
            ('{"type":1}', "post_auth_type1"),
            ('{"type":2}', "post_auth_type2"),
            ('{"type":3}', "post_auth_type3"),
            ('{"type":5}', "post_auth_type5"),
            ('{"type":0}', "post_auth_type0"),
        ],
        listen_time=10,
    )
    results["ws_probes"].append(session4)

    await asyncio.sleep(1)

    # Session 5: Try with different JSON fields
    session5 = await ws_full_session(
        f"wss://{SERVER_IP}:{WS_PORT}/",
        ssl_context,
        "field_exploration",
        [
            ('{"Type":"Auth","params":{"hash":"test"}}', "Type_Auth"),
            ('{"action":"auth","hash":"test"}', "action_auth"),
            ('{"cmd":"serial"}', "cmd_serial"),
            ('{"request":"lua_library","name":"test"}', "req_lua"),
            ('{"type":4,"params":{"hash":"test","hash2":"test","serial":"test"}}', "auth_with_serial"),
        ],
        listen_time=5,
    )
    results["ws_probes"].append(session5)

    # Raw TCP probe for completeness
    print("\n  Raw TCP probe on WS port...")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        raw_sock = socket.create_connection((SERVER_IP, WS_PORT), timeout=TIMEOUT)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=SERVER_IP)

        # Just send some raw bytes and see what happens
        ssl_sock.send(b"HELLO\r\n")
        try:
            data = ssl_sock.recv(4096)
            if data:
                save_ws_message(data, "raw_tls_response")
                results["ws_probes"].append({
                    "type": "raw_tls",
                    "port": WS_PORT,
                    "response_size": len(data),
                    "response_hex": data.hex(),
                })
        except socket.timeout:
            results["ws_probes"].append({
                "type": "raw_tls",
                "port": WS_PORT,
                "note": "no response to raw bytes",
            })
        ssl_sock.close()
    except Exception as e:
        results["ws_probes"].append({
            "type": "raw_tls",
            "port": WS_PORT,
            "error": str(e),
        })


def port_scanning():
    """Quick scan of nearby ports."""
    print("\n[Phase 4B] Port scanning...")
    ports_to_check = [80, 443, 8080, 8443, 30030, 30031, 30032, 30033,
                      30029, 30028, 3000, 3001, 9090, 9091]
    for port in ports_to_check:
        is_open = probe_port(SERVER_IP, port)
        results["port_scan"][str(port)] = is_open
        if is_open:
            print(f"  Port {port}: OPEN")


def main():
    print("[Phase 4B] Starting server probing (with full binary dumps)...")
    print(f"  Target: {SERVER_IP}")
    print(f"  HTTP port: {HTTP_PORT}")
    print(f"  WS port: {WS_PORT}")
    print(f"  Dump dir: {WS_DUMP_DIR}")
    print()

    port_scanning()
    http_probing()

    if HAS_WEBSOCKETS:
        try:
            asyncio.run(ws_probing())
        except Exception as e:
            results["errors"].append(f"WebSocket probing error: {str(e)}")
            results["errors"].append(traceback.format_exc())
            print(f"  WebSocket error: {e}")
    else:
        print("  websockets library not available, skipping WS probing")
        results["errors"].append("websockets library not available")

    # Save results
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Print dump summary
    print(f"\n{'='*60}")
    print(f"  Dump Summary")
    print(f"{'='*60}")
    for df in results.get("ws_dump_files", []):
        print(f"  {df['label']:50s} {df['size']:>10d} bytes  {df['type']}")

    print(f"\n[Phase 4B] Results saved to {OUTPUT_PATH}")
    print(f"[Phase 4B] Binary dumps in {WS_DUMP_DIR}/")
    print(f"[Phase 4B] Complete.")


if __name__ == "__main__":
    main()
