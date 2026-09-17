#!/usr/bin/env python3
"""
Integration tests for Neverlose mock servers.

Tests both HTTP (port 30031) and WebSocket (port 30030) servers.
Parameterized to run against Python or Rust backends.

Usage (Python backend):
  nix-shell -p "python3.withPackages (ps: [ps.websockets ps.pytest ps.pytest-asyncio ps.aiohttp])" \
    --run "pytest server/test_servers.py -v"

Usage (Rust backend):
  TEST_BACKEND=rust pytest server/test_servers.py -v
"""

import asyncio
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import aiohttp
import pytest
import websockets

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_DIR = Path(__file__).parent
DATA_DIR = SERVER_DIR / "data"

HTTP_PORT = 30031
WS_PORT = 30030

BACKEND = os.environ.get("TEST_BACKEND", "python").lower()

SPOOFED_SERIAL_PREFIX = "g6w/cgN2AuDs"

AVATAR_SIZE = 28_823
MODULE_SIZE = 385_360
KEY_SIZE = 80

AUTH_MESSAGE = "fz8XfUGGBvylN7IW"
AUTH_DATA = "5aAxpFpna5QqvYMv"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 10.0):
    """Block until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} not open after {timeout}s")


@pytest.fixture(scope="session")
def servers():
    """Start the appropriate backend servers and yield. Kill on teardown."""
    procs = []

    if BACKEND == "python":
        http_proc = subprocess.Popen(
            [sys.executable, str(SERVER_DIR / "http_server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ws_proc = subprocess.Popen(
            [sys.executable, str(SERVER_DIR / "wss_server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs = [http_proc, ws_proc]
    elif BACKEND == "rust":
        rust_bin = SERVER_DIR / "rust-server" / "target" / "release" / "neverlose-server"
        if not rust_bin.exists():
            rust_bin = SERVER_DIR / "rust-server" / "target" / "debug" / "neverlose-server"
        assert rust_bin.exists(), f"Rust binary not found at {rust_bin}"
        rust_proc = subprocess.Popen(
            [str(rust_bin)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs = [rust_proc]
    else:
        raise ValueError(f"Unknown backend: {BACKEND}")

    try:
        _wait_for_port(HTTP_PORT)
        _wait_for_port(WS_PORT)
        yield
    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


@pytest.fixture(scope="session")
def http_base(servers):
    return f"http://127.0.0.1:{HTTP_PORT}"


def _ws_url():
    if BACKEND == "python":
        return f"wss://127.0.0.1:{WS_PORT}"
    return f"ws://127.0.0.1:{WS_PORT}"


def _ws_ssl_context():
    if BACKEND == "python":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


# ---------------------------------------------------------------------------
# HTTP Tests
# ---------------------------------------------------------------------------


class TestHTTP:
    """Tests for the HTTP server on port 30031."""

    @pytest.mark.asyncio
    async def test_config(self, http_base):
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{http_base}/api/config") as r:
                assert r.status == 200
                assert r.headers.get("X-Powered-By") == "Express"
                data = await r.json()
                assert data["status"] == "ok"
                assert data["config"]["glow"] is True

    @pytest.mark.asyncio
    async def test_getavatar(self, http_base):
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{http_base}/api/getavatar") as r:
                assert r.status == 200
                assert "image/png" in r.headers.get("Content-Type", "")
                assert r.headers.get("X-Powered-By") == "Express"
                body = await r.read()
                assert body[:4] == b"\x89PNG"
                assert len(body) == AVATAR_SIZE

    @pytest.mark.asyncio
    async def test_getavatar_with_params(self, http_base):
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{http_base}/api/getavatar?size=100&token=foo") as r:
                assert r.status == 200
                body = await r.read()
                assert body[:4] == b"\x89PNG"
                assert len(body) == AVATAR_SIZE

    @pytest.mark.asyncio
    async def test_sendlog(self, http_base):
        url = f"{http_base}/api/sendlog?token=t&a=0&build=1&cont=c&dump=d&cheat=csgo"
        async with aiohttp.ClientSession() as s:
            async with s.get(url) as r:
                assert r.status == 200
                assert r.headers.get("X-Powered-By") == "Express"
                data = await r.json()
                assert data == {"status": "ok"}

    @pytest.mark.asyncio
    async def test_lua_library(self, http_base):
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{http_base}/lua/testlib") as r:
                assert r.status == 200
                assert r.headers.get("X-Powered-By") == "Express"
                ct = r.headers.get("Content-Type", "")
                assert "text/plain" in ct
                body = await r.text()
                assert body == "-- lua library: testlib\n"

    @pytest.mark.asyncio
    async def test_post_type4_serial(self, http_base):
        payload = {"type": 4, "params": {"hash": "x", "hash2": "y"}}
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{http_base}/anything", json=payload) as r:
                assert r.status == 200
                assert r.headers.get("X-Powered-By") == "Express"
                body = await r.text()
                assert body.startswith(SPOOFED_SERIAL_PREFIX)

    @pytest.mark.asyncio
    async def test_404_get(self, http_base):
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{http_base}/nonexistent") as r:
                assert r.status == 404
                assert r.headers.get("X-Powered-By") == "Express"
                body = await r.text()
                assert "<pre>Cannot GET /nonexistent</pre>" in body

    @pytest.mark.asyncio
    async def test_404_post(self, http_base):
        payload = {"type": 99}
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{http_base}/nonexistent", json=payload) as r:
                assert r.status == 404
                assert r.headers.get("X-Powered-By") == "Express"
                body = await r.text()
                assert "<pre>" in body
                assert "Cannot" in body

    @pytest.mark.asyncio
    async def test_express_header_on_all_routes(self, http_base):
        """Verify X-Powered-By: Express on various routes."""
        routes = ["/api/config", "/api/getavatar", "/nonexistent"]
        async with aiohttp.ClientSession() as s:
            for route in routes:
                async with s.get(f"{http_base}{route}") as r:
                    assert r.headers.get("X-Powered-By") == "Express", \
                        f"Missing X-Powered-By on {route}"


# ---------------------------------------------------------------------------
# WebSocket Tests
# ---------------------------------------------------------------------------


class TestWebSocket:
    """Tests for the WebSocket server on port 30030."""

    @pytest.mark.asyncio
    async def test_three_frames_on_empty_string(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            await ws.send("")
            frames = []
            for _ in range(3):
                frame = await asyncio.wait_for(ws.recv(), timeout=5)
                frames.append(frame)
            assert isinstance(frames[0], str)
            assert isinstance(frames[1], bytes)
            assert isinstance(frames[2], bytes)

    @pytest.mark.asyncio
    async def test_three_frames_on_json(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            await ws.send('{"type":4}')
            frames = []
            for _ in range(3):
                frame = await asyncio.wait_for(ws.recv(), timeout=5)
                frames.append(frame)
            assert isinstance(frames[0], str)
            assert isinstance(frames[1], bytes)
            assert isinstance(frames[2], bytes)

    @pytest.mark.asyncio
    async def test_auth_json_content(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            await ws.send("")
            auth_frame = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(auth_frame)
            assert data == {
                "Type": "Auth",
                "Message": AUTH_MESSAGE,
                "Data": AUTH_DATA,
            }

    @pytest.mark.asyncio
    async def test_module_blob_size(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            await ws.send("")
            await ws.recv()  # auth
            module = await asyncio.wait_for(ws.recv(), timeout=5)
            assert isinstance(module, bytes)
            assert len(module) == MODULE_SIZE

    @pytest.mark.asyncio
    async def test_key_blob_size(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            await ws.send("")
            await ws.recv()  # auth
            await ws.recv()  # module
            key = await asyncio.wait_for(ws.recv(), timeout=5)
            assert isinstance(key, bytes)
            assert len(key) == KEY_SIZE

    @pytest.mark.asyncio
    async def test_no_response_after_three_frames(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            await ws.send("")
            for _ in range(3):
                await asyncio.wait_for(ws.recv(), timeout=5)
            # Send more messages — should get no response
            await ws.send("hello")
            await ws.send('{"type":0}')
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(ws.recv(), timeout=2)

    @pytest.mark.asyncio
    async def test_no_push_before_first_message(self, servers):
        async with websockets.connect(
            _ws_url(), ssl=_ws_ssl_context(), max_size=50 * 1024 * 1024
        ) as ws:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(ws.recv(), timeout=3)
