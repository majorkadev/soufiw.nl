#!/usr/bin/env python3
"""Minimal WSS probe - connect, auth, dump all responses fully to disk."""
import ssl, json, asyncio, os, websockets

SERVER = "145.239.80.134"
PORT = 30030
DUMP_DIR = "/tmp/nl_analysis/output/ws_dumps"
os.makedirs(DUMP_DIR, exist_ok=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

counter = 0
def save(data, label):
    global counter
    counter += 1
    ext = "bin" if isinstance(data, bytes) else "txt"
    path = f"{DUMP_DIR}/{counter:03d}_{label}.{ext}"
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)
    sz = len(data)
    print(f"  [{counter}] {label}: {sz} bytes -> {path}")
    if isinstance(data, bytes):
        hexpath = f"{DUMP_DIR}/{counter:03d}_{label}.hex"
        with open(hexpath, "w") as f:
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                h = " ".join(f"{b:02X}" for b in chunk)
                a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                f.write(f"{i:08X}  {h:<48s}  {a}\n")

async def session(messages, name):
    print(f"\n=== Session: {name} ===")
    try:
        async with websockets.connect(
            f"wss://{SERVER}:{PORT}/",
            additional_headers={"User-Agent": "NLR/1.0"},
            ssl=ctx, open_timeout=10, close_timeout=5,
            ping_timeout=20, max_size=50*1024*1024,
        ) as ws:
            for msg, label in messages:
                save(msg if isinstance(msg, bytes) else msg, f"{name}_sent_{label}")
                await ws.send(msg)
                print(f"  Sent: {label}")
                # collect responses
                resp_n = 0
                while True:
                    try:
                        r = await asyncio.wait_for(ws.recv(), timeout=8)
                        resp_n += 1
                        save(r, f"{name}_recv_{label}_r{resp_n}")
                    except asyncio.TimeoutError:
                        break
    except Exception as e:
        print(f"  Error: {e}")

async def main():
    # Session 1: auth with test hash
    await session([
        ('{"params":{"hash":"test","hash2":"test"},"type":4}', "auth"),
    ], "s1_auth_test")

    # Session 2: auth with real hash from source code
    await session([
        ('{"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="},"type":4}', "auth_real"),
    ], "s2_auth_real")

    # Session 3: type exploration
    await session([
        ('{"type":1}', "t1"),
        ('{"type":2}', "t2"),
        ('{"type":3}', "t3"),
        ('{"type":5}', "t5"),
    ], "s3_types")

    # Session 4: auth then post-auth types
    await session([
        ('{"params":{"hash":"test","hash2":"test"},"type":4}', "auth"),
        ('{"type":1}', "post_t1"),
        ('{"type":2}', "post_t2"),
        ('{"type":3}', "post_t3"),
        ('{"type":5}', "post_t5"),
        ('{"type":0}', "post_t0"),
    ], "s4_post_auth")

    # Session 5: binary messages
    await session([
        (b'\x04\x00\x00\x00', "bin4"),
        (b'\x01\x00\x00\x00', "bin1"),
    ], "s5_binary")

    print(f"\n=== Done. Dumps in {DUMP_DIR}/ ===")

asyncio.run(main())
