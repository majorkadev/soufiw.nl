#!/usr/bin/env python3
"""
Phase 5: Merge + Final Report Generator (v2 - clean output)
Reads all phase outputs and produces a consolidated REPORT.md
"""

import json
import os
import re
from datetime import datetime
from collections import defaultdict

OUTPUT_DIR = "/tmp/nl_analysis/output"
REPORT_PATH = "/tmp/nl_analysis/REPORT.md"


def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"  Warning: Could not load {path}: {e}")
        return None

def load_text(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception as e:
        print(f"  Warning: Could not load {path}: {e}")
        return None

def is_real_route(s):
    """Filter out garbage strings that look like routes but aren't."""
    if len(s) < 3 or len(s) > 200:
        return False
    # Must start with / followed by a letter
    if not re.match(r'^/[a-zA-Z]', s):
        return False
    # Must be mostly alphanumeric + common URL chars
    clean_chars = sum(1 for c in s if c.isalnum() or c in '/-_.')
    if clean_chars / len(s) < 0.8:
        return False
    # No control chars or weird symbols
    if any(ord(c) < 32 or ord(c) > 126 for c in s):
        return False
    # Not random gibberish - should have word-like patterns
    if re.search(r'[A-Z][0-9][A-Z]|[^a-zA-Z0-9/_\-\.]{2,}', s):
        return False
    return True

def is_real_json(s):
    """Filter out binary garbage matching { or [."""
    try:
        json.loads(s)
        return True
    except Exception:
        return False

def extract_ghidra_sections(ghidra_text):
    """Extract meaningful decompiled sections from Ghidra output."""
    if not ghidra_text:
        return {}
    sections = {}
    current_key = None
    current_lines = []

    for line in ghidra_text.split("\n"):
        if line.strip().startswith("=== ") or line.strip().startswith("--- "):
            if current_key and current_lines:
                content = "\n".join(current_lines).strip()
                if content and len(content) > 20:
                    sections[current_key] = content
            current_key = line.strip().strip("=-").strip()
            current_lines = []
        elif current_key:
            current_lines.append(line)

    if current_key and current_lines:
        content = "\n".join(current_lines).strip()
        if content and len(content) > 20:
            sections[current_key] = content
    return sections

def extract_r2_sections(r2_text):
    """Extract meaningful sections from r2 output, stripping escape codes."""
    if not r2_text:
        return {}
    # Strip terminal escape codes
    r2_text = re.sub(r'\[\?[\d;]+[a-zA-Z]', '', r2_text)
    sections = {}
    current_key = None
    current_lines = []

    for line in r2_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("=== ") and stripped.endswith("==="):
            if current_key and current_lines:
                content = "\n".join(current_lines).strip()
                if content and len(content) > 10:
                    sections[current_key] = content
            current_key = stripped.strip("= ").strip()
            current_lines = []
        elif stripped.startswith("--- ") and stripped.endswith("---"):
            if current_key and current_lines:
                content = "\n".join(current_lines).strip()
                if content and len(content) > 10:
                    sections[current_key] = content
            current_key = stripped.strip("- ").strip()
            current_lines = []
        elif current_key:
            current_lines.append(line)

    if current_key and current_lines:
        content = "\n".join(current_lines).strip()
        if content and len(content) > 10:
            sections[current_key] = content
    return sections

def generate_report():
    print("[Phase 5] Generating final report (v2)...")

    phase1 = load_json(os.path.join(OUTPUT_DIR, "phase1_results.json"))
    ghidra_text = load_text(os.path.join(OUTPUT_DIR, "ghidra_results.txt"))
    r2_text = load_text(os.path.join(OUTPUT_DIR, "r2_results.txt"))
    emulation = load_json(os.path.join(OUTPUT_DIR, "phase4_emulation.json"))
    probe = load_json(os.path.join(OUTPUT_DIR, "phase4_server_probe.json"))

    ghidra_sections = extract_ghidra_sections(ghidra_text)
    r2_sections = extract_r2_sections(r2_text)

    r = []  # report lines

    r.append("# Neverlose Binary Analysis Report")
    r.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    r.append(f"Binary: nl.bin (53MB raw x86-32 memory dump, base 0x412A0000)")
    r.append("")

    # ===== EXECUTIVE SUMMARY =====
    r.append("## 1. Executive Summary")
    r.append("")
    if phase1:
        bi = phase1.get("binary_info", {})
        ts = phase1.get("total_strings", {})
        r.append(f"- **Binary size**: {bi.get('size', '?')} bytes ({int(bi.get('size', 0))/1024/1024:.1f} MB)")
        r.append(f"- **VA range**: {bi.get('base_addr', '?')} - {bi.get('end_addr', '?')}")
        r.append(f"- **Strings found**: {ts.get('ascii', '?')} ASCII, {ts.get('utf16le', '?')} UTF-16LE, {ts.get('interesting', '?')} categorized")
    r.append(f"- **Phases completed**: Phase 1 (strings), Phase 2 (Ghidra{'  - ' + str(len(ghidra_sections)) + ' sections' if ghidra_sections else ' - failed'}), Phase 3 (r2), Phase 4A (emulation), Phase 4B (WSS probing)")
    r.append("")
    r.append("**Key Findings:**")
    r.append("- Server at `145.239.80.134` uses **WSS on port 30030** (TLS) and **HTTP on port 30031**")
    r.append("- WSS protocol: on connect, server always sends 3 frames: auth JSON + 385KB encrypted blob + 80-byte encrypted blob")
    r.append("- Auth JSON response: `{\"Type\":\"Auth\",\"Message\":\"...\",\"Data\":\"...\"}`")
    r.append("- Client auth request format: `{\"params\":{\"hash\":\"...\",\"hash2\":\"...\"},\"type\":4}`")
    r.append("- Binary uses **WebSocket++ 0.8.2**, **nlohmann::json**, **OpenSSL**, **Crypto++** (CipherMode, SHA-256)")
    r.append("- VMProtect virtualizes the 3 critical network methods: `GetSerial`, `MakeRequest`, `QueryLuaLibrary`")
    r.append("- Requestor vtable at data address `0x420F5BF4` holds pointers to all 5 virtual methods")
    r.append("")

    # ===== PROTOCOL: WSS =====
    r.append("## 2. WebSocket Protocol (Port 30030, TLS)")
    r.append("")
    r.append("### Connection Flow")
    r.append("")
    r.append("1. Client connects via **WSS** (TLS) to `wss://145.239.80.134:30030/`")
    r.append("2. Server immediately sends 3 frames (regardless of what client sends):")
    r.append("")
    r.append("| Frame | Type | Size | Content |")
    r.append("|-------|------|------|---------|")
    r.append('| 1 | Text | 70 bytes | `{"Type":"Auth","Message":"fz8XfUGGBvylN7IW","Data":"5aAxpFpna5QqvYMv"}` |')
    r.append("| 2 | Binary | 385,360 bytes | Encrypted payload (high entropy, md5: `908adc35eef97b71052eccaeed5dd584`) |")
    r.append("| 3 | Binary | 80 bytes | Encrypted blob (likely key/signature) |")
    r.append("")
    r.append("### Client Messages")
    r.append("")
    r.append("The client sends JSON with `type` field. Known from source code:")
    r.append("```json")
    r.append('{"params":{"hash":"<base64>","hash2":"<base64>"},"type":4}')
    r.append("```")
    r.append("")
    r.append("Where `hash` and `hash2` are base64-encoded HWID hashes. Example from source:")
    r.append("```")
    r.append('hash:  "N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA="')
    r.append('hash2: "hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="')
    r.append("```")
    r.append("")
    r.append("### Server Response Behavior")
    r.append("")
    r.append("- Server sends the same 3 frames for **any** message (type 1-10, binary, anything)")
    r.append("- Post-auth messages (sent after initial auth) receive **no response**")
    r.append("- The `Message` and `Data` fields in the auth JSON are **static** (same across sessions)")
    r.append("- The 385KB binary blob is **identical** across all sessions (static content)")
    r.append("")

    # WebSocket strings from binary
    if phase1:
        ws_strings = phase1.get("string_categories", {}).get("websocket_related", [])
        if ws_strings:
            r.append("### WebSocket Strings in Binary")
            r.append("")
            for e in ws_strings[:25]:
                r.append(f"- `{e['string'][:120]}` at {e['va']}")
            r.append("")

    # ===== PROTOCOL: HTTP =====
    r.append("## 3. HTTP Protocol (Port 30031)")
    r.append("")
    r.append("### MakeRequest Method")
    r.append("")
    r.append("From source code (`Requestor.cpp`):")
    r.append("```")
    r.append("MakeRequest(std::string& out, std::string_view route, int param3, int param4)")
    r.append("```")
    r.append("- Uses `WinHttpOpenRequest` with `GET` method")
    r.append("- User-Agent: `NLR/1.0`")
    r.append("- Server: `145.239.80.134:30031`")
    r.append("- Routes are passed as `string_view` — the actual routes are constructed by VMProtect'd callers")
    r.append("")

    # Ghidra string search results for HTTP patterns
    if ghidra_text:
        r.append("### HTTP-Related Strings Found by Ghidra")
        r.append("")
        for pattern in ["Content-Type", "User-Agent", "Authorization", "Bearer", "POST", "GET", "PUT"]:
            key = f'Pattern "{pattern}"'
            for sec_name, sec_content in ghidra_sections.items():
                if key in sec_name or (pattern in sec_content and "found at" in sec_content):
                    lines = sec_content.split("\n")
                    for line in lines:
                        line = line.strip()
                        if line and ("Full string:" in line or "Referenced by" in line or "found at" in line):
                            r.append(f"- {line}")
                    break
        r.append("")

    # URLs and IPs
    if phase1:
        urls = phase1.get("string_categories", {}).get("url", [])
        ips = phase1.get("string_categories", {}).get("ip_address", [])
        if urls or ips:
            r.append("### URLs and IP Addresses in Binary")
            r.append("")
            for e in urls[:20]:
                r.append(f"- `{e['string'][:200]}` at {e['va']}")
            for e in ips[:10]:
                r.append(f"- `{e['string'][:60]}` at {e['va']}")
            r.append("")

    # ===== REQUESTOR VTABLE =====
    r.append("## 4. Requestor Interface (Virtual Table)")
    r.append("")
    r.append("From `neverlosesdk.hpp`:")
    r.append("```cpp")
    r.append("class Requestor {")
    r.append("    virtual void MakeRequest(std::string& out, std::string_view route, int, int) = 0;  // vtable[0]")
    r.append("    virtual void GetSerial(std::string& out, nlohmann::json& request) = 0;             // vtable[1]")
    r.append("    virtual void fn2() = 0;                                                            // vtable[2]")
    r.append("    virtual void fn3() = 0;                                                            // vtable[3]")
    r.append("    virtual void QueryLuaLibrary(std::string& out, std::string_view name) = 0;         // vtable[4]")
    r.append("};")
    r.append("```")
    r.append("")
    r.append("### Key Addresses")
    r.append("")
    r.append("| VA | Name | VMProtect | Description |")
    r.append("|-----|------|-----------|-------------|")
    r.append("| `0x41BC78E0` | GetSerial | **Yes** | Generates serial from HWID hash JSON |")
    r.append("| `0x41BC98E0` | MakeRequest | **Yes** | HTTP GET to route, returns response body |")
    r.append("| `0x41BC9670` | QueryLuaLibrary | **Yes** | Fetches Lua library by name |")
    r.append("| `0x41BC9450` | Requestor::Instance | No | Returns singleton from `g_pRequestor` |")
    r.append("| `0x41C16EA0` | ws_client_send_wrap | No | WebSocket send wrapper |")
    r.append("| `0x412A0A00` | entry_point | No | Module initialization |")
    r.append("| `0x4200A118` | error_handler | No | `__CxxThrowException` |")
    r.append("| `0x41EBB510` | SHA256_transform | No | SHA-256 block transform |")
    r.append("| `0x41DA0BA0` | mem_dispatcher | No | Memory dispatch/hooking |")
    r.append("")
    r.append("### Key Data Addresses")
    r.append("")
    r.append("| VA | Name | Description |")
    r.append("|-----|------|-------------|")
    r.append("| `0x42518C58` | g_pRequestor | Singleton pointer to Requestor object |")
    r.append("| `0x42518C54` | g_requestor_flag | Set to `0x80000004` during init |")
    r.append("| `0x42518C44` | g_hConsole | Console handle |")
    r.append("| `0x41BF8341` | auth_token_ptr | Token/key data storage |")
    r.append("| `0x420F5BF4` | vtable_data | Vtable entries for MakeRequest, GetSerial, etc. |")
    r.append("")

    # ===== AUTHENTICATION =====
    r.append("## 5. Authentication Flow")
    r.append("")
    r.append("### GetSerial")
    r.append("")
    r.append("1. Binary constructs HWID hashes (`hash` and `hash2`, base64-encoded)")
    r.append("2. Packages them as JSON: `{\"params\":{\"hash\":\"...\",\"hash2\":\"...\"},\"type\":4}`")
    r.append("3. Calls `GetSerial(out, json_request)` through VMProtect'd vtable slot")
    r.append("4. Server returns a base64-encoded serial (512+ bytes)")
    r.append("")
    r.append("### WebSocket Client Structure")
    r.append("```cpp")
    r.append("class Client {")
    r.append("    virtual void vt() = 0;")
    r.append("    int IsConnected;         // +0x04: connection status")
    r.append("    void* endpoint;          // +0x08: websocketpp endpoint object")
    r.append("    uint32_t reserved[2];    // +0x0C")
    r.append("    char* SomeKey;           // +0x14: auth message from server")
    r.append("    uint32_t reserved2[6];   // +0x18")
    r.append("    char* SomeKey1;          // +0x30: auth data from server")
    r.append("};")
    r.append("```")
    r.append("")

    # Auth strings
    if phase1:
        r.append("### Auth-Related Strings")
        r.append("")
        auth_strings = phase1.get("string_categories", {}).get("auth_related", [])
        # Filter to meaningful ones
        meaningful_auth = [e for e in auth_strings if any(kw in e["string"].lower() for kw in
            ["auth", "serial", "token", "login", "session", "cookie", "hwid", "license"])]
        for e in meaningful_auth[:25]:
            r.append(f"- `{e['string'][:150]}` at {e['va']}")
        r.append("")

    # ===== GHIDRA DECOMPILED =====
    r.append("## 6. Ghidra Decompiled Code (Key Functions)")
    r.append("")

    # Show the important Ghidra sections
    priority_sections = [
        "References to Requestor_Instance",
        "References to ws_client_send_wrap",
        "References to entry_point",
        "References to GetSerial",
        "References to MakeRequest",
        "References to QueryLuaLibrary",
        "Analyzing Data References",
        "Finding Network-Related String References",
        "Analyzing Requestor Vtable",
        "Auth Token Analysis",
    ]

    for sec_name in priority_sections:
        for key, content in ghidra_sections.items():
            if sec_name.lower() in key.lower():
                r.append(f"### {key}")
                r.append("")
                # Truncate very long sections
                if len(content) > 8000:
                    r.append(f"```c\n{content[:8000]}\n... (truncated, {len(content)} chars total)\n```")
                else:
                    r.append(f"```c\n{content}\n```")
                r.append("")
                break

    # ===== R2 DISASSEMBLY =====
    r.append("## 7. radare2 Disassembly (Key Functions)")
    r.append("")

    r2_priority = [
        "Requestor::Instance",
        "ws_client_send_wrap",
        "entry_point",
        "XRefs to GetSerial",
        "XRefs to MakeRequest",
        "XRefs to Requestor::Instance",
        "XRefs to ws_client_send_wrap",
        "XRefs to g_pRequestor",
        "XRefs to auth_token_ptr",
        "g_pRequestor value",
        "auth_token data",
    ]

    for sec_name in r2_priority:
        for key, content in r2_sections.items():
            if sec_name.lower() in key.lower():
                r.append(f"### {key}")
                r.append("")
                if len(content) > 5000:
                    r.append(f"```asm\n{content[:5000]}\n... (truncated)\n```")
                else:
                    r.append(f"```asm\n{content}\n```")
                r.append("")
                break

    # R2 string search results
    r.append("### String Search Results (r2)")
    r.append("")
    for sec_name in ["/api", "/auth", "/serial", "/lua", "/config", "websocket",
                     "NLR/", "neverlose", "145.239", "application/json",
                     "Content-Type", "User-Agent", "Authorization",
                     "\"type\"", "\"params\"", "\"hash\"", "nlohmann"]:
        for key, content in r2_sections.items():
            if sec_name in key:
                hits = [l.strip() for l in content.split("\n") if l.strip() and "hit" in l.lower()]
                if hits:
                    r.append(f"**{key}**: {len(hits)} hits")
                    for h in hits[:5]:
                        r.append(f"  - {h}")
                    r.append("")
                break

    # ===== EMULATION =====
    r.append("## 8. Unicorn Emulation Results")
    r.append("")
    if emulation and "function_traces" in emulation:
        for name, trace in emulation["function_traces"].items():
            r.append(f"### {name}")
            r.append(f"- Address: {trace.get('address', 'N/A')}")
            r.append(f"- Status: {trace.get('status', 'N/A')}")
            r.append(f"- Instructions executed: {trace.get('instructions_executed', 'N/A')}")
            r.append(f"- Return value: {trace.get('return_value', 'N/A')}")
            if trace.get("external_calls_made"):
                r.append(f"- External calls ({len(trace['external_calls_made'])}):")
                for call in trace["external_calls_made"][:10]:
                    r.append(f"  - {call.get('name', call.get('to', '?'))} from {call.get('from', '?')}")
            r.append("")

    # ===== CROSS REFERENCES =====
    r.append("## 9. Cross-Reference Analysis")
    r.append("")
    if phase1:
        xrefs = phase1.get("xrefs_to_known", {})
        for key, data in xrefs.items():
            total = data.get("total_refs", 0)
            r.append(f"### {key} ({total} refs)")
            r.append("")
            for ref in data.get("refs", [])[:10]:
                patterns = ", ".join(ref.get("patterns", [])) or "(data ref)"
                r.append(f"- `{ref['va']}`: {patterns}")
            r.append("")

        vmp_sites = phase1.get("vmp_call_sites", {})
        if vmp_sites:
            r.append("### VMProtect'd Function Direct Call Sites")
            r.append("")
            for func_name, sites in vmp_sites.items():
                r.append(f"**{func_name}** — {len(sites)} call sites:")
                for site in sites[:10]:
                    r.append(f"- `{site['call_site_va']}` (pre-call context from `{site['pre_call_start_va']}`)")
                    r.append(f"  ```\n  {site['pre_call_bytes'][:120]}\n  ```")
                r.append("")

    # ===== SERVER IMPLEMENTATION GUIDE =====
    r.append("## 10. Server Implementation Guide")
    r.append("")
    r.append("### WSS Server (Port 30030)")
    r.append("")
    r.append("1. Accept TLS WebSocket connections at `wss://host:30030/`")
    r.append("2. On new connection, immediately send 3 frames:")
    r.append('   - Frame 1 (text): `{"Type":"Auth","Message":"<16-char-key>","Data":"<16-char-data>"}`')
    r.append("   - Frame 2 (binary): The encrypted module payload (385,360 bytes)")
    r.append("   - Frame 3 (binary): Encryption key/signature (80 bytes)")
    r.append("3. Handle client auth message: `{\"params\":{\"hash\":\"...\",\"hash2\":\"...\"},\"type\":4}`")
    r.append("4. The `Message` and `Data` fields map to `Client::SomeKey` and `Client::SomeKey1`")
    r.append("")
    r.append("### HTTP Server (Port 30031)")
    r.append("")
    r.append("1. Accept HTTP GET requests with `User-Agent: NLR/1.0`")
    r.append("2. Routes are passed via `MakeRequest(out, route, param3, param4)`")
    r.append("3. The actual routes are constructed by VMProtect'd code — not directly extractable")
    r.append("4. Response body is returned as raw string via the `out` parameter")
    r.append("")
    r.append("### Authentication")
    r.append("")
    r.append("1. Client computes HWID hashes (base64)")
    r.append("2. Sends `GetSerial` with JSON: `{\"params\":{\"hash\":\"...\",\"hash2\":\"...\"},\"type\":4}`")
    r.append("3. Server returns base64-encoded serial string (512+ bytes)")
    r.append("4. Serial is used for ongoing session authentication")
    r.append("")

    # ===== WSS DUMP FILES =====
    r.append("## 11. WSS Binary Dump Files")
    r.append("")
    r.append("All captured in `/tmp/nl_analysis/output/ws_dumps/`:")
    r.append("")
    r.append("| File | Size | Description |")
    r.append("|------|------|-------------|")

    dump_dir = "/tmp/nl_analysis/output/ws_dumps"
    if os.path.isdir(dump_dir):
        for f in sorted(os.listdir(dump_dir)):
            if f.endswith(".hex"):
                continue
            path = os.path.join(dump_dir, f)
            size = os.path.getsize(path)
            desc = ""
            if "recv" in f and "r1" in f:
                desc = "Auth JSON response"
            elif "recv" in f and "r2" in f:
                desc = "385KB encrypted payload"
            elif "recv" in f and "r3" in f:
                desc = "80-byte encrypted blob"
            elif "sent" in f and "auth" in f:
                desc = "Client auth request"
            elif "sent" in f:
                desc = "Client message"
            r.append(f"| `{f}` | {size:,} | {desc} |")
    r.append("")

    # ===== RAW REFERENCES =====
    r.append("## 12. Additional References")
    r.append("")

    if phase1:
        # Port references
        port_refs = phase1.get("port_references", {})
        if port_refs:
            r.append("### Port References in Code")
            r.append("")
            for name, addrs in port_refs.items():
                r.append(f"- **{name}**: {len(addrs)} refs — {', '.join(addrs[:5])}")
            r.append("")

        # Network patterns
        net = phase1.get("network_patterns", {})
        if net:
            r.append("### Network Byte Patterns")
            r.append("")
            for name, addrs in net.items():
                r.append(f"- **{name}**: {', '.join(addrs[:8])}")
            r.append("")

        # Crypto strings
        crypto = phase1.get("string_categories", {}).get("crypto_related", [])
        if crypto:
            real_crypto = [e for e in crypto if any(kw in e["string"].lower() for kw in
                ["sha", "aes", "rsa", "cipher", "encrypt", "decrypt", "hmac", "evp", "md5"])]
            if real_crypto:
                r.append("### Crypto Strings")
                r.append("")
                for e in real_crypto[:20]:
                    r.append(f"- `{e['string'][:120]}` at {e['va']}")
                r.append("")

        # Lua strings
        lua = phase1.get("string_categories", {}).get("lua_related", [])
        if lua:
            real_lua = [e for e in lua if "lua" in e["string"].lower() or "script" in e["string"].lower()]
            if real_lua:
                r.append("### Lua Strings")
                r.append("")
                for e in real_lua[:15]:
                    r.append(f"- `{e['string'][:120]}` at {e['va']}")
                r.append("")

    r.append("### Phase Output Files")
    r.append("")
    r.append("| File | Size | Description |")
    r.append("|------|------|-------------|")
    for fname, desc in [
        ("phase1_results.json", "String extraction + byte-level xrefs"),
        ("ghidra_results.txt", "Ghidra decompiled output"),
        ("r2_results.txt", "radare2 disassembly + xrefs"),
        ("phase4_emulation.json", "Unicorn emulation traces"),
        ("phase4_server_probe.json", "Live server probing results"),
    ]:
        path = os.path.join(OUTPUT_DIR, fname)
        if os.path.exists(path):
            size = os.path.getsize(path)
            r.append(f"| `{fname}` | {size:,} | {desc} |")
        else:
            r.append(f"| `{fname}` | missing | {desc} |")
    r.append("")

    with open(REPORT_PATH, "w") as f:
        f.write("\n".join(r))

    print(f"[Phase 5] Report written to {REPORT_PATH}")
    print(f"[Phase 5] Report: {len(r)} lines")

if __name__ == "__main__":
    generate_report()
