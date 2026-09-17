#!/usr/bin/env python3
"""
Phase 1: Fast Python String + Cross-Reference Extraction
Operates on raw bytes of nl.bin — no heavy tooling needed.
"""

import struct
import json
import re
import os
import sys
from collections import defaultdict

BINARY_PATH = "/tmp/nl_analysis/nl.bin"
OUTPUT_PATH = "/tmp/nl_analysis/output/phase1_results.json"
BASE_ADDR = 0x412A0000
CODE_REGION_END = 0x12FFFFF  # file offset for code region
MIN_STR_LEN = 5

# Known function addresses
KNOWN_FUNCTIONS = {
    0x41BC78E0: {"name": "GetSerial", "vmp": True},
    0x41BC98E0: {"name": "MakeRequest", "vmp": True},
    0x41BC9670: {"name": "QueryLuaLibrary", "vmp": True},
    0x41BC9450: {"name": "Requestor::Instance", "vmp": False},
    0x41C16EA0: {"name": "ws_client_send_wrap", "vmp": False},
    0x412A0A00: {"name": "entry_point", "vmp": False},
    0x4200A118: {"name": "error_handler", "vmp": False},
    0x41EBB510: {"name": "SHA256_transform", "vmp": False},
    0x41DA0BA0: {"name": "mem_dispatcher", "vmp": False},
}

KNOWN_DATA = {
    0x42518C58: "g_pRequestor",
    0x41BF8341: "auth_token_ptr",
    0x42518C44: "g_hConsole",
}

ALL_KNOWN_ADDRS = {}
ALL_KNOWN_ADDRS.update({va: info["name"] for va, info in KNOWN_FUNCTIONS.items()})
ALL_KNOWN_ADDRS.update(KNOWN_DATA)


def va_to_offset(va):
    return va - BASE_ADDR


def offset_to_va(offset):
    return offset + BASE_ADDR


def extract_ascii_strings(data, min_len=MIN_STR_LEN):
    """Extract printable ASCII strings with their file offsets."""
    strings = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                s = "".join(current)
                strings.append((start, s))
            current = []
    if len(current) >= min_len:
        strings.append((start, "".join(current)))
    return strings


def extract_utf16le_strings(data, min_len=MIN_STR_LEN):
    """Extract UTF-16LE strings with their file offsets."""
    strings = []
    i = 0
    while i < len(data) - 1:
        current = []
        start = i
        while i < len(data) - 1:
            lo = data[i]
            hi = data[i + 1]
            if hi == 0 and 0x20 <= lo <= 0x7E:
                current.append(chr(lo))
                i += 2
            else:
                break
        if len(current) >= min_len:
            s = "".join(current)
            # Filter out strings that are just repeated ASCII (already caught)
            if not all(c == current[0] for c in current):
                strings.append((start, s, "utf16le"))
        i += 2 if not current else 0
        if not current:
            i += 2
    return strings


def categorize_string(s):
    """Categorize a string by its content pattern."""
    categories = []
    sl = s.lower()

    # HTTP routes
    if re.match(r'^/[a-z]', s) or re.match(r'^/v\d+/', s):
        categories.append("http_route")
    if re.match(r'^https?://', s):
        categories.append("url")

    # IP addresses
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        categories.append("ip_address")

    # JSON-related
    if s.startswith('{') or s.startswith('['):
        categories.append("json_fragment")
    if re.match(r'^[a-z_][a-z0-9_]*$', s) and len(s) < 30:
        categories.append("possible_field_name")

    # Protobuf
    if s.startswith("CMsg") or s.endswith(".proto"):
        categories.append("protobuf")

    # Auth/token/key references
    auth_patterns = ["auth", "token", "serial", "license", "key", "hwid",
                     "hash", "login", "password", "session", "cookie"]
    if any(p in sl for p in auth_patterns):
        categories.append("auth_related")

    # WebSocket
    ws_patterns = ["websocket", "ws://", "wss://", "upgrade", "handshake",
                   "send_wrap", "ws_client", "socket"]
    if any(p in sl for p in ws_patterns):
        categories.append("websocket_related")

    # Network
    net_patterns = ["http", "request", "response", "post", "get ",
                    "content-type", "user-agent", "accept", "header"]
    if any(p in sl for p in net_patterns):
        categories.append("network_related")

    # Error messages
    if any(p in sl for p in ["error", "fail", "exception", "invalid", "denied"]):
        categories.append("error_message")

    # API/endpoint patterns
    if any(p in sl for p in ["/api/", "/v1/", "/v2/", "/auth/", "/lua/",
                              "/config/", "/serial/", "/user/"]):
        categories.append("api_endpoint")

    # Crypto
    if any(p in sl for p in ["sha256", "md5", "aes", "rsa", "encrypt",
                              "decrypt", "cipher", "hmac"]):
        categories.append("crypto_related")

    # Lua
    if any(p in sl for p in ["lua", "script", "callback", "library"]):
        categories.append("lua_related")

    # NLR User-Agent
    if "nlr" in sl or "neverlose" in sl:
        categories.append("neverlose_specific")

    if not categories:
        categories.append("uncategorized")

    return categories


def find_code_xrefs(data, target_va, code_end):
    """Find 4-byte LE references to target_va in code region."""
    xrefs = []
    target_bytes = struct.pack("<I", target_va)
    pos = 0
    while pos < min(code_end, len(data)):
        idx = data.find(target_bytes, pos, min(code_end, len(data)))
        if idx == -1:
            break
        xrefs.append(idx)
        pos = idx + 1
    return xrefs


def analyze_xref_context(data, xref_offset, context_bytes=32):
    """Analyze bytes around an xref to identify instruction patterns."""
    start = max(0, xref_offset - 16)
    end = min(len(data), xref_offset + 20)
    context = data[start:end]
    rel_pos = xref_offset - start

    patterns = []

    # Check for push imm32 (0x68 XX XX XX XX)
    if rel_pos >= 1 and context[rel_pos - 1] == 0x68:
        patterns.append("push_imm32")

    # Check for mov reg, imm32 (0xB8+reg XX XX XX XX)
    if rel_pos >= 1 and 0xB8 <= context[rel_pos - 1] <= 0xBF:
        reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
        reg = context[rel_pos - 1] - 0xB8
        patterns.append(f"mov_{reg_names[reg]}_imm32")

    # Check for call rel32 (0xE8 XX XX XX XX)
    if rel_pos >= 1 and context[rel_pos - 1] == 0xE8:
        # This is a relative call, the 4 bytes are a relative offset
        target = struct.unpack("<i", context[rel_pos:rel_pos + 4])[0]
        call_target = offset_to_va(xref_offset + 4) + target
        patterns.append(f"call_rel32_to_0x{call_target:08X}")

    # Check for mov [mem], imm32 (0xC7 05 XX XX XX XX YY YY YY YY)
    if rel_pos >= 2 and context[rel_pos - 2] == 0xC7:
        patterns.append("mov_mem_imm32")

    # Check for lea reg, [addr] - various encodings
    if rel_pos >= 2 and context[rel_pos - 2] == 0x8D:
        patterns.append("lea_reg_addr")

    # Look for a call instruction shortly after (within 20 bytes)
    for i in range(rel_pos + 4, min(rel_pos + 20, len(context) - 4)):
        if context[i] == 0xE8:
            # Relative call
            if i + 5 <= len(context):
                target = struct.unpack("<i", context[i + 1:i + 5])[0]
                call_va = offset_to_va(start + i + 5) + target
                patterns.append(f"followed_by_call_0x{call_va:08X}")
            break

    # Raw bytes for manual inspection
    hex_context = " ".join(f"{b:02X}" for b in context)

    return {
        "patterns": patterns,
        "hex_context": hex_context,
        "context_start_va": f"0x{offset_to_va(start):08X}",
    }


def find_function_prologues(data, code_end):
    """Find all function prologues in the code region."""
    prologues = []

    # Pattern 1: push ebp; mov ebp, esp (55 89 E5)
    p1 = b"\x55\x89\xE5"
    # Pattern 2: push ebp; mov ebp, esp (55 8B EC)
    p2 = b"\x55\x8B\xEC"

    for pattern, name in [(p1, "gcc_prologue"), (p2, "msvc_prologue")]:
        pos = 0
        while pos < min(code_end, len(data)):
            idx = data.find(pattern, pos, min(code_end, len(data)))
            if idx == -1:
                break
            prologues.append({
                "offset": idx,
                "va": f"0x{offset_to_va(idx):08X}",
                "type": name,
            })
            pos = idx + 1

    return sorted(prologues, key=lambda x: x["offset"])


def find_string_references(data, string_va, code_end):
    """Find code that references a string by pushing its VA."""
    refs = []

    # push imm32 with string VA
    push_pattern = b"\x68" + struct.pack("<I", string_va)
    pos = 0
    while pos < min(code_end, len(data)):
        idx = data.find(push_pattern, pos, min(code_end, len(data)))
        if idx == -1:
            break
        ref_va = offset_to_va(idx)
        refs.append({
            "instruction_va": f"0x{ref_va:08X}",
            "type": "push",
        })
        pos = idx + 1

    # mov reg, imm32 with string VA
    string_bytes = struct.pack("<I", string_va)
    for reg_opcode in range(0xB8, 0xC0):  # mov eax..edi, imm32
        mov_pattern = bytes([reg_opcode]) + string_bytes
        pos = 0
        while pos < min(code_end, len(data)):
            idx = data.find(mov_pattern, pos, min(code_end, len(data)))
            if idx == -1:
                break
            reg_names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
            ref_va = offset_to_va(idx)
            refs.append({
                "instruction_va": f"0x{ref_va:08X}",
                "type": f"mov_{reg_names[reg_opcode - 0xB8]}",
            })
            pos = idx + 1

    return refs


def main():
    print("[Phase 1] Loading binary...")
    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    binary_size = len(data)
    print(f"  Binary size: {binary_size} bytes ({binary_size / 1024 / 1024:.1f} MB)")
    print(f"  VA range: 0x{BASE_ADDR:08X} - 0x{BASE_ADDR + binary_size:08X}")

    code_end = min(CODE_REGION_END, binary_size)

    results = {
        "binary_info": {
            "size": binary_size,
            "base_addr": f"0x{BASE_ADDR:08X}",
            "end_addr": f"0x{BASE_ADDR + binary_size:08X}",
            "code_region_end_offset": code_end,
        },
        "known_addresses": {f"0x{va:08X}": name for va, name in ALL_KNOWN_ADDRS.items()},
    }

    # Step 1: Extract strings
    print("[Phase 1] Extracting ASCII strings...")
    ascii_strings = extract_ascii_strings(data)
    print(f"  Found {len(ascii_strings)} ASCII strings")

    print("[Phase 1] Extracting UTF-16LE strings...")
    utf16_strings = extract_utf16le_strings(data)
    print(f"  Found {len(utf16_strings)} UTF-16LE strings")

    # Step 2: Categorize strings
    print("[Phase 1] Categorizing strings...")
    categorized = defaultdict(list)
    interesting_strings = []

    for offset, s in ascii_strings:
        va = offset_to_va(offset)
        cats = categorize_string(s)
        entry = {
            "string": s,
            "offset": offset,
            "va": f"0x{va:08X}",
            "encoding": "ascii",
            "categories": cats,
        }
        for cat in cats:
            categorized[cat].append(entry)
        if "uncategorized" not in cats:
            interesting_strings.append(entry)

    for offset, s, enc in utf16_strings:
        va = offset_to_va(offset)
        cats = categorize_string(s)
        entry = {
            "string": s,
            "offset": offset,
            "va": f"0x{va:08X}",
            "encoding": enc,
            "categories": cats,
        }
        for cat in cats:
            categorized[cat].append(entry)
        if "uncategorized" not in cats:
            interesting_strings.append(entry)

    # Print category summary
    print("\n  String categories:")
    for cat in sorted(categorized.keys()):
        count = len(categorized[cat])
        if cat != "uncategorized":
            print(f"    {cat}: {count}")

    results["string_categories"] = {
        cat: entries[:200]  # Limit to 200 per category for output size
        for cat, entries in categorized.items()
        if cat != "uncategorized"
    }
    results["total_strings"] = {
        "ascii": len(ascii_strings),
        "utf16le": len(utf16_strings),
        "interesting": len(interesting_strings),
    }

    # Step 3: Find xrefs to known functions
    print("\n[Phase 1] Scanning for cross-references to known addresses...")
    xref_results = {}
    for va, name in ALL_KNOWN_ADDRS.items():
        print(f"  Scanning for refs to {name} (0x{va:08X})...")
        xrefs = find_code_xrefs(data, va, code_end)
        if xrefs:
            xref_entries = []
            for xoff in xrefs[:100]:  # Limit to 100 xrefs per address
                ctx = analyze_xref_context(data, xoff)
                xref_entries.append({
                    "file_offset": xoff,
                    "va": f"0x{offset_to_va(xoff):08X}",
                    **ctx,
                })
            xref_results[f"0x{va:08X}_{name}"] = {
                "total_refs": len(xrefs),
                "refs": xref_entries,
            }
            print(f"    Found {len(xrefs)} references")
        else:
            print(f"    No references found")

    results["xrefs_to_known"] = xref_results

    # Step 4: Find function prologues
    print("\n[Phase 1] Finding function prologues...")
    prologues = find_function_prologues(data, code_end)
    print(f"  Found {len(prologues)} function prologues")
    results["function_prologues"] = {
        "count": len(prologues),
        "first_50": prologues[:50],
        "last_50": prologues[-50:] if len(prologues) > 50 else [],
    }

    # Step 5: Find code references to interesting strings
    print("\n[Phase 1] Finding code references to interesting strings...")
    string_xrefs = {}
    # Focus on the most interesting categories
    priority_cats = ["http_route", "url", "ip_address", "api_endpoint",
                     "auth_related", "websocket_related", "neverlose_specific",
                     "network_related", "json_fragment"]

    seen_strings = set()
    for cat in priority_cats:
        for entry in categorized.get(cat, []):
            s = entry["string"]
            if s in seen_strings:
                continue
            seen_strings.add(s)
            va = int(entry["va"], 16)
            refs = find_string_references(data, va, code_end)
            if refs:
                string_xrefs[s] = {
                    "string_va": entry["va"],
                    "categories": entry["categories"],
                    "code_refs": refs[:20],
                }

    print(f"  Found references for {len(string_xrefs)} strings")
    results["string_code_refs"] = string_xrefs

    # Step 6: Special scan — look for call patterns to known VMProtect'd functions
    # Even though calls to these are indirect (through VMP handler), we can find
    # places that reference the VMP entry points
    print("\n[Phase 1] Scanning for call patterns to VMProtect'd functions...")
    vmp_call_sites = {}
    for va, info in KNOWN_FUNCTIONS.items():
        if not info["vmp"]:
            continue
        name = info["name"]
        # Find E8 (call rel32) patterns that target this VA
        for off in range(0, min(code_end, len(data)) - 5):
            if data[off] == 0xE8:
                rel = struct.unpack("<i", data[off + 1:off + 5])[0]
                target = offset_to_va(off + 5) + rel
                if target == va:
                    caller_va = offset_to_va(off)
                    if name not in vmp_call_sites:
                        vmp_call_sites[name] = []
                    # Get context - look backwards for argument setup
                    ctx_start = max(0, off - 48)
                    ctx_bytes = data[ctx_start:off + 5]
                    hex_ctx = " ".join(f"{b:02X}" for b in ctx_bytes)
                    vmp_call_sites[name].append({
                        "call_site_va": f"0x{caller_va:08X}",
                        "pre_call_bytes": hex_ctx,
                        "pre_call_start_va": f"0x{offset_to_va(ctx_start):08X}",
                    })

    for name, sites in vmp_call_sites.items():
        print(f"  {name}: {len(sites)} direct call sites")
    results["vmp_call_sites"] = vmp_call_sites

    # Step 7: Scan for specific byte patterns related to networking
    print("\n[Phase 1] Scanning for network-related patterns...")
    net_patterns = {}

    # Look for "NLR/1.0" User-Agent
    for pattern_name, pattern_bytes in [
        ("NLR_useragent", b"NLR/1.0"),
        ("content_type_json", b"application/json"),
        ("content_type_proto", b"application/x-protobuf"),
        ("ws_upgrade", b"websocket"),
    ]:
        positions = []
        pos = 0
        while True:
            idx = data.find(pattern_bytes, pos)
            if idx == -1:
                break
            positions.append(f"0x{offset_to_va(idx):08X}")
            pos = idx + 1
        if positions:
            net_patterns[pattern_name] = positions
            print(f"  {pattern_name}: found at {', '.join(positions[:5])}")

    results["network_patterns"] = net_patterns

    # Step 8: Look for port numbers in immediate values (30030, 30031)
    print("\n[Phase 1] Scanning for port number references...")
    port_refs = {}
    for port, name in [(30030, "ws_port_30030"), (30031, "http_port_30031"),
                       (443, "https_443"), (80, "http_80"), (8080, "alt_http_8080")]:
        port_bytes = struct.pack("<H", port)
        positions = []
        pos = 0
        while pos < code_end:
            idx = data.find(port_bytes, pos, code_end)
            if idx == -1:
                break
            # Check if this looks like it's in an instruction context
            # (push, mov, etc.) vs just random data
            if idx > 0:
                prev_byte = data[idx - 1]
                # push imm16 = 66 6A XX XX or push imm32 with port in low word
                # mov reg, imm with port value
                if prev_byte in [0x68, 0x6A] or (0xB8 <= prev_byte <= 0xBF):
                    positions.append(f"0x{offset_to_va(idx):08X}")
            pos = idx + 1
        # Also search for push imm32 with port value
        port_dword = struct.pack("<I", port)
        push_pattern = b"\x68" + port_dword
        pos = 0
        while pos < code_end:
            idx = data.find(push_pattern, pos, code_end)
            if idx == -1:
                break
            positions.append(f"0x{offset_to_va(idx):08X}")
            pos = idx + 1

        if positions:
            # Remove duplicates and sort
            positions = sorted(set(positions))
            port_refs[name] = positions
            print(f"  {name}: {len(positions)} references")

    results["port_references"] = port_refs

    # Save results
    print(f"\n[Phase 1] Saving results to {OUTPUT_PATH}...")
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"[Phase 1] Complete. Output: {OUTPUT_PATH}")

    # Print summary of most interesting findings
    print("\n" + "=" * 60)
    print("PHASE 1 SUMMARY - Most Interesting Findings")
    print("=" * 60)

    for cat in ["http_route", "api_endpoint", "url", "ip_address",
                "websocket_related", "auth_related", "neverlose_specific"]:
        entries = categorized.get(cat, [])
        if entries:
            print(f"\n--- {cat} ({len(entries)} strings) ---")
            for e in entries[:20]:
                print(f"  0x{int(e['va'], 16):08X}: {e['string'][:100]}")


if __name__ == "__main__":
    main()
