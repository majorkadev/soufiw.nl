#!/usr/bin/env bash
# Phase 3: Targeted radare2 Analysis
# Quick disassembly and xref extraction

set -euo pipefail

BINARY="/tmp/nl_analysis/nl.bin"
OUTPUT="/tmp/nl_analysis/output/r2_results.txt"
BASE_ADDR="0x412A0000"

mkdir -p "$(dirname "$OUTPUT")"

echo "[Phase 3] Starting radare2 analysis..."
echo "[Phase 3] This may take ~10 minutes..."

# Run radare2 with commands piped via stdin
nix-shell -p radare2 --run "r2 -q -a x86 -b 32 -m ${BASE_ADDR} -e scr.interactive=false -e scr.color=0 -e anal.timeout=300 '${BINARY}' << 'R2EOF'
?e ==========================================================
?e radare2 Analysis Results for nl.bin
?e ==========================================================

f GetSerial 1 0x41BC78E0
f MakeRequest 1 0x41BC98E0
f QueryLuaLibrary 1 0x41BC9670
f Requestor_Instance 1 0x41BC9450
f ws_client_send_wrap 1 0x41C16EA0
f entry_point 1 0x412A0A00
f error_handler 1 0x4200A118
f SHA256_transform 1 0x41EBB510
f mem_dispatcher 1 0x41DA0BA0
f g_pRequestor 4 0x42518C58
f auth_token_ptr 1 0x41BF8341
f g_hConsole 4 0x42518C44

?e
?e === Requestor::Instance (0x41BC9450) ===
af @ 0x41BC9450
pdf @ 0x41BC9450

?e
?e === ws_client_send_wrap (0x41C16EA0) ===
af @ 0x41C16EA0
pdf @ 0x41C16EA0

?e
?e === entry_point (0x412A0A00) ===
af @ 0x412A0A00
pdf @ 0x412A0A00

?e
?e === error_handler (0x4200A118) ===
af @ 0x4200A118
pdf @ 0x4200A118

?e
?e === mem_dispatcher (0x41DA0BA0) ===
af @ 0x41DA0BA0
pdf @ 0x41DA0BA0

?e
?e --- Cross-References to Key Functions ---

?e
?e === XRefs to GetSerial (0x41BC78E0) ===
axt @ 0x41BC78E0

?e
?e === XRefs to MakeRequest (0x41BC98E0) ===
axt @ 0x41BC98E0

?e
?e === XRefs to QueryLuaLibrary (0x41BC9670) ===
axt @ 0x41BC9670

?e
?e === XRefs to Requestor::Instance (0x41BC9450) ===
axt @ 0x41BC9450

?e
?e === XRefs to ws_client_send_wrap (0x41C16EA0) ===
axt @ 0x41C16EA0

?e
?e === XRefs to g_pRequestor (0x42518C58) ===
axt @ 0x42518C58

?e
?e === XRefs to auth_token_ptr (0x41BF8341) ===
axt @ 0x41BF8341

?e
?e --- Searching for Route Strings ---

?e === /api ===
/ /api

?e === /auth ===
/ /auth

?e === /ws ===
/ /ws

?e === /v1 ===
/ /v1

?e === /serial ===
/ /serial

?e === /lua ===
/ /lua

?e === /config ===
/ /config

?e === websocket ===
/ websocket

?e === NLR/ ===
/ NLR/

?e === neverlose ===
/i neverlose

?e === 145.239 ===
/ 145.239

?e === application/json ===
/ application/json

?e === Content-Type ===
/ Content-Type

?e === User-Agent ===
/ User-Agent

?e === Authorization ===
/ Authorization

?e
?e --- Reading Data at Known Addresses ---

?e === g_pRequestor value at 0x42518C58 ===
px 16 @ 0x42518C58

?e === auth_token data at 0x41BF8341 ===
px 64 @ 0x41BF8341

?e === g_hConsole at 0x42518C44 ===
px 16 @ 0x42518C44

?e
?e --- JSON patterns ---
/ \"type\"
/ \"params\"
/ \"hash\"
/ nlohmann

?e
?e --- All Flags ---
f

?e === Analysis Complete ===
R2EOF" > "${OUTPUT}" 2>&1 || true

echo "[Phase 3] Results saved to ${OUTPUT}"
echo "[Phase 3] Complete."
