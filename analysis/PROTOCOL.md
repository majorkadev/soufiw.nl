# Neverlose Binary Network Protocol

Reverse-engineered from `nl.bin` (53MB x86-32 memory dump at base 0x412A0000).

## Architecture Overview

The binary uses two network channels:

| Channel | Port | Protocol | Transport | Used By |
|---------|------|----------|-----------|---------|
| HTTP | 30031 | HTTP/1.1 GET | Plaintext | MakeRequest (slot 0), QueryLuaLibrary (slot 4) |
| WebSocket | 30030 | WSS (TLS) | WebSocket over TLS | GetSerial (slot 1), fn3 (slot 3) |

The `Requestor` singleton (at `0x42518C58`) provides 5 virtual methods via vtable at `0x420F5BF4`:

| Slot | Offset | Method | Target VA | VMProtect | Signature |
|------|--------|--------|-----------|-----------|-----------|
| 0 | +0x00 | MakeRequest | 0x41BC98E0 | Yes | `void(string& out, string_view route, int, int)` |
| 1 | +0x04 | GetSerial | 0x41BC78E0 | Yes | `void(string& out, json& request)` |
| 2 | +0x08 | fn2 | 0x41BC9050 | Yes | Unknown (never called in analyzed code) |
| 3 | +0x0C | fn3 | 0x41BC9E20 | Yes | `void(string& out, json& request)` (inferred) |
| 4 | +0x10 | QueryLuaLibrary | 0x41BC9670 | Yes | `void(string& out, string_view name)` |

`Requestor::Instance()` at `0x41BC9450` returns the singleton pointer. All methods are VMProtect-virtualized.

## HTTP Protocol (Port 30031, probed 2026-02-22)

**Crack server probe**: Only `/api/getavatar` returns 200. All other routes return Express 404.
The crack server only implements the avatar endpoint — config, sendlog, and lua routes are
likely only on the real Neverlose server (which we don't have access to).

### User-Agent
```
NLR/1.0
```

### Common Query Parameters
```
token=<AUTH_TOKEN>    Authentication token
a=0                   Unknown flag
build=<BUILD_ID>      Client build identifier
cont=<CONT_VALUE>     Continuation/context value
dump=<DUMP_DATA>      Register dump (crash logs)
cheat=csgo            Game identifier
```

### Discovered Routes

#### GET /api/config
- **Source**: Confirmed via Unicorn emulation (function 0x415890C0)
- **Caller**: MakeRequest (vtable slot 0)
- **Response**: JSON config object

#### GET /api/getavatar?size=100&token=TOKEN
- **Source**: XOR decryption of function 0x415890C0
- **Caller**: MakeRequest (vtable slot 0)
- **Response**: Avatar image data (PNG/JPEG)

#### GET /api/sendlog?token=T&a=0&build=B&cont=C&dump=D&cheat=csgo
- **Source**: XOR decryption of function 0x415ECC45
- **Caller**: fn3 (vtable slot 3) — may also use HTTP
- **Purpose**: Crash/error log reporting
- **Dump format**: Contains register values (`eax=`, `ebp=`, etc.)
- **Response**: `{"status": "ok"}`

#### GET /lua/\<name\>?token=T&cheat=csgo&build=B
- **Source**: QueryLuaLibrary (vtable slot 4)
- **Caller**: Various lua script loading functions
- **Response**: Lua script source code (text/plain)

## WebSocket Protocol (Port 30030, TLS)

### Connection Flow (verified via probing, 2026-02-22)

```
Client                          Server
  |                               |
  |---- WSS connect (TLS) -----→ |
  |                               |
  |---- ANY message (trigger) -→ |  Client must send first
  |                               |
  |←---- Auth JSON (text) ------- |  Frame 1
  |←---- Module blob (binary) --- |  Frame 2 (385,360 bytes)
  |←---- Key blob (binary) ------ |  Frame 3 (80 bytes)
  |                               |
  |  (server ignores all further messages on crack server)
```

**Important**: The crack server does NOT push frames proactively. It waits for the
client's first message (any content, even empty string), then sends the 3 frames.
After that, it ignores all subsequent messages (types 0-9 all timeout).

The crack server is purely a payload delivery system. Auth/serial validation,
data requests, etc. are handled client-side by the Requestor.cpp hooks.

### Frame 1: Auth JSON
```json
{"Type":"Auth","Message":"fz8XfUGGBvylN7IW","Data":"5aAxpFpna5QqvYMv"}
```
- `Message` and `Data` are stored in the `Client` object (see `neverlosesdk.hpp`)
- Used as encryption keys for the module/key blobs

### Frame 2: Encrypted Module
- 385,360 bytes of encrypted data
- Decrypted using keys from Frame 1
- Contains the cheat module code

### Frame 3: Encrypted Key Material
- 80 bytes of encrypted key data
- Used in combination with Frame 2 for module loading

### Client JSON Messages

The client sends JSON messages with a `type` field:

#### Type 4: Authentication (GetSerial)
```json
{
  "type": 4,
  "params": {
    "hash": "N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=",
    "hash2": "hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="
  }
}
```
- `hash`: Base64-encoded hardware fingerprint
- `hash2`: Base64-encoded secondary hash (includes SHA256)
- **Response**: Base64-encoded serial string (680+ chars)

#### Type 0-3, 5: Data Requests
Observed during probing but exact payloads not yet decoded. Context from binary analysis:

| Type | Likely Purpose | JSON Fields Found Nearby |
|------|---------------|--------------------------|
| 0 | Config/init | config, version |
| 1 | Heartbeat | status |
| 2 | Inventory/skins | weapon_, item_, index, name, image, rarity, loot |
| 3 | Entity/netvar data | BasePlayer, BaseEntity, VisualAngles |
| 5 | Scripts/lua | data |

### Server Behavior
The crack server at `145.239.80.134:30030` sends the same 3 initial frames on every connection regardless of client messages. The SHA256 hashes of the blobs are constant:
- Module: `9c603b80f813250f32d798706a5ea3b081667de9e01cd0dedd54a5c8bc703cd6`
- Key: `cd574003432b454ae0d8f04a5ac8c12bc71868d6c3435d8fe9595f33d4f1eeeb`

## Authentication Flow

```
1. Client connects to WSS (port 30030)
2. Server sends Auth JSON + module blob + key blob
3. Client stores Message/Data keys in Client object
4. Client computes hardware hash (hash) and SHA256 hash (hash2)
5. Client sends {"type":4,"params":{"hash":"...","hash2":"..."}} via fn3
6. Server validates hashes and returns serial string
7. Client validates serial
8. On failure: shows "License error." or "Invalid HWID."
9. On success: proceeds to load cheat module
```

### Anti-Debug Checks
- Checks for `/x32dbg.ini` on disk (function 0x41582C00)
- Multiple license validation paths (functions 0x4157F5F0, 0x41616C00)

## JSON Response Fields

### Chat/Notification Messages
```json
{
  "Message": "...",
  "Sender": "...",
  "Type": "...",
  "Time": "...",
  "Msg": "..."
}
```

### Error Responses
```json
{
  "reason": "License error."
}
```
```json
{
  "reason": "Invalid HWID."
}
```

### Inventory/Skin Data
```json
{
  "weapons": [
    {
      "weapon_": "...",
      "item_": "...",
      "index": 0,
      "name": "...",
      "image": "....svg",
      "rarity": "...",
      "loot": "..."
    }
  ]
}
```

### Game Config
```json
{
  "player": {...},
  "weapons": {...},
  "skybox": "...",
  "block": 0,
  "group": "..."
}
```

## Key Addresses

| VA | Name | Type |
|----|------|------|
| 0x412A0000 | Binary base | - |
| 0x412A0A00 | entry_point | Function |
| 0x41BC9450 | Requestor::Instance | Function |
| 0x41BC98E0 | MakeRequest | VMP Function |
| 0x41BC78E0 | GetSerial | VMP Function |
| 0x41BC9050 | fn2 | VMP Function |
| 0x41BC9E20 | fn3 | VMP Function |
| 0x41BC9670 | QueryLuaLibrary | VMP Function |
| 0x41C16EA0 | ws_client_send_wrap | Function |
| 0x420F5BF4 | Requestor vtable | Data |
| 0x42518C58 | g_pRequestor | Data (singleton ptr) |
| 0x42518C54 | g_pRequestor_flag | Data |
| 0x41BF8341 | auth_token_ptr | Data |
| 0x4200A118 | error_handler | Function |
| 0x41EBB510 | SHA256_transform | Function |
| 0x41DA0BA0 | mem_dispatcher | Function |

## Instance Call Sites (25 total, 21 unique functions)

| Call VA | Function | Vtable Slot | Purpose |
|---------|----------|-------------|---------|
| 0x413CA180 | 0x413C75C0 | 3 (fn3) | Rendering/shader config |
| 0x4156E6EF | 0x4156C3C0 | 3 (fn3) | Inventory/skin data |
| 0x4158003D | 0x4157F5F0 | 3 (fn3) | Auth validation |
| 0x4158141D | 0x4157F5F0 | 3 (fn3) | Auth validation |
| 0x41583ED5 | 0x41582C00 | 3 (fn3) | Anti-debug (/x32dbg.ini) |
| 0x41584D8F | 0x41582C00 | 3 (fn3) | Anti-debug |
| 0x4158910D | 0x415890C0 | 0 (MakeRequest) | /api/config, /api/getavatar |
| 0x415C2C2B | 0x415C01D0 | 3 (fn3) | Entity data |
| 0x415C471B | 0x415C3B63 | 3 (fn3) | Game config |
| 0x415ED7FD | 0x415ECC45 | 3 (fn3) | Crash logging |
| 0x4160C82E | 0x4160B570 | 3 (fn3) | Block data |
| 0x4161888F | 0x41616C00 | 3 (fn3) | License validation |
| 0x41619813 | 0x41616C00 | 3 (fn3) | License validation |
| 0x417EBE08 | 0x417EBAA0 | 3 (fn3) | Group data |
| 0x417EBECA | 0x417EBAA0 | 3 (fn3) | Group data |
| 0x41B63D60 | 0x41B63BB0 | 3 (fn3) | Netvar data |
| 0x41BC66F9 | 0x41BC5690 | 3 (fn3) | Generic data |
| 0x41BC74E1 | 0x41BC6C10 | 3 (fn3) | Requestor internal |

## String Encryption

Routes and JSON field names are XOR-encrypted using 128-bit SSE operations:
```
mov [esi+staging_high], HIGH_DWORD    ; Stage encrypted data
mov [esi+staging_low], LOW_DWORD      ; (pairs of 4-byte values = 8 bytes)
...                                    ; (repeat for 16-32 bytes)
lea eax, [esi+key_offset]             ; Load key pointer
movaps xmm0, [esi+enc_offset]        ; Load 16 bytes encrypted
xorps xmm0, [eax]                    ; XOR with 16 bytes key
movaps [esi+enc_offset], xmm0        ; Store decrypted
```

## Server Implementation

See `server/http_server.py` (HTTP) and `server/wss_server.py` (WSS).
