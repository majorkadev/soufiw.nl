# Neverlose Binary Analysis Report

Generated: 2026-02-22 05:19:17
Binary: nl.bin (53MB raw x86-32 memory dump, base 0x412A0000)

## 1. Executive Summary

- **Binary size**: 55578624 bytes (53.0 MB)
- **VA range**: 0x412A0000 - 0x447A1000
- **Strings found**: 122174 ASCII, 457 UTF-16LE, 7125 categorized
- **Phases completed**: Phase 1 (strings), Phase 2 (Ghidra  - 160 sections), Phase 3 (r2), Phase 4A (emulation), Phase 4B (WSS probing)

**Key Findings:**
- Server at `145.239.80.134` uses **WSS on port 30030** (TLS) and **HTTP on port 30031**
- WSS protocol: on connect, server always sends 3 frames: auth JSON + 385KB encrypted blob + 80-byte encrypted blob
- Auth JSON response: `{"Type":"Auth","Message":"...","Data":"..."}`
- Client auth request format: `{"params":{"hash":"...","hash2":"..."},"type":4}`
- Binary uses **WebSocket++ 0.8.2**, **nlohmann::json**, **OpenSSL**, **Crypto++** (CipherMode, SHA-256)
- VMProtect virtualizes the 3 critical network methods: `GetSerial`, `MakeRequest`, `QueryLuaLibrary`
- Requestor vtable at data address `0x420F5BF4` holds pointers to all 5 virtual methods

## 2. WebSocket Protocol (Port 30030, TLS)

### Connection Flow

1. Client connects via **WSS** (TLS) to `wss://145.239.80.134:30030/`
2. Server immediately sends 3 frames (regardless of what client sends):

| Frame | Type | Size | Content |
|-------|------|------|---------|
| 1 | Text | 70 bytes | `{"Type":"Auth","Message":"fz8XfUGGBvylN7IW","Data":"5aAxpFpna5QqvYMv"}` |
| 2 | Binary | 385,360 bytes | Encrypted payload (high entropy, md5: `908adc35eef97b71052eccaeed5dd584`) |
| 3 | Binary | 80 bytes | Encrypted blob (likely key/signature) |

### Client Messages

The client sends JSON with `type` field. Known from source code:
```json
{"params":{"hash":"<base64>","hash2":"<base64>"},"type":4}
```

Where `hash` and `hash2` are base64-encoded HWID hashes. Example from source:
```
hash:  "N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA="
hash2: "hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="
```

### Server Response Behavior

- Server sends the same 3 frames for **any** message (type 1-10, binary, anything)
- Post-auth messages (sent after initial auth) receive **no response**
- The `Message` and `Data` fields in the auth JSON are **static** (same across sessions)
- The 385KB binary blob is **identical** across all sessions (static content)

### WebSocket Strings in Binary

- `websocket` at 0x420F62B0
- `WebSocket++/0.8.2` at 0x420F63E4
- `Upgrade` at 0x420F660E
- `Sec-WebSocket-Key` at 0x42177170
- `Pass through from socket policy` at 0x42177182
- `Asio transport socket shutdown timed out` at 0x4217764A
- `The closing handshake timed out` at 0x4217768C
- `The opening handshake timed out` at 0x421776AC
- `TLS handshake timed out` at 0x421776CC
- `process handshake request` at 0x42177752
- `websocketpp.transport` at 0x421777BD
- `Sec-WebSocket-Accept` at 0x4217785D
- `websocketpp.transport.asio.socket` at 0x42177B32
- `Call to log_http_result for WebSocket` at 0x42177B54
- `Sec-WebSocket-Extensions` at 0x42177E9D
- `websocketpp.processor` at 0x421781CA
- `Socket component error` at 0x42178299
- `socket_select_interrupter` at 0x42178377
- `websocketpp` at 0x42178665
- `websocketpp.transport.asio` at 0x4217871D
- `Sec-WebSocket-Location` at 0x42178992
- `Sec-WebSocket-Version` at 0x42178A14
- `Sec-WebSocket-Origin` at 0x42178A71
- `Sec-WebSocket-Protocol` at 0x42178BB2
- `Server handshake response` at 0x42179470

## 3. HTTP Protocol (Port 30031)

### MakeRequest Method

From source code (`Requestor.cpp`):
```
MakeRequest(std::string& out, std::string_view route, int param3, int param4)
```
- Uses `WinHttpOpenRequest` with `GET` method
- User-Agent: `NLR/1.0`
- Server: `145.239.80.134:30031`
- Routes are passed as `string_view` — the actual routes are constructed by VMProtect'd callers

### HTTP-Related Strings Found by Ghidra

- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb
- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb
- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb
- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb
- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb
- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb
- Pattern "websocket" found at 6 locations:
- Referenced by FUN_41c2fe70 at 0x41c2ff70
- Full string: "websocketpp.transport"
- Full string: "websocketpp.transport.asio.socket"
- Full string: "websocketpp.processor"
- Full string: "websocketpp"
- Full string: "websocketpp.transport.asio"
- Pattern "Content-Type" found at 6 locations:
- Full string: "BContent-Type: application/ocsp-request"
- Full string: "Content-Type: %s%s%s"
- Referenced by FUN_41eac170 at 0x41eac236
- Referenced by FUN_41eabb80 at 0x41eabbf3
- Referenced by FUN_41f09570 at 0x41f09915
- Full string: "Content-Type: application/dns-message"
- Full string: "Content-Type:"
- Full string: "Content-Type: application/x-www-form-urlencoded"
- Referenced by FUN_41f09570 at 0x41f09929
- Pattern "User-Agent" found at 2 locations:
- Referenced by FUN_41f0f660 at 0x41f0f7fb
- Referenced by FUN_41f06f60 at 0x41f06fe9
- Full string: "User-Agent: %s"
- Referenced by FUN_41f0f660 at 0x41f0f821
- Pattern "Authorization" found at 7 locations:
- Referenced by FUN_41f0b560 at 0x41f0b794
- Referenced by FUN_41f0b560 at 0x41f0b650
- Full string: "Authorization:"
- Full string: "%sAuthorization: Digest %s"
- Full string: "Authorization: Bearer %s"
- Referenced by FUN_41f0b560 at 0x41f0b7bf
- Full string: "%sAuthorization: Basic %s"
- Full string: "%sAuthorization: NTLM %s"
- Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"
- Pattern "Bearer" found at 2 locations:
- Referenced by FUN_41f0b560 at 0x41f0b7ac
- Full string: "Authorization: Bearer %s"
- Pattern "token" found at 11 locations:
- Full string: "unknown token"
- Full string: "Invalid method token."
- Full string: "network_connection_token"
- Full string: "token not present"
- Full string: "token present"
- Full string: "int_ts_RESP_verify_token"
- Full string: "no time stamp token"
- Full string: "ICC or token signature"
- Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
- Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
- Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "
- Pattern "hash" found at 20 locations:
- Full string: "invalid hash bucket count"
- Full string: "expecting a siphash key"
- Full string: "setCext-hashedRoot"
- Full string: "pkey_siphash_init"
- Full string: "hashAlgorithm"
- Full string: "userhash"
- Full string: "EVP_PKEY_get0_siphash"
- Full string: "siphash"
- Full string: "ssl_handshake_hash"
- Full string: "create_synthetic_message_hash"
- Full string: "GOST R 34.11-2012 with 256 bit hash"
- Full string: "GOST R 34.11-2012 with 512 bit hash"
- Full string: "Message hash"
- Referenced by FUN_41f9d4f0 at 0x41f9d512
- Referenced by FUN_41f9d4f0 at 0x41f9d504
- Full string: "%s, userhash=true"
- Full string: "tlsv1 bad certificate hash value"
- Full string: "bad certificate hash value"
- Full string: "cert already in hash table"
- Full string: "cipher or hash unavailable"
- Full string: "strhash"
- Full string: "hashFunc"
- Pattern "POST" found at 4 locations:
- Full string: "Failed sending POST request"
- Full string: "Failed sending HTTP POST request"
- Referenced by FUN_41f06f60 at 0x41f0706c
- Referenced by FUN_41eb2e00 at 0x41eb327d
- Referenced by FUN_41eb2e00 at 0x41eb3275
- Full string: "POST "
- Referenced by FUN_41ef69a0 at 0x41ef74d3
- Pattern "GET" found at 5 locations:
- Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
- Referenced by FUN_41f06f60 at 0x41f0707e
- Referenced by FUN_41eb2e00 at 0x41eb3299
- Referenced by FUN_41eb2e00 at 0x41eb3291
- Full string: "GET "
- Referenced by FUN_41ef69a0 at 0x41ef74bb
- Full string: "GETJ5"
- Pattern "PUT" found at 3 locations:
- Full string: "Failed sending PUT request"
- Referenced by FUN_41f08780 at 0x41f08746
- Referenced by FUN_41f06f60 at 0x41f07075
- Referenced by FUN_41eb2e00 at 0x41eb328b
- Referenced by FUN_41eb2e00 at 0x41eb3283
- Referenced by FUN_41f08780 at 0x41f08740
- Full string: "PUT "
- Referenced by FUN_41ef69a0 at 0x41ef74fb

### URLs and IP Addresses in Binary

- `http://ns.adobe.com/xap/1.0/` at 0x42248460
- `1.3.6.1.5.5.7.3.1` at 0x421A3584
- `127.0.0.1` at 0x421A35C0
- `127.0.0.1/` at 0x421A387C

## 4. Requestor Interface (Virtual Table)

From `neverlosesdk.hpp`:
```cpp
class Requestor {
    virtual void MakeRequest(std::string& out, std::string_view route, int, int) = 0;  // vtable[0]
    virtual void GetSerial(std::string& out, nlohmann::json& request) = 0;             // vtable[1]
    virtual void fn2() = 0;                                                            // vtable[2]
    virtual void fn3() = 0;                                                            // vtable[3]
    virtual void QueryLuaLibrary(std::string& out, std::string_view name) = 0;         // vtable[4]
};
```

### Key Addresses

| VA | Name | VMProtect | Description |
|-----|------|-----------|-------------|
| `0x41BC78E0` | GetSerial | **Yes** | Generates serial from HWID hash JSON |
| `0x41BC98E0` | MakeRequest | **Yes** | HTTP GET to route, returns response body |
| `0x41BC9670` | QueryLuaLibrary | **Yes** | Fetches Lua library by name |
| `0x41BC9450` | Requestor::Instance | No | Returns singleton from `g_pRequestor` |
| `0x41C16EA0` | ws_client_send_wrap | No | WebSocket send wrapper |
| `0x412A0A00` | entry_point | No | Module initialization |
| `0x4200A118` | error_handler | No | `__CxxThrowException` |
| `0x41EBB510` | SHA256_transform | No | SHA-256 block transform |
| `0x41DA0BA0` | mem_dispatcher | No | Memory dispatch/hooking |

### Key Data Addresses

| VA | Name | Description |
|-----|------|-------------|
| `0x42518C58` | g_pRequestor | Singleton pointer to Requestor object |
| `0x42518C54` | g_requestor_flag | Set to `0x80000004` during init |
| `0x42518C44` | g_hConsole | Console handle |
| `0x41BF8341` | auth_token_ptr | Token/key data storage |
| `0x420F5BF4` | vtable_data | Vtable entries for MakeRequest, GetSerial, etc. |

## 5. Authentication Flow

### GetSerial

1. Binary constructs HWID hashes (`hash` and `hash2`, base64-encoded)
2. Packages them as JSON: `{"params":{"hash":"...","hash2":"..."},"type":4}`
3. Calls `GetSerial(out, json_request)` through VMProtect'd vtable slot
4. Server returns a base64-encoded serial (512+ bytes)

### WebSocket Client Structure
```cpp
class Client {
    virtual void vt() = 0;
    int IsConnected;         // +0x04: connection status
    void* endpoint;          // +0x08: websocketpp endpoint object
    uint32_t reserved[2];    // +0x0C
    char* SomeKey;           // +0x14: auth message from server
    uint32_t reserved2[6];   // +0x18
    char* SomeKey1;          // +0x30: auth data from server
};
```

### Auth-Related Strings

- `Authu` at 0x41EB9DE4
- `Unauthorized` at 0x420F6910
- `Non Authoritative Information` at 0x42178938
- `unknown token` at 0x42178AEC
- `thrown but unknown type, cannot serialize into error message` at 0x42179ABB
- `Proxy Authentication Required` at 0x42179F56
- `Network Authentication Required` at 0x42179F74
- `Invalid method token.` at 0x4217B392
- `client_cookie` at 0x4217CB3E
- `client_session` at 0x4217CB79
- `%CMsgSteamDatagramGameServerAuthTicket` at 0x4217CC34
- `authorized_steam_id` at 0x4217CC73
- `authorized_public_ip` at 0x4217CC90
- `21.CMsgSteamDatagramGameServerAuthTicket.ExtraField` at 0x4217CD1B
- `)CMsgSteamDatagramGameserverSessionRequest` at 0x4217CDC7
- `2&.CMsgSteamDatagramGameServerAuthTicket` at 0x4217CE01
- `client_cookie` at 0x4217CE58
- `-CMsgSteamDatagramGameserverSessionEstablished` at 0x4217CE6F
- `client_cookie` at 0x4217CEA1
- `CMsgSteamDatagramNoSession` at 0x4217CEF6
- `client_cookie` at 0x4217CF14
- `client_cookie` at 0x4217D412
- `client_cookie` at 0x4217D579
- `client_session_id` at 0x4217D6C8
- `client_session_id` at 0x4217D7BD

## 6. Ghidra Decompiled Code (Key Functions)

### References to Requestor_Instance (0x41bc9450)

```c
Found 11 references
    Ref from 0x413ca180 type=UNCONDITIONAL_CALL
      In function: FUN_413c75c0 at 0x413c75c0
    Ref from 0x415ed7fd type=UNCONDITIONAL_CALL
      In function: FUN_415e96c0 at 0x415e96c0
    Ref from 0x415ed9b3 type=UNCONDITIONAL_CALL
      In function: FUN_415e96c0 at 0x415e96c0
    Ref from 0x415ede86 type=UNCONDITIONAL_CALL
      In function: FUN_415e96c0 at 0x415e96c0
    Ref from 0x415ee033 type=UNCONDITIONAL_CALL
      In function: FUN_415e96c0 at 0x415e96c0
    Ref from 0x415ee13f type=UNCONDITIONAL_CALL
      In function: FUN_415e96c0 at 0x415e96c0
    Ref from 0x4161888f type=UNCONDITIONAL_CALL
      In function: FUN_41616c00 at 0x41616c00
    Ref from 0x41619813 type=UNCONDITIONAL_CALL
      In function: FUN_41616c00 at 0x41616c00
    Ref from 0x4161b863 type=UNCONDITIONAL_CALL
      In function: FUN_41616c00 at 0x41616c00
    Ref from 0x415c2c2b type=UNCONDITIONAL_CALL
      Not in a known function - attempting to create one
    Ref from 0x415c471b type=UNCONDITIONAL_CALL
      Not in a known function - attempting to create one

  Decompiling 3 caller functions:
```

### References to ws_client_send_wrap (0x41c16ea0)

```c
Found 1 references
    Ref from 0x420f6ff8 type=DATA
      Not in a known function - attempting to create one

  Decompiling 0 caller functions:
```

### References to entry_point (0x412a0a00)

```c
Found 0 references

  Decompiling 0 caller functions:
```

### References to GetSerial (0x41bc78e0)

```c
Found 1 references
    Ref from 0x420f5bf8 type=DATA
      Not in a known function - attempting to create one

  Decompiling 0 caller functions:
```

### References to MakeRequest (0x41bc98e0)

```c
Found 1 references
    Ref from 0x420f5bf4 type=DATA
      Not in a known function - attempting to create one

  Decompiling 0 caller functions:
```

### References to QueryLuaLibrary (0x41bc9670)

```c
Found 1 references
    Ref from 0x420f5c04 type=DATA
      Not in a known function - attempting to create one

  Decompiling 0 caller functions:
```

### Step 6: Finding Network-Related String References

```c
Pattern "websocket" found at 6 locations:
    0x420f62b0
      Referenced by FUN_41c2fe70 at 0x41c2ff70
      Referenced from 0x41c2d9b0
    0x421777bd
      Full string: "websocketpp.transport"
      Referenced from 0x41c20af0
    0x42177b32
      Full string: "websocketpp.transport.asio.socket"
      Referenced from 0x41c16430
    0x421781ca
      Full string: "websocketpp.processor"
      Referenced from 0x41bfaf20
    0x42178665
      Full string: "websocketpp"
      Referenced from 0x41c31c20
    0x4217871d
      Full string: "websocketpp.transport.asio"

  Pattern "Content-Type" found at 6 locations:
    0x42120b74
      Full string: "BContent-Type: application/ocsp-request"
    0x42187c04
      Full string: "Content-Type: %s%s%s"
    0x42193734
      Referenced by FUN_41eac170 at 0x41eac236
      Referenced by FUN_41eabb80 at 0x41eabbf3
      Referenced by FUN_41f09570 at 0x41f09915
      Referenced from 0x41eab1a8
    0x42195430
      Full string: "Content-Type: application/dns-message"
    0x4219f77c
      Full string: "Content-Type:"
    0x421a7c84
      Full string: "Content-Type: application/x-www-form-urlencoded"
      Referenced by FUN_41f09570 at 0x41f09929

  Pattern "User-Agent" found at 2 locations:
    0x4218395c
      Referenced by FUN_41f0f660 at 0x41f0f7fb
      Referenced by FUN_41f06f60 at 0x41f06fe9
    0x421a7bd0
      Full string: "User-Agent: %s"
      Referenced by FUN_41f0f660 at 0x41f0f821

  Pattern "Authorization" found at 7 locations:
    0x4218c02c
      Referenced by FUN_41f0b560 at 0x41f0b794
      Referenced by FUN_41f0b560 at 0x41f0b650
    0x4219f6a4
      Full string: "Authorization:"
    0x421a7b52
      Full string: "%sAuthorization: Digest %s"
    0x421a7b70
      Full string: "Authorization: Bearer %s"
      Referenced by FUN_41f0b560 at 0x41f0b7bf
    0x421a7b8e
      Full string: "%sAuthorization: Basic %s"
    0x421a7baa
      Full string: "%sAuthorization: NTLM %s"
    0x421ac480
      Full string: "Authorization: %s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s"

  Pattern "Bearer" found at 2 locations:
    0x421897ac
      Referenced by FUN_41f0b560 at 0x41f0b7ac
    0x421a7b7f
      Full string: "Authorization: Bearer %s"

  Pattern "token" found at 11 locations:
    0x42178af4
      Full string: "unknown token"
    0x4217b3a1
      Full string: "Invalid method token."
    0x4217f14b
      Full string: "network_connection_token"
    0x42183680
      Full string: "token not present"
    0x42183694
      Full string: "token present"
    0x4218cf73
      Full string: "int_ts_RESP_verify_token"
    0x4218cf8a
      Full string: "no time stamp token"
    0x421928d7
      Full string: "ICC or token signature"
    0x421abff6
      Full string: " Tokenizer::ParseFloat() passed text that could not have been tokenized as a float: "
    0x421ac050
      Full string: " Tokenizer::ParseInteger() passed text that could not have been tokenized as an integer: "
    0x421ac0fd
      Full string: " Tokenizer::ParseStringAppend() passed text that could not have been tokenized as a string: "

  Pattern "hash" found at 20 locations:
    0x42177881
      Full string: "invalid hash bucket count"
    0x42180403
      Full string: "expecting a siphash key"
    0x42183158
      Full string: "setCext-hashedRoot"
    0x42183c9c
      Full string: "pkey_siphash_init"
    0x4218d80c
      Full string: "hashAlgorithm"
    0x4218fa0c
      Full string: "userhash"
    0x4218fa25
      Full string: "EVP_PKEY_get0_siphash"
    0x4218fa2f
      Full string: "siphash"
    0x4218fa42
      Full string: "ssl_handshake_hash"
    0x4218fa61
      Full string: "create_synthetic_message_hash"
    0x4218fa87
      Full string: "GOST R 34.11-2012 with 256 bit hash"
    0x4218faab
      Full string: "GOST R 34.11-2012 with 512 bit hash"
    0x4218fab8
      Full string: "Message hash"
      Referenced by FUN_41f9d4f0 at 0x41f9d512
      Referenced by FUN_41f9d4f0 at 0x41f9d504
    0x421916bc
      Full string: "%s, userhash=true"
    0x42191852
      Full string: "tlsv1 bad certificate hash value"
    0x42191870
      Full string: "bad certificate hash value"
    0x42194b34
      Full string: "cert already in hash table"
    0x42194c2a
      Full string: "cipher or hash unavailable"
    0x42195955
      Full string: "strhash"
    0x42199554
      Full string: "hashFunc"

  Pattern "POST" found at 4 locations:
    0x42182427
      Full string: "Failed sending POST request"
    0x42182448
      Full string: "Failed sending HTTP POST request"
    0x4219b440
      Referenced by FUN_41f06f60 at 0x41f0706c
      Referenced by FUN_41eb2e00 at 0x41eb327d
      Referenced by FUN_41eb2e00 at 0x41eb3275
    0x421a6744
      Full string: "POST "
      Referenced by FUN_41ef69a0 at 0x41ef74d3

  Pattern "GET" found at 5 locations:
    0x420f6890
      Referenced from 0x41c10364
    0x4217f030
      Full string: ",NETWORK_DISCONNECT_VERYLARGETRANSFEROVERFLOW"
    0x4219b768
      Referenced by FUN_41f06f60 at 0x41f0707e
      Referenced by FUN_41eb2e00 at 0x41eb3299
      Referenced by FUN_41eb2e00 at 0x41eb3291
    0x421a674c
      Full string: "GET "
      Referenced by FUN_41ef69a0 at 0x41ef74bb
    0x4275e7f2
      Full string: "GETJ5"

  Pattern "PUT" found at 3 locations:
    0x4218240b
      Full string: "Failed sending PUT request"
    0x4219b428
      Referenced by FUN_41f08780 at 0x41f08746
      Referenced by FUN_41f06f60 at 0x41f07075
      Referenced by FUN_41eb2e00 at 0x41eb328b
      Referenced by FUN_41eb2e00 at 0x41eb3283
      Referenced by FUN_41f08780 at 0x41f08740
    0x421a673c
      Full string: "PUT "
      Referenced by FUN_41ef69a0 at 0x41ef74fb
```

### Step 7: Analyzing Requestor Vtable

```c
g_pRequestor (0x42518C58) = 0x0
```

### Auth Token Analysis

```c
Auth token data at 0x41BF8341: "\xC8-&B\x0FW\xC0\x0F)F`\xC7Ft"

[*] Analysis complete.
```

## 7. radare2 Disassembly (Key Functions)

### String Search Results (r2)

## 8. Unicorn Emulation Results

### Requestor_Instance
- Address: 0x41BC9450
- Status: completed
- Instructions executed: 28
- Return value: 0x00000000

### ws_client_send_wrap
- Address: 0x41C16EA0
- Status: completed
- Instructions executed: 50000
- Return value: 0x00000000

### entry_point
- Address: 0x412A0A00
- Status: completed
- Instructions executed: 50000
- Return value: 0x4479135C

### error_handler
- Address: 0x4200A118
- Status: completed
- Instructions executed: 50000
- Return value: 0x700FEFF0

### SHA256_transform
- Address: 0x41EBB510
- Status: completed
- Instructions executed: 38
- Return value: 0x00000000

### mem_dispatcher
- Address: 0x41DA0BA0
- Status: completed
- Instructions executed: 50000
- Return value: 0xE3E9B4C3

## 9. Cross-Reference Analysis

### 0x41BC78E0_GetSerial (1 refs)

- `0x420F5BF8`: (data ref)

### 0x41BC98E0_MakeRequest (1 refs)

- `0x420F5BF4`: (data ref)

### 0x41BC9670_QueryLuaLibrary (1 refs)

- `0x420F5C04`: (data ref)

### 0x41C16EA0_ws_client_send_wrap (1 refs)

- `0x420F6FF8`: (data ref)

### 0x42518C58_g_pRequestor (3 refs)

- `0x41BC78B3`: (data ref)
- `0x41BC949B`: followed_by_call_0x41CA1E0A
- `0x41BC94CF`: push_imm32, followed_by_call_0x41BC9610

### 0x42518C44_g_hConsole (1 refs)

- `0x41BC072F`: followed_by_call_0x42033BB0

## 10. Server Implementation Guide

### WSS Server (Port 30030)

1. Accept TLS WebSocket connections at `wss://host:30030/`
2. On new connection, immediately send 3 frames:
   - Frame 1 (text): `{"Type":"Auth","Message":"<16-char-key>","Data":"<16-char-data>"}`
   - Frame 2 (binary): The encrypted module payload (385,360 bytes)
   - Frame 3 (binary): Encryption key/signature (80 bytes)
3. Handle client auth message: `{"params":{"hash":"...","hash2":"..."},"type":4}`
4. The `Message` and `Data` fields map to `Client::SomeKey` and `Client::SomeKey1`

### HTTP Server (Port 30031)

1. Accept HTTP GET requests with `User-Agent: NLR/1.0`
2. Routes are passed via `MakeRequest(out, route, param3, param4)`
3. The actual routes are constructed by VMProtect'd code — not directly extractable
4. Response body is returned as raw string via the `out` parameter

### Authentication

1. Client computes HWID hashes (base64)
2. Sends `GetSerial` with JSON: `{"params":{"hash":"...","hash2":"..."},"type":4}`
3. Server returns base64-encoded serial string (512+ bytes)
4. Serial is used for ongoing session authentication

## 11. WSS Binary Dump Files

All captured in `/tmp/nl_analysis/output/ws_dumps/`:

| File | Size | Description |
|------|------|-------------|
| `001_s1_auth_test_sent_auth.txt` | 50 | Client auth request |
| `002_s1_auth_test_recv_auth_r1.txt` | 70 | Auth JSON response |
| `003_s1_auth_test_recv_auth_r2.bin` | 385,360 | 385KB encrypted payload |
| `004_s1_auth_test_recv_auth_r3.bin` | 80 | 80-byte encrypted blob |
| `005_s2_auth_real_sent_auth_real.txt` | 142 | Client auth request |
| `006_s2_auth_real_recv_auth_real_r1.txt` | 70 | Auth JSON response |
| `007_s2_auth_real_recv_auth_real_r2.bin` | 385,360 | 385KB encrypted payload |
| `008_s2_auth_real_recv_auth_real_r3.bin` | 80 | 80-byte encrypted blob |
| `009_s3_types_sent_t1.txt` | 10 | Client message |
| `010_s3_types_recv_t1_r1.txt` | 70 | Auth JSON response |
| `011_s3_types_recv_t1_r2.bin` | 385,360 | 385KB encrypted payload |
| `012_s3_types_recv_t1_r3.bin` | 80 | 80-byte encrypted blob |
| `013_s3_types_sent_t2.txt` | 10 | Client message |
| `014_s3_types_sent_t3.txt` | 10 | Client message |
| `015_s3_types_sent_t5.txt` | 10 | Client message |
| `016_s4_post_auth_sent_auth.txt` | 50 | Client auth request |
| `017_s4_post_auth_recv_auth_r1.txt` | 70 | Auth JSON response |
| `018_s4_post_auth_recv_auth_r2.bin` | 385,360 | 385KB encrypted payload |
| `019_s4_post_auth_recv_auth_r3.bin` | 80 | 80-byte encrypted blob |
| `020_s4_post_auth_sent_post_t1.txt` | 10 | Client auth request |
| `021_s4_post_auth_sent_post_t2.txt` | 10 | Client auth request |
| `022_s4_post_auth_sent_post_t3.txt` | 10 | Client auth request |
| `023_s4_post_auth_sent_post_t5.txt` | 10 | Client auth request |
| `024_s4_post_auth_sent_post_t0.txt` | 10 | Client auth request |
| `025_s5_binary_sent_bin4.bin` | 4 | Client message |
| `026_s5_binary_recv_bin4_r1.txt` | 70 | Auth JSON response |
| `027_s5_binary_recv_bin4_r2.bin` | 385,360 | 385KB encrypted payload |
| `028_s5_binary_recv_bin4_r3.bin` | 80 | 80-byte encrypted blob |
| `029_s5_binary_sent_bin1.bin` | 4 | Client message |

## 12. Additional References

### Port References in Code

- **ws_port_30030**: 2 refs — 0x4232F976, 0x42530B8A
- **https_443**: 18 refs — 0x415ACD90, 0x418EA143, 0x41BFF54C, 0x41C0FEBA, 0x41C26BCA
- **http_80**: 79 refs — 0x412A5C76, 0x412A5C7E, 0x412F6351, 0x41326295, 0x41326363
- **alt_http_8080**: 10 refs — 0x416F9170, 0x41A0D377, 0x41BAEB25, 0x41C5BD51, 0x41C5D2F2

### Network Byte Patterns

- **ws_upgrade**: 0x420F62B0, 0x421777BD, 0x42177B32, 0x421781CA, 0x42178665, 0x4217871D

### Crypto Strings

- `prsAd` at 0x41723A4C
- `ENCRYPTED` at 0x42121FA0
- `ampersand` at 0x4212E74D
- `ampersandsmall` at 0x4212ED8E
- `AEsmall` at 0x4212F2E3
- `CipherModeBase: feedback size cannot be specified for this cipher mode` at 0x42179B15
- `EVP_CIPHER_CTX_copy` at 0x4217FBBC
- `encipherOnly` at 0x4217FCB0
- `decipherOnly` at 0x4217FCC0
- `Encipher Only` at 0x4217FCE0
- `Decipher Only` at 0x4217FCF0
- `rsa_cms_verify` at 0x4217FDF0
- `rsa_item_verify` at 0x4217FE64
- `pkey_rsa_verify` at 0x4217FE9C
- `int_rsa_verify` at 0x4217FEAC
- `RSA_verify` at 0x4217FEE8
- `CMS_decrypt_set1_pkey` at 0x4217FFEC
- `aes_xts_init_key` at 0x42180068
- `aesni_xts_init_key` at 0x4218007C
- `aes_t4_xts_init_key` at 0x42180090

### Lua Strings

- `in function mp_encode_lua_table_as_array` at 0x421771A2
- `in function mp_decode_to_lua_array` at 0x421771CB
- `invalid vector subscript` at 0x42177826
- `invalid array<T, N> subscript` at 0x4217783F
- `not enough space left on Lua stack to retrieve environment` at 0x42177933
- `The descriptor does not fit into the select call's fd_set` at 0x42177AB8
- `not enough space left on Lua stack to push valuees` at 0x4217800C
- `not enough space left on Lua stack for a floating point number` at 0x42178579
- `not enough space left on Lua stack for an integral number` at 0x421785CE
- `in function mp_encode_lua_table_as_map` at 0x42178676
- `not enough space left on Lua stack for the name of a meta_function` at 0x42178841
- `not enough space left on Lua stack for a string` at 0x42178F37
- `not enough Lua stack space to push this reference value` at 0x421790F6
- `not enough Lua stack space to push a single reference value` at 0x4217912E
- `MessagePack C implementation for Lua` at 0x4217A584

### Phase Output Files

| File | Size | Description |
|------|------|-------------|
| `phase1_results.json` | 466,006 | String extraction + byte-level xrefs |
| `ghidra_results.txt` | 832,897 | Ghidra decompiled output |
| `r2_results.txt` | 62,870 | radare2 disassembly + xrefs |
| `phase4_emulation.json` | 9,252 | Unicorn emulation traces |
| `phase4_server_probe.json` | 13,216 | Live server probing results |
