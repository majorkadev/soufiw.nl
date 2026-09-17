#!/usr/bin/env python3
"""
Neverlose Client Emulator - Unicorn-based sandboxed emulation

Sets up a fake Requestor object with logging vtable stubs so that when
non-VMProtect'd caller functions invoke virtual methods (MakeRequest,
GetSerial, QueryLuaLibrary, fn2, fn3), we capture the arguments.

Key approach:
  - Create a fake Requestor at a known address with a vtable where each
    slot points to a stub that logs arguments and returns cleanly
  - Write g_pRequestor (0x42518C58) to point to our fake Requestor
  - Emulate non-VMP'd caller functions that call through the vtable
  - Hook all indirect calls to detect vtable dispatches
  - Log everything: memory accesses, strings, vtable calls, arguments

Usage:
  nix-shell -p "python3.withPackages (ps: [ps.unicorn ps.capstone])" \\
    --run "python3 analysis/scripts/emulate_client.py"
"""

import json
import os
import struct
import sys
import time
import traceback
from collections import defaultdict

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    print("ERROR: pip install unicorn")
    sys.exit(1)

try:
    from capstone import *
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    print("WARNING: capstone not available, disassembly disabled")

# ============================================================================
# Constants
# ============================================================================

BINARY_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "neverlose", "bins", "nl.bin")
if not os.path.exists(BINARY_PATH):
    BINARY_PATH = "/tmp/nl_analysis/nl.bin"

OUTPUT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "emulation_v2.json")

BASE_ADDR    = 0x412A0000
STACK_ADDR   = 0x70000000
STACK_SIZE   = 0x100000   # 1MB
TEB_ADDR     = 0x7FFE0000
PEB_ADDR     = 0x7FFD0000
GDT_ADDR     = 0x7FFC0000
HEAP_ADDR    = 0x10000000
HEAP_SIZE    = 0x200000   # 2MB
API_STUB_ADDR = 0x77000000
API_STUB_SIZE = 0x10000

# Fake objects we create
FAKE_REQUESTOR_ADDR = 0x60000000  # Our fake Requestor object
FAKE_VTABLE_ADDR    = 0x60001000  # Vtable for fake Requestor
FAKE_STUBS_ADDR     = 0x60002000  # Stub code for vtable methods
FAKE_CLIENT_ADDR    = 0x60003000  # Fake Client object
FAKE_STRING_BUF     = 0x60004000  # Buffer for std::string out params
FAKE_REGION_SIZE    = 0x10000

# Known addresses from the binary
KNOWN_FUNCTIONS = {
    0x41BC9450: "Requestor_Instance",
    0x41C16EA0: "ws_client_send_wrap",
    0x412A0A00: "entry_point",
    0x4200A118: "error_handler",
    0x41EBB510: "SHA256_transform",
    0x41DA0BA0: "mem_dispatcher",
}

VMP_FUNCTIONS = {
    0x41BC78E0: "GetSerial",
    0x41BC98E0: "MakeRequest",
    0x41BC9670: "QueryLuaLibrary",
}

# Non-VMP'd callers found by Ghidra that call through Requestor vtable
CALLER_FUNCTIONS = {
    0x415E96C0: "FUN_415e96c0",   # Calls vtable[4] (QueryLuaLibrary), vtable[3] (fn3); builds query params
    0x413C75C0: "FUN_413c75c0",   # Calls vtable[3] (fn3)
    0x41616C00: "FUN_41616c00",   # Calls vtable[3] (fn3)
    0x41BFAAD0: "ws_event_loop",  # WebSocket++ io_service::run
    0x41BFA0B0: "ssl_tls_init",   # SSL/TLS context init
    0x41BFAD20: "msg_dispatch_1", # WebSocket message dispatcher
    0x41BF1E70: "msg_dispatch_2", # WebSocket message dispatcher
}

DATA_ADDRS = {
    0x42518C58: "g_pRequestor",
    0x42518C54: "g_pRequestor_flag",
    0x41BF8341: "auth_token_ptr",
    0x42518C44: "g_hConsole",
    0x420F5BF4: "vtable_MakeRequest",
    0x420F5BF8: "vtable_GetSerial",
    0x420F5C04: "vtable_QueryLuaLibrary",
    0x420F6FF8: "vtable_ws_send_wrap",
}

# Vtable slot mapping (MSVC __thiscall: this in ECX, args on stack)
# vtable[0] = MakeRequest(std::string& out, std::string_view route, int, int)
# vtable[1] = GetSerial(std::string& out, nlohmann::json& request)
# vtable[2] = fn2()
# vtable[3] = fn3()
# vtable[4] = QueryLuaLibrary(std::string& out, std::string_view name)
VTABLE_SLOTS = {
    0: "MakeRequest",
    1: "GetSerial",
    2: "fn2",
    3: "fn3",
    4: "QueryLuaLibrary",
}


# ============================================================================
# Emulator
# ============================================================================

class NLEmulator:
    def __init__(self):
        self.uc = None
        self.cs = None
        self.binary_data = None
        self.binary_size = 0
        self.heap_ptr = HEAP_ADDR + 0x1000
        self.instruction_count = 0
        self.max_instructions = 200000
        self.current_function = None

        # Logging
        self.log = []
        self.vtable_calls = []
        self.vmp_calls = []
        self.api_calls = []
        self.mem_accesses = []
        self.strings_accessed = []
        self.indirect_calls = []
        self.errors = []
        self.function_results = {}

        # Track string_view arguments
        self.captured_routes = []
        self.captured_lua_libs = []
        self.captured_serials = []

    def info(self, msg):
        print(f"  {msg}")
        self.log.append(msg)

    def load_binary(self):
        print(f"[*] Loading binary from {BINARY_PATH}")
        with open(BINARY_PATH, "rb") as f:
            self.binary_data = f.read()
        self.binary_size = len(self.binary_data)
        print(f"    Size: {self.binary_size:,} bytes ({self.binary_size / 1024 / 1024:.1f} MB)")

    def setup_capstone(self):
        if HAS_CAPSTONE:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.cs.detail = True

    def create_gdt_entry(self, base, limit, access, flags):
        entry = bytearray(8)
        entry[0] = limit & 0xFF
        entry[1] = (limit >> 8) & 0xFF
        entry[2] = base & 0xFF
        entry[3] = (base >> 8) & 0xFF
        entry[4] = (base >> 16) & 0xFF
        entry[5] = access
        entry[6] = ((limit >> 16) & 0x0F) | (flags << 4)
        entry[7] = (base >> 24) & 0xFF
        return bytes(entry)

    def setup_unicorn(self):
        print("[*] Setting up Unicorn x86-32 emulator")
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # 1. Map binary
        binary_pages = ((self.binary_size + 0xFFF) & ~0xFFF)
        self.uc.mem_map(BASE_ADDR, binary_pages, UC_PROT_ALL)
        self.uc.mem_write(BASE_ADDR, self.binary_data)
        print(f"    Binary mapped: 0x{BASE_ADDR:08X} - 0x{BASE_ADDR + binary_pages:08X}")

        # 2. Map stack
        self.uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)

        # 3. Map TEB/PEB/GDT region
        self.uc.mem_map(GDT_ADDR, 0x40000, UC_PROT_ALL)

        # Setup TEB
        teb = bytearray(0x1000)
        struct.pack_into("<I", teb, 0x00, 0)           # ExceptionList (NULL)
        struct.pack_into("<I", teb, 0x04, STACK_ADDR + STACK_SIZE)  # StackBase
        struct.pack_into("<I", teb, 0x08, STACK_ADDR)   # StackLimit
        struct.pack_into("<I", teb, 0x18, TEB_ADDR)     # Self
        struct.pack_into("<I", teb, 0x24, 0x1000)       # ThreadId
        struct.pack_into("<I", teb, 0x2C, GDT_ADDR + 0x3000)  # ThreadLocalStoragePointer
        struct.pack_into("<I", teb, 0x30, PEB_ADDR)     # PEB pointer
        self.uc.mem_write(TEB_ADDR, bytes(teb))

        # Setup TLS array
        tls_array = bytearray(0x100)  # 64 TLS slots
        self.uc.mem_write(GDT_ADDR + 0x3000, bytes(tls_array))

        # Setup PEB
        peb = bytearray(0x1000)
        struct.pack_into("<I", peb, 0x08, BASE_ADDR)    # ImageBaseAddress
        struct.pack_into("<I", peb, 0x0C, 0)            # Ldr (NULL)
        self.uc.mem_write(PEB_ADDR, bytes(peb))

        # 4. Setup GDT
        gdt = bytearray(0x100)
        gdt[0x08:0x10] = self.create_gdt_entry(0, 0xFFFFF, 0x9B, 0x0C)  # CS
        gdt[0x10:0x18] = self.create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C)  # DS
        gdt[0x18:0x20] = self.create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C)  # SS
        gdt[0x20:0x28] = self.create_gdt_entry(TEB_ADDR, 0xFFF, 0xF3, 0x0C)  # FS -> TEB
        self.uc.mem_write(GDT_ADDR, bytes(gdt))
        self.uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, 0x100, 0))
        self.uc.reg_write(UC_X86_REG_CS, 0x08)
        self.uc.reg_write(UC_X86_REG_DS, 0x10)
        self.uc.reg_write(UC_X86_REG_ES, 0x10)
        self.uc.reg_write(UC_X86_REG_SS, 0x18)
        self.uc.reg_write(UC_X86_REG_FS, 0x23)
        self.uc.reg_write(UC_X86_REG_GS, 0x10)

        # 5. Map heap
        self.uc.mem_map(HEAP_ADDR, HEAP_SIZE, UC_PROT_ALL)

        # 6. Map API stub region (filled with RET instructions)
        self.uc.mem_map(API_STUB_ADDR, API_STUB_SIZE, UC_PROT_ALL)
        self.uc.mem_write(API_STUB_ADDR, b"\xC3" * API_STUB_SIZE)

        # 7. Map fake objects region
        self.uc.mem_map(FAKE_REQUESTOR_ADDR, FAKE_REGION_SIZE, UC_PROT_ALL)

        print(f"    Stack: 0x{STACK_ADDR:08X} ({STACK_SIZE // 1024}KB)")
        print(f"    TEB: 0x{TEB_ADDR:08X}, PEB: 0x{PEB_ADDR:08X}")
        print(f"    Heap: 0x{HEAP_ADDR:08X} ({HEAP_SIZE // 1024}KB)")
        print(f"    Fake objects: 0x{FAKE_REQUESTOR_ADDR:08X}")

    def setup_fake_requestor(self):
        """Create a fake Requestor object with a vtable that points to logging stubs."""
        print("[*] Setting up fake Requestor with logging vtable")

        # Each stub is a small piece of x86 code that does:
        #   mov eax, STUB_ID    ; identify which vtable slot was called
        #   int3                ; breakpoint - we catch this in hook
        #   ret                 ; return to caller
        # We use INT3 (0xCC) as a trap to log in our hook_intr handler

        stubs = bytearray(0x1000)
        for slot_idx in range(5):
            offset = slot_idx * 0x20  # 32 bytes per stub
            # mov eax, slot_idx
            stubs[offset] = 0xB8
            struct.pack_into("<I", stubs, offset + 1, slot_idx)
            # int3
            stubs[offset + 5] = 0xCC
            # ret (caller cleans stack for __thiscall)
            stubs[offset + 6] = 0xC3

        self.uc.mem_write(FAKE_STUBS_ADDR, bytes(stubs))

        # Build vtable: 5 function pointers
        vtable = bytearray(0x20)
        for slot_idx in range(5):
            stub_addr = FAKE_STUBS_ADDR + slot_idx * 0x20
            struct.pack_into("<I", vtable, slot_idx * 4, stub_addr)
        self.uc.mem_write(FAKE_VTABLE_ADDR, bytes(vtable))

        # Build Requestor object: first DWORD is vtable pointer
        obj = bytearray(0x100)
        struct.pack_into("<I", obj, 0, FAKE_VTABLE_ADDR)  # vtable ptr
        self.uc.mem_write(FAKE_REQUESTOR_ADDR, bytes(obj))

        # Write g_pRequestor to point to our fake Requestor
        self.uc.mem_write(0x42518C58, struct.pack("<I", FAKE_REQUESTOR_ADDR))
        # Set the flag that indicates Requestor is initialized
        self.uc.mem_write(0x42518C54, struct.pack("<I", 0x80000004))

        # Also set up a fake string buffer for out parameters
        # MSVC std::string small buffer: [ptr, size, capacity, buffer[16]]
        str_buf = bytearray(0x100)
        # ptr = points to inline buffer at offset 16
        struct.pack_into("<I", str_buf, 0, FAKE_STRING_BUF + 16)
        struct.pack_into("<I", str_buf, 4, 0)  # size = 0
        struct.pack_into("<I", str_buf, 8, 15) # capacity = 15 (SSO)
        self.uc.mem_write(FAKE_STRING_BUF, bytes(str_buf))

        print(f"    Requestor object: 0x{FAKE_REQUESTOR_ADDR:08X}")
        print(f"    Vtable: 0x{FAKE_VTABLE_ADDR:08X}")
        print(f"    Stubs: 0x{FAKE_STUBS_ADDR:08X}")
        print(f"    g_pRequestor patched at 0x42518C58 -> 0x{FAKE_REQUESTOR_ADDR:08X}")

    def setup_fake_client(self):
        """Create a fake Client object with SomeKey/SomeKey1 from auth."""
        print("[*] Setting up fake Client with auth keys")

        client = bytearray(0x100)
        # vtable pointer (slot 0) - point to a RET stub
        struct.pack_into("<I", client, 0x00, API_STUB_ADDR)
        # IsConnected
        struct.pack_into("<I", client, 0x04, 1)
        # endpoint (websocketpp)
        struct.pack_into("<I", client, 0x08, 0)

        # SomeKey at offset +0x14: "fz8XfUGGBvylN7IW"
        key_addr = FAKE_CLIENT_ADDR + 0x80
        struct.pack_into("<I", client, 0x14, key_addr)
        key1 = b"fz8XfUGGBvylN7IW\x00"
        client[0x80:0x80+len(key1)] = key1

        # SomeKey1 at offset +0x30: "5aAxpFpna5QqvYMv"
        key2_addr = FAKE_CLIENT_ADDR + 0xA0
        struct.pack_into("<I", client, 0x30, key2_addr)
        key2 = b"5aAxpFpna5QqvYMv\x00"
        client[0xA0:0xA0+len(key2)] = key2

        self.uc.mem_write(FAKE_CLIENT_ADDR, bytes(client))
        print(f"    Client object: 0x{FAKE_CLIENT_ADDR:08X}")
        print(f"    SomeKey:  '{key1[:-1].decode()}' at 0x{key_addr:08X}")
        print(f"    SomeKey1: '{key2[:-1].decode()}' at 0x{key2_addr:08X}")

    def read_string(self, addr, max_len=512):
        """Read a null-terminated ASCII string from memory."""
        try:
            data = bytes(self.uc.mem_read(addr, max_len))
            null = data.find(b"\x00")
            if null > 0:
                s = data[:null]
                if all(0x20 <= b < 0x7F for b in s):
                    return s.decode("ascii")
        except Exception:
            pass
        return None

    def read_string_view(self, data_ptr, size):
        """Read a std::string_view given pointer and size."""
        if size == 0 or size > 4096 or data_ptr == 0:
            return None
        try:
            data = bytes(self.uc.mem_read(data_ptr, size))
            if all(0x20 <= b < 0x7F for b in data):
                return data.decode("ascii")
            return data.hex()
        except Exception:
            return None

    def read_std_string(self, string_obj_addr):
        """Read an MSVC std::string object."""
        try:
            raw = bytes(self.uc.mem_read(string_obj_addr, 32))
            # MSVC layout: union { char buf[16]; char* ptr; } at offset 0
            # size at offset 16, capacity at offset 20
            size = struct.unpack_from("<I", raw, 16)[0]
            capacity = struct.unpack_from("<I", raw, 20)[0]

            if size == 0:
                return ""
            if capacity <= 15:
                # Small string optimization - data is inline
                data = raw[:size]
            else:
                # Data is on heap
                ptr = struct.unpack_from("<I", raw, 0)[0]
                data = bytes(self.uc.mem_read(ptr, min(size, 4096)))

            if all(0x20 <= b < 0x7F or b in (0x0A, 0x0D, 0x09) for b in data):
                return data.decode("ascii", errors="replace")
            return data.hex()
        except Exception:
            return None

    # ========================================================================
    # Hooks
    # ========================================================================

    def hook_interrupt(self, uc, intno, user_data):
        """Catch INT3 from our vtable stubs."""
        if intno == 3:  # INT3 - our vtable stub trap
            eax = uc.reg_read(UC_X86_REG_EAX)
            ecx = uc.reg_read(UC_X86_REG_ECX)
            esp = uc.reg_read(UC_X86_REG_ESP)
            eip = uc.reg_read(UC_X86_REG_EIP)

            slot_name = VTABLE_SLOTS.get(eax, f"unknown_slot_{eax}")

            entry = {
                "slot": eax,
                "name": slot_name,
                "this": f"0x{ecx:08X}",
                "caller_function": self.current_function,
                "eip": f"0x{eip:08X}",
            }

            # Read arguments based on slot
            try:
                # Return address is at [esp], args start at [esp+4]
                ret_addr = struct.unpack("<I", bytes(uc.mem_read(esp, 4)))[0]
                entry["return_to"] = f"0x{ret_addr:08X}"

                if eax == 0:  # MakeRequest(string& out, string_view route, int, int)
                    args = struct.unpack("<5I", bytes(uc.mem_read(esp + 4, 20)))
                    out_ptr, route_ptr, route_size, p3, p4 = args
                    route = self.read_string_view(route_ptr, route_size)
                    entry["args"] = {
                        "out_ptr": f"0x{out_ptr:08X}",
                        "route_ptr": f"0x{route_ptr:08X}",
                        "route_size": route_size,
                        "route": route,
                        "param3": p3,
                        "param4": p4,
                    }
                    if route:
                        self.captured_routes.append(route)
                    self.info(f"  *** VTABLE[0] MakeRequest(route='{route}', p3={p3}, p4={p4})")

                elif eax == 1:  # GetSerial(string& out, json& request)
                    args = struct.unpack("<2I", bytes(uc.mem_read(esp + 4, 8)))
                    out_ptr, json_ptr = args
                    # Try reading the JSON object
                    json_str = self.read_std_string(json_ptr) if json_ptr else None
                    entry["args"] = {
                        "out_ptr": f"0x{out_ptr:08X}",
                        "json_ptr": f"0x{json_ptr:08X}",
                        "json_content": json_str,
                    }
                    self.info(f"  *** VTABLE[1] GetSerial(json='{json_str}')")

                elif eax == 2:  # fn2()
                    entry["args"] = {}
                    self.info(f"  *** VTABLE[2] fn2()")

                elif eax == 3:  # fn3()
                    # fn3 might take arguments we don't know about yet
                    # Read a few stack slots to see
                    stack_args = struct.unpack("<4I", bytes(uc.mem_read(esp + 4, 16)))
                    # Try reading each as a string pointer
                    arg_strs = []
                    for i, arg in enumerate(stack_args):
                        s = self.read_string(arg) if 0x10000 < arg < 0x80000000 else None
                        arg_strs.append(s)
                    entry["args"] = {
                        f"arg{i}": f"0x{a:08X}" + (f" ('{s}')" if s else "")
                        for i, (a, s) in enumerate(zip(stack_args, arg_strs))
                    }
                    self.info(f"  *** VTABLE[3] fn3({', '.join(f'0x{a:08X}' for a in stack_args)})")

                elif eax == 4:  # QueryLuaLibrary(string& out, string_view name)
                    args = struct.unpack("<3I", bytes(uc.mem_read(esp + 4, 12)))
                    out_ptr, name_ptr, name_size = args
                    name = self.read_string_view(name_ptr, name_size)
                    entry["args"] = {
                        "out_ptr": f"0x{out_ptr:08X}",
                        "name_ptr": f"0x{name_ptr:08X}",
                        "name_size": name_size,
                        "name": name,
                    }
                    if name:
                        self.captured_lua_libs.append(name)
                    self.info(f"  *** VTABLE[4] QueryLuaLibrary(name='{name}')")

            except Exception as e:
                entry["error"] = str(e)

            self.vtable_calls.append(entry)

            # Skip past the INT3 to the RET instruction
            uc.reg_write(UC_X86_REG_EIP, eip + 1)

    def hook_code(self, uc, address, size, user_data):
        """Hook every instruction for call interception."""
        self.instruction_count += 1
        if self.instruction_count >= self.max_instructions:
            uc.emu_stop()
            return

        # Check if we're executing inside our fake vtable stubs
        if FAKE_STUBS_ADDR <= address < FAKE_STUBS_ADDR + 0x1000:
            slot = (address - FAKE_STUBS_ADDR) // 0x20
            if (address - FAKE_STUBS_ADDR) % 0x20 == 0:  # First instruction of stub
                self._handle_vtable_stub_entry(uc, address, slot)
            return

        # Check for calls to VMP'd functions or indirect vtable calls
        try:
            code = bytes(uc.mem_read(address, min(size, 16)))
        except Exception:
            return

        # Direct CALL rel32
        if len(code) >= 5 and code[0] == 0xE8:
            rel = struct.unpack("<i", code[1:5])[0]
            target = (address + 5 + rel) & 0xFFFFFFFF
            self._handle_direct_call(uc, address, target)

        # Direct CALL to Requestor::Instance - log it
        if len(code) >= 5 and code[0] == 0xE8:
            rel = struct.unpack("<i", code[1:5])[0]
            target = (address + 5 + rel) & 0xFFFFFFFF
            if target == 0x41BC9450:
                self.info(f"  >> CALL Requestor::Instance from 0x{address:08X}")

        # Indirect CALL - try to resolve target
        if len(code) >= 2 and code[0] == 0xFF:
            modrm = code[1]
            reg_field = (modrm >> 3) & 7
            if reg_field == 2:  # CALL indirect
                self._handle_indirect_call(uc, address, code)

    def _handle_vtable_stub_entry(self, uc, address, slot):
        """Called when execution enters one of our fake vtable stubs."""
        slot_name = VTABLE_SLOTS.get(slot, f"unknown_{slot}")
        ecx = uc.reg_read(UC_X86_REG_ECX)
        esp = uc.reg_read(UC_X86_REG_ESP)

        self.info(f"  !!! VTABLE STUB HIT: slot {slot} ({slot_name}) at 0x{address:08X}")

        entry = {
            "slot": slot,
            "name": slot_name,
            "this": f"0x{ecx:08X}",
            "caller_function": self.current_function,
            "eip": f"0x{address:08X}",
        }

        try:
            # Return address is at [esp], args start at [esp+4]
            ret_addr = struct.unpack("<I", bytes(uc.mem_read(esp, 4)))[0]
            entry["return_to"] = f"0x{ret_addr:08X}"

            if slot == 0:  # MakeRequest
                args = struct.unpack("<5I", bytes(uc.mem_read(esp + 4, 20)))
                out_ptr, route_ptr, route_size, p3, p4 = args
                route = self.read_string_view(route_ptr, route_size)
                entry["args"] = {"route": route, "param3": p3, "param4": p4}
                if route:
                    self.captured_routes.append(route)
                self.info(f"      MakeRequest(route='{route}', p3={p3}, p4={p4})")

            elif slot == 1:  # GetSerial
                args = struct.unpack("<2I", bytes(uc.mem_read(esp + 4, 8)))
                out_ptr, json_ptr = args
                json_str = self.read_std_string(json_ptr) if json_ptr else None
                entry["args"] = {"json": json_str}
                self.info(f"      GetSerial(json='{json_str}')")

            elif slot == 4:  # QueryLuaLibrary
                args = struct.unpack("<3I", bytes(uc.mem_read(esp + 4, 12)))
                out_ptr, name_ptr, name_size = args
                name = self.read_string_view(name_ptr, name_size)
                entry["args"] = {"name": name}
                if name:
                    self.captured_lua_libs.append(name)
                self.info(f"      QueryLuaLibrary(name='{name}')")

            else:  # fn2, fn3
                stack_args = struct.unpack("<8I", bytes(uc.mem_read(esp + 4, 32)))
                arg_info = {}
                for i, a in enumerate(stack_args):
                    s = self.read_string(a) if 0x10000 < a < 0x80000000 else None
                    arg_info[f"arg{i}"] = f"0x{a:08X}" + (f" ('{s}')" if s else "")
                entry["args"] = arg_info
                self.info(f"      {slot_name}({', '.join(f'0x{a:08X}' for a in stack_args[:4])})")

        except Exception as e:
            entry["error"] = str(e)

        self.vtable_calls.append(entry)

    def _handle_direct_call(self, uc, from_addr, target):
        """Handle a direct CALL instruction."""
        if target in VMP_FUNCTIONS:
            name = VMP_FUNCTIONS[target]
            ecx = uc.reg_read(UC_X86_REG_ECX)
            esp = uc.reg_read(UC_X86_REG_ESP)

            entry = {
                "from": f"0x{from_addr:08X}",
                "target": f"0x{target:08X}",
                "name": name,
                "ecx": f"0x{ecx:08X}",
                "function": self.current_function,
            }

            # Try to read arguments
            try:
                stack = struct.unpack("<8I", bytes(uc.mem_read(esp, 32)))
                entry["stack"] = [f"0x{s:08X}" for s in stack]

                if name == "MakeRequest":
                    # After CALL pushes return addr: out=[esp+4], route_ptr=[esp+8], ...
                    # But before CALL: out=[esp], route_ptr=[esp+4], ...
                    out_ptr, route_ptr, route_size = stack[0], stack[1], stack[2]
                    route = self.read_string_view(route_ptr, route_size)
                    entry["route"] = route
                    if route:
                        self.captured_routes.append(route)
                    self.info(f"  >>> Direct CALL MakeRequest(route='{route}')")

                elif name == "QueryLuaLibrary":
                    out_ptr, name_ptr, name_size = stack[0], stack[1], stack[2]
                    name = self.read_string_view(name_ptr, name_size)
                    entry["lib_name"] = name
                    if name:
                        self.captured_lua_libs.append(name)
                    self.info(f"  >>> Direct CALL QueryLuaLibrary(name='{name}')")

                elif name == "GetSerial":
                    out_ptr, json_ptr = stack[0], stack[1]
                    json_str = self.read_std_string(json_ptr) if json_ptr else None
                    entry["json"] = json_str
                    self.info(f"  >>> Direct CALL GetSerial(json='{json_str}')")

            except Exception as e:
                entry["error"] = str(e)

            self.vmp_calls.append(entry)

    def _handle_indirect_call(self, uc, address, code):
        """Handle an indirect CALL instruction - detect vtable dispatch."""
        try:
            # Use capstone to decode if available, otherwise do basic decoding
            if self.cs:
                insns = list(self.cs.disasm(code, address, count=1))
                if not insns:
                    return
                insn = insns[0]
                # We want: call dword ptr [reg + offset]
                # This is how vtable calls look: call [eax+0x10]
                op_str = insn.op_str
                if "ptr" in op_str and insn.mnemonic == "call":
                    # Try to evaluate the target
                    for op in insn.operands:
                        if op.type == 3:  # CS_OP_MEM
                            base_reg = op.mem.base
                            disp = op.mem.disp
                            # Read the base register value
                            reg_map = {19: UC_X86_REG_EAX, 21: UC_X86_REG_ECX,
                                       22: UC_X86_REG_EDX, 20: UC_X86_REG_EBX,
                                       30: UC_X86_REG_ESI, 23: UC_X86_REG_EDI}
                            if base_reg in reg_map:
                                base_val = uc.reg_read(reg_map[base_reg])
                                target_addr = base_val + disp
                                target = struct.unpack("<I", bytes(uc.mem_read(target_addr, 4)))[0]

                                # Check if target is one of our fake stubs
                                if FAKE_STUBS_ADDR <= target < FAKE_STUBS_ADDR + 0x1000:
                                    slot = (target - FAKE_STUBS_ADDR) // 0x20
                                    self.info(f"  === Indirect vtable call: {op_str} -> slot {slot} ({VTABLE_SLOTS.get(slot, '?')}) from 0x{address:08X}")

                                # Check if target is a known VMP function
                                if target in VMP_FUNCTIONS:
                                    self.info(f"  === Indirect call to VMP: {VMP_FUNCTIONS[target]} from 0x{address:08X}")
                                    self._handle_direct_call(uc, address, target)

                                # Log all indirect calls to interesting ranges
                                entry = {
                                    "from": f"0x{address:08X}",
                                    "target_ptr": f"0x{target_addr:08X}",
                                    "target": f"0x{target:08X}",
                                    "op_str": op_str,
                                    "function": self.current_function,
                                }
                                if target in VMP_FUNCTIONS:
                                    entry["name"] = VMP_FUNCTIONS[target]
                                elif target in KNOWN_FUNCTIONS:
                                    entry["name"] = KNOWN_FUNCTIONS[target]
                                elif FAKE_STUBS_ADDR <= target < FAKE_STUBS_ADDR + 0x1000:
                                    slot = (target - FAKE_STUBS_ADDR) // 0x20
                                    entry["name"] = f"fake_vtable_slot_{slot}_{VTABLE_SLOTS.get(slot, '?')}"

                                self.indirect_calls.append(entry)
        except Exception:
            pass

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        """Hook memory accesses to known data addresses."""
        for data_addr, data_name in DATA_ADDRS.items():
            if data_addr <= address < data_addr + 64:
                entry = {
                    "address": f"0x{address:08X}",
                    "name": data_name,
                    "type": "read" if access in (UC_MEM_READ,) else "write",
                    "size": size,
                    "function": self.current_function,
                }
                if access not in (UC_MEM_READ,):
                    entry["value"] = f"0x{value:08X}" if size == 4 else f"0x{value:X}"
                self.mem_accesses.append(entry)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Map unmapped memory pages on demand."""
        page = address & ~0xFFF
        try:
            uc.mem_map(page, 0x1000, UC_PROT_ALL)
            return True
        except Exception:
            return False

    # ========================================================================
    # Emulation
    # ========================================================================

    def emulate_function(self, addr, name, max_insn=None, setup=None):
        """Emulate a single function with full tracing."""
        if max_insn is None:
            max_insn = self.max_instructions

        print(f"\n[>] Emulating {name} at 0x{addr:08X}")
        self.current_function = name
        self.instruction_count = 0
        old_max = self.max_instructions
        self.max_instructions = max_insn

        result = {
            "address": f"0x{addr:08X}",
            "name": name,
            "status": "unknown",
            "instructions": 0,
            "vtable_calls": [],
            "vmp_calls": [],
        }

        try:
            # Reset stack
            esp = STACK_ADDR + STACK_SIZE - 0x2000
            self.uc.reg_write(UC_X86_REG_ESP, esp)
            self.uc.reg_write(UC_X86_REG_EBP, esp)
            self.uc.reg_write(UC_X86_REG_EAX, 0)
            self.uc.reg_write(UC_X86_REG_EBX, 0)
            self.uc.reg_write(UC_X86_REG_ECX, 0)
            self.uc.reg_write(UC_X86_REG_EDX, 0)
            self.uc.reg_write(UC_X86_REG_ESI, 0)
            self.uc.reg_write(UC_X86_REG_EDI, 0)

            # Push return address (points to RET sled)
            ret_addr = API_STUB_ADDR + 0x100
            esp -= 4
            self.uc.mem_write(esp, struct.pack("<I", ret_addr))
            self.uc.reg_write(UC_X86_REG_ESP, esp)

            # Custom setup
            if setup:
                setup(self.uc, esp)

            # Track vtable/vmp calls for this function
            pre_vt = len(self.vtable_calls)
            pre_vmp = len(self.vmp_calls)

            # Add hooks
            h_code = self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
            h_intr = self.uc.hook_add(UC_HOOK_INTR, self.hook_interrupt)
            h_mem = self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.hook_mem_access)
            h_inv = self.uc.hook_add(
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                self.hook_mem_invalid,
            )

            try:
                self.uc.emu_start(addr, ret_addr, timeout=60 * UC_SECOND_SCALE, count=max_insn)
                result["status"] = "completed"
            except UcError as e:
                eip = self.uc.reg_read(UC_X86_REG_EIP)
                result["status"] = f"stopped: {e}"
                result["stopped_at"] = f"0x{eip:08X}"

                # Try to read what's at the stop address
                s = self.read_string(eip)
                if s:
                    result["stopped_at_string"] = s

            result["instructions"] = self.instruction_count
            result["vtable_calls"] = self.vtable_calls[pre_vt:]
            result["vmp_calls"] = self.vmp_calls[pre_vmp:]

            # Capture return value
            eax = self.uc.reg_read(UC_X86_REG_EAX)
            result["return_eax"] = f"0x{eax:08X}"
            s = self.read_string(eax)
            if s and len(s) > 2:
                result["return_string"] = s

            # Clean up hooks
            self.uc.hook_del(h_code)
            self.uc.hook_del(h_intr)
            self.uc.hook_del(h_mem)
            self.uc.hook_del(h_inv)

        except Exception as e:
            result["status"] = f"error: {e}"
            result["traceback"] = traceback.format_exc()
            self.errors.append({"function": name, "error": str(e)})

        self.max_instructions = old_max
        self.function_results[name] = result

        print(f"    Status: {result['status']}")
        print(f"    Instructions: {result['instructions']}")
        if result['vtable_calls']:
            print(f"    Vtable calls: {len(result['vtable_calls'])}")
        if result['vmp_calls']:
            print(f"    VMP calls: {len(result['vmp_calls'])}")

        return result

    def find_function_start(self, address):
        """Scan backwards for function prologue (push ebp; mov ebp, esp)."""
        offset = address - BASE_ADDR
        if offset < 0 or offset >= self.binary_size:
            return None
        for i in range(min(offset, 8192)):
            pos = offset - i
            if pos < 2:
                break
            b = self.binary_data
            if b[pos] == 0x55:  # push ebp
                if pos + 2 < self.binary_size:
                    if (b[pos+1] == 0x8B and b[pos+2] == 0xEC) or \
                       (b[pos+1] == 0x89 and b[pos+2] == 0xE5):
                        return BASE_ADDR + pos
        return None

    def _emulate_callers_targeted(self):
        """Emulate each known caller with function-specific setup."""

        # FUN_415e96c0: Crash/error reporter that builds query params
        # It reads [ebp+8] -> ptr, dereferences to get an object, reads field +0xc
        # and compares with global at 0x425088ec. If equal, jumps to end.
        # We need: a valid input object, and the global set to a DIFFERENT value.
        def setup_415e96c0(uc, esp):
            # Create a fake input object
            # arg1 = pointer to a pointer to an object
            obj_inner = HEAP_ADDR + 0x80000  # inner object
            obj_outer = HEAP_ADDR + 0x80100  # outer pointer
            # Inner object: field at +0x0 and +0xc matter
            inner_data = bytearray(0x40)
            struct.pack_into("<I", inner_data, 0x00, 0xAABBCCDD)  # [obj+0] = some value
            struct.pack_into("<I", inner_data, 0x0C, 0x12345678)  # [obj+0xc] = version/counter
            uc.mem_write(obj_inner, bytes(inner_data))
            # Outer pointer: points to inner object
            uc.mem_write(obj_outer, struct.pack("<I", obj_inner))
            # Push arg1 (at esp+4, after return address)
            uc.mem_write(esp + 4, struct.pack("<I", obj_outer))
            # Set the global cache to a DIFFERENT value so the function proceeds
            uc.mem_write(0x425088EC, struct.pack("<I", 0x00000000))
            # Provide output string buffer as arg2
            uc.mem_write(esp + 8, struct.pack("<I", FAKE_STRING_BUF))

        self.emulate_function(0x415E96C0, "FUN_415e96c0", max_insn=500000, setup=setup_415e96c0)

        # FUN_413c75c0: Anti-tamper check using PEB fields
        # Reads PEB offsets 0xa8, 0xa4, 0xb8, 0xbc, 0x64 and sums them
        # Then compares against a computed constant.
        # We need to either: populate PEB correctly, or patch the cmp/je to NOP.
        # Strategy: Patch the conditional jump at 0x413C765A to force the "proceed" path
        def setup_413c75c0(uc, esp):
            uc.reg_write(UC_X86_REG_ECX, FAKE_REQUESTOR_ADDR)
            uc.mem_write(esp + 4, struct.pack("<I", FAKE_STRING_BUF))
            uc.mem_write(esp + 8, struct.pack("<I", FAKE_STRING_BUF + 0x40))
            # Patch the anti-tamper je at 0x413C765A to JMP (always taken)
            # je = 0x0F 0x84 rel32 (6 bytes). Patch to jmp = 0xE9 rel32 + NOP (6 bytes)
            # Actually: je 0x413c7685 from 0x413C765A
            # The offset is 0x413c7685 - 0x413C7660 = 0x25 (accounting for instruction length)
            # Let's just NOP the je to fall through instead
            offset = 0x413C765A - BASE_ADDR
            insn = self.binary_data[offset:offset+6]
            if insn[0] == 0x0F and insn[1] == 0x84:
                # Patch je to NOP (6 bytes)
                uc.mem_write(0x413C765A, b"\x90\x90\x90\x90\x90\x90")
                self.info("Patched anti-tamper je at 0x413C765A")
            elif insn[0] == 0x74:
                # short je (2 bytes)
                uc.mem_write(0x413C765A, b"\x90\x90")
                self.info("Patched anti-tamper short je at 0x413C765A")

        self.emulate_function(0x413C75C0, "FUN_413c75c0", max_insn=500000, setup=setup_413c75c0)

        # FUN_41616c00: JSON parser - expects JSON string as first arg
        # Checks: byte [edx] == '{' (0x7b) and byte [edx+1] == '"' (0x22)
        # edx = [ebp+8] = first argument
        def setup_41616c00(uc, esp):
            # Write a JSON string in memory
            json_str = b'{"params":{"hash":"test","hash2":"test"},"type":4}\x00'
            json_addr = HEAP_ADDR + 0x81000
            uc.mem_write(json_addr, json_str)
            # arg1 = pointer to JSON string data
            uc.mem_write(esp + 4, struct.pack("<I", json_addr))
            # arg2 = length (non-zero to pass test edi,edi check)
            uc.mem_write(esp + 8, struct.pack("<I", len(json_str) - 1))
            # arg3 = flag byte (movzx eax, byte [ebp+0x10])
            uc.mem_write(esp + 12, struct.pack("<I", 1))

        self.emulate_function(0x41616C00, "FUN_41616c00", max_insn=500000, setup=setup_41616c00)

        # Emulate remaining caller functions with generic setup
        remaining = {
            0x41BFAAD0: "ws_event_loop",
            0x41BFA0B0: "ssl_tls_init",
            0x41BFAD20: "msg_dispatch_1",
            0x41BF1E70: "msg_dispatch_2",
        }
        for addr, name in remaining.items():
            offset = addr - BASE_ADDR
            if offset < 0 or offset + 3 >= self.binary_size:
                continue
            if self.binary_data[offset] != 0x55:
                self.info(f"Skipping {name} at 0x{addr:08X} - no prologue")
                continue

            def setup_generic(uc, esp, _a=addr):
                uc.reg_write(UC_X86_REG_ECX, FAKE_REQUESTOR_ADDR)
                for i in range(4):
                    uc.mem_write(esp + 4 + i * 4, struct.pack("<I", FAKE_STRING_BUF + i * 0x40))

            self.emulate_function(addr, name, max_insn=200000, setup=setup_generic)

    def _emulate_vtable_call_sites(self):
        """Directly emulate known vtable call sites with precisely set up state."""
        print("\n[*] Targeted vtable call site emulation")

        # Also re-emulate caller_0x415890C0 with much higher instruction limit
        def setup_415890c0(uc, esp):
            uc.reg_write(UC_X86_REG_ECX, FAKE_REQUESTOR_ADDR)
            # arg1 at [ebp+8] - not used before Instance call
            uc.mem_write(esp + 4, struct.pack("<I", FAKE_STRING_BUF))

        self.emulate_function(0x415890C0, "caller_0x415890C0_extended",
                              max_insn=2000000, setup=setup_415890c0)

        # Site 1: 0x4158934B - MakeRequest vtable call in caller_0x415890C0
        # Layout at the call:
        #   [esi+0x8c] = Requestor pointer
        #   route data at [esi+0x60] or lea edx,[esi+0x60]
        #   route size at [esi+0x70]
        #   call edi where edi = *(*[esi+0x8c])  (vtable[0])
        def setup_site1(uc, esp):
            # Set up ESI to point to a work area
            work = HEAP_ADDR + 0x90000
            uc.reg_write(UC_X86_REG_ESI, work)

            # [esi+0x8c] = pointer to Requestor
            uc.mem_write(work + 0x8c, struct.pack("<I", FAKE_REQUESTOR_ADDR))

            # Build a fake decrypted route at [esi+0x60] (inline SSO string)
            # The code does: cmp [esi+0x74], 0x10; jb -> lea edx,[esi+0x60]
            # So if capacity < 0x10, data is inline at esi+0x60
            test_route = b"/api/config\x00"
            uc.mem_write(work + 0x60, test_route)
            # [esi+0x70] = size
            uc.mem_write(work + 0x70, struct.pack("<I", len(test_route) - 1))
            # [esi+0x74] = capacity (< 0x10 means inline SSO)
            uc.mem_write(work + 0x74, struct.pack("<I", 0x0F))

            # [esi+0x10] = out string (SSO initialized)
            out_buf = bytearray(0x20)
            struct.pack_into("<I", out_buf, 0x10, 0)     # size=0
            struct.pack_into("<I", out_buf, 0x14, 0x0F)  # capacity=15 (SSO)
            uc.mem_write(work + 0x10, bytes(out_buf))

            # Set up exception handler chain
            uc.mem_write(work + 0xB0, struct.pack("<I", 0xFFFFFFFF))  # end of chain
            uc.mem_write(work + 0xB4, struct.pack("<I", 0x4158B760))  # handler
            uc.mem_write(work + 0xB8, struct.pack("<I", 2))           # state

        # Start from 0x4158933A (where it loads eax=route_size, edx=route_data)
        # 0x4158933A: mov eax, [esi+0x70]  ; route size
        # 0x4158933D: cmp [esi+0x74], 0x10 ; SSO check
        # 0x41589341: jb -> lea edx, [esi+0x60]  ; inline data
        # 0x4158934B: mov ecx, [esi+0x8c]  ; Requestor ptr
        # ...
        # 0x41589369: call edi             ; MakeRequest!
        self.emulate_function(0x4158933A, "vtable_site1_MakeRequest",
                              max_insn=1000, setup=setup_site1)

        # Site 2: 0x4158942F - vtable[1] (GetSerial?) call in same function
        # mov ecx, [eax+0x84]; mov eax,[ecx]; mov eax,[eax+4]; call eax
        # This calls vtable[1] on a sub-object
        def setup_site2(uc, esp):
            work = HEAP_ADDR + 0x92000
            uc.reg_write(UC_X86_REG_ESI, work)

            # [esi+0x3c] = pointer to "this" object
            this_obj = HEAP_ADDR + 0x93000
            uc.mem_write(work + 0x3c, struct.pack("<I", this_obj))

            # [this_obj + 0x84] = pointer to a sub-object (like Client)
            sub_obj = FAKE_REQUESTOR_ADDR  # Use our fake Requestor as the sub-object too
            uc.mem_write(this_obj + 0x84, struct.pack("<I", sub_obj))

            # [esi+0x40] = some data
            uc.mem_write(work + 0x40, struct.pack("<I", 0))

            # Exception state
            uc.mem_write(work + 0xB8, struct.pack("<I", 4))

        self.emulate_function(0x41589423, "vtable_site2_vtable1",
                              max_insn=1000, setup=setup_site2)

        # Also try to find more vtable call sites by searching for the pattern:
        # mov reg, [reg]  ; load vtable
        # call [reg+N]    ; call vtable slot
        # near g_pRequestor references
        print("\n[*] Scanning for call [reg+offset] patterns near g_pRequestor refs")
        emulated_set = set(f"0x{a:08X}" for a in CALLER_FUNCTIONS)
        emulated_set.add(f"0x{0x41BC9450:08X}")
        emulated_set.add(f"0x{0x415890C0:08X}")
        self._scan_and_emulate_vtable_patterns(emulated_set)

    def _scan_and_emulate_vtable_patterns(self, emulated_set):
        """Find call edi/eax patterns near Requestor::Instance calls and emulate them."""
        target = 0x41BC9450  # Requestor::Instance
        code_end = min(self.binary_size, 0x1300000)
        sites = []

        for i in range(code_end - 5):
            if self.binary_data[i] == 0xE8:
                rel = struct.unpack_from("<i", self.binary_data, i + 1)[0]
                dest = (BASE_ADDR + i + 5 + rel) & 0xFFFFFFFF
                if dest == target:
                    call_va = BASE_ADDR + i
                    # Search forward up to 500 bytes for "call edi" (FF D7) or "call eax" (FF D0)
                    for j in range(i + 5, min(i + 500, code_end - 1)):
                        if self.binary_data[j] == 0xFF:
                            next_byte = self.binary_data[j + 1]
                            if next_byte in (0xD0, 0xD1, 0xD2, 0xD3, 0xD6, 0xD7):
                                # call reg
                                reg_names = {0xD0: "eax", 0xD1: "ecx", 0xD2: "edx",
                                             0xD3: "ebx", 0xD6: "esi", 0xD7: "edi"}
                                vtable_call_va = BASE_ADDR + j
                                sites.append({
                                    "instance_call": f"0x{call_va:08X}",
                                    "vtable_call": f"0x{vtable_call_va:08X}",
                                    "call_reg": reg_names.get(next_byte, f"0x{next_byte:02X}"),
                                    "distance": j - i,
                                })
                                break
                            elif next_byte & 0xC0 != 0xC0:
                                # call [reg+disp] - memory indirect
                                vtable_call_va = BASE_ADDR + j
                                sites.append({
                                    "instance_call": f"0x{call_va:08X}",
                                    "vtable_call": f"0x{vtable_call_va:08X}",
                                    "call_type": "mem_indirect",
                                    "modrm": f"0x{next_byte:02X}",
                                    "distance": j - i,
                                })
                                break

        print(f"    Found {len(sites)} Requestor::Instance → vtable call patterns")
        for s in sites:
            print(f"      Instance@{s['instance_call']} → vtable@{s['vtable_call']} "
                  f"({s.get('call_reg', s.get('call_type', '?'))}, +{s['distance']} bytes)")

        self.function_results["vtable_call_patterns"] = sites

        # Emulate each discovered pattern
        for idx, site in enumerate(sites):
            instance_va = int(site["instance_call"], 16)
            func_start = self.find_function_start(instance_va)
            if not func_start:
                continue

            # Skip if already emulated as a known caller
            if func_start in CALLER_FUNCTIONS or f"0x{func_start:08X}" in emulated_set:
                continue
            emulated_set.add(f"0x{func_start:08X}")

            def setup_pattern(uc, esp, _fs=func_start):
                uc.reg_write(UC_X86_REG_ECX, FAKE_REQUESTOR_ADDR)
                uc.mem_write(esp + 4, struct.pack("<I", FAKE_STRING_BUF))
                uc.mem_write(esp + 8, struct.pack("<I", FAKE_STRING_BUF + 0x40))
                uc.mem_write(esp + 12, struct.pack("<I", FAKE_STRING_BUF + 0x80))
                uc.mem_write(esp + 16, struct.pack("<I", 0))

            self.emulate_function(func_start, f"pattern_{idx}_0x{func_start:08X}",
                                  max_insn=500000, setup=setup_pattern)

    def scan_for_vtable_callers(self):
        """Scan binary code for patterns that load g_pRequestor and call through vtable."""
        print("\n[*] Scanning binary for Requestor vtable call patterns")

        g_pReq = 0x42518C58
        g_pReq_bytes = struct.pack("<I", g_pReq)

        # Pattern: mov reg, [g_pRequestor]; mov reg2, [reg]; call [reg2+offset]
        # Or: push arg; push arg; mov ecx, [g_pRequestor]; mov eax, [ecx]; call [eax+offset]
        callers = []
        code_end = min(self.binary_size, 0x1300000)  # Don't scan encrypted region

        for i in range(code_end - 10):
            # Look for references to g_pRequestor address
            if self.binary_data[i:i+4] == g_pReq_bytes:
                va = BASE_ADDR + i
                # Check instruction context
                # mov reg, [imm32] is: 8B 0D/15/1D/25/2D/35/3D [imm32]
                # or: A1 [imm32] (mov eax, [imm32])
                if i > 0:
                    prev = self.binary_data[i-2:i]
                    if prev[0] == 0x8B and prev[1] in (0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
                        # mov reg, [g_pRequestor]
                        func_start = self.find_function_start(va - 2)
                        callers.append({
                            "ref_va": f"0x{va:08X}",
                            "insn_va": f"0x{va-2:08X}",
                            "func_start": f"0x{func_start:08X}" if func_start else None,
                            "type": "mov_reg_[g_pRequestor]",
                        })
                    elif i > 0 and self.binary_data[i-1] == 0xA1:
                        # mov eax, [g_pRequestor]
                        func_start = self.find_function_start(va - 1)
                        callers.append({
                            "ref_va": f"0x{va:08X}",
                            "insn_va": f"0x{va-1:08X}",
                            "func_start": f"0x{func_start:08X}" if func_start else None,
                            "type": "mov_eax_[g_pRequestor]",
                        })

        print(f"    Found {len(callers)} references to g_pRequestor in code")

        # Deduplicate by function start
        seen_funcs = set()
        unique_callers = []
        for c in callers:
            fs = c["func_start"]
            if fs and fs not in seen_funcs:
                seen_funcs.add(fs)
                unique_callers.append(c)

        print(f"    Unique caller functions: {len(unique_callers)}")
        return unique_callers

    def scan_requestor_instance_callers(self):
        """Find all CALL instructions targeting Requestor::Instance (0x41BC9450)."""
        print("\n[*] Scanning for CALL Requestor::Instance")
        target = 0x41BC9450
        callers = []
        code_end = min(self.binary_size, 0x1300000)

        for i in range(code_end - 5):
            if self.binary_data[i] == 0xE8:  # CALL rel32
                rel = struct.unpack_from("<i", self.binary_data, i + 1)[0]
                dest = (BASE_ADDR + i + 5 + rel) & 0xFFFFFFFF
                if dest == target:
                    call_va = BASE_ADDR + i
                    func_start = self.find_function_start(call_va)
                    callers.append({
                        "call_va": f"0x{call_va:08X}",
                        "func_start": f"0x{func_start:08X}" if func_start else None,
                    })

        print(f"    Found {len(callers)} CALL Requestor::Instance sites")
        return callers

    def run(self):
        """Main execution."""
        t0 = time.time()
        self.load_binary()
        self.setup_capstone()
        self.setup_unicorn()
        self.setup_fake_requestor()
        self.setup_fake_client()

        # ---- Phase 1: Scan for all callers ----
        vtable_callers = self.scan_for_vtable_callers()
        instance_callers = self.scan_requestor_instance_callers()

        # ---- Phase 2: Emulate Requestor::Instance ----
        self.emulate_function(0x41BC9450, "Requestor_Instance", max_insn=5000)

        # ---- Phase 3: Emulate known non-VMP'd caller functions with targeted setups ----
        self._emulate_callers_targeted()

        # ---- Phase 3.5: Targeted vtable call site emulation ----
        # We found that caller_0x415890C0 calls MakeRequest at 0x41589369
        # via: mov ecx,[esi+0x8c]; mov edi,[ecx]; mov edi,[edi]; ... call edi
        # But it also has a second vtable call at 0x4158943F: call eax (vtable[1])
        # Let's emulate from just before the vtable dispatch with state set up
        self._emulate_vtable_call_sites()

        # ---- Phase 4: Emulate newly discovered callers from scan ----
        emulated = set(f"0x{a:08X}" for a in CALLER_FUNCTIONS)
        emulated.add(f"0x{0x41BC9450:08X}")

        all_caller_starts = set()
        for c in vtable_callers:
            if c["func_start"] and c["func_start"] not in emulated:
                all_caller_starts.add(c["func_start"])
        for c in instance_callers:
            if c["func_start"] and c["func_start"] not in emulated:
                all_caller_starts.add(c["func_start"])

        print(f"\n[*] Emulating {len(all_caller_starts)} newly discovered caller functions")
        for func_start_str in sorted(all_caller_starts):
            func_start = int(func_start_str, 16)
            name = f"caller_0x{func_start:08X}"

            def setup_discovered(uc, esp, _fs=func_start):
                uc.reg_write(UC_X86_REG_ECX, FAKE_REQUESTOR_ADDR)
                for i in range(4):
                    uc.mem_write(esp + 4 + i * 4, struct.pack("<I", FAKE_STRING_BUF + i * 0x40))

            self.emulate_function(func_start, name, max_insn=100000, setup=setup_discovered)

        # ---- Phase 5: Emulate non-VMP'd known functions ----
        for addr, name in KNOWN_FUNCTIONS.items():
            if name == "Requestor_Instance":
                continue
            self.emulate_function(addr, name, max_insn=50000)

        # ---- Compile results ----
        elapsed = time.time() - t0
        results = {
            "metadata": {
                "binary": BINARY_PATH,
                "binary_size": self.binary_size,
                "elapsed_seconds": round(elapsed, 1),
                "total_instructions": sum(r.get("instructions", 0) for r in self.function_results.values() if isinstance(r, dict)),
            },
            "captured_routes": self.captured_routes,
            "captured_lua_libs": self.captured_lua_libs,
            "captured_serials": self.captured_serials,
            "vtable_calls": self.vtable_calls,
            "vmp_direct_calls": self.vmp_calls,
            "function_results": self.function_results,
            "vtable_callers_scan": vtable_callers[:50],
            "instance_callers_scan": instance_callers[:50],
            "indirect_calls": self.indirect_calls[:200],
            "memory_accesses": self.mem_accesses[:500],
            "errors": self.errors,
        }

        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w") as f:
            json.dump(results, f, indent=2, default=str)

        # ---- Summary ----
        print(f"\n{'='*60}")
        print(f"EMULATION COMPLETE ({elapsed:.1f}s)")
        print(f"{'='*60}")
        print(f"Functions emulated:     {len(self.function_results)}")
        print(f"Total instructions:     {results['metadata']['total_instructions']:,}")
        print(f"Vtable calls captured:  {len(self.vtable_calls)}")
        print(f"VMP direct calls:       {len(self.vmp_calls)}")
        print(f"Memory accesses logged: {len(self.mem_accesses)}")

        if self.captured_routes:
            print(f"\n*** CAPTURED ROUTES ({len(self.captured_routes)}):")
            for r in self.captured_routes:
                print(f"    {r}")

        if self.captured_lua_libs:
            print(f"\n*** CAPTURED LUA LIBRARIES ({len(self.captured_lua_libs)}):")
            for l in self.captured_lua_libs:
                print(f"    {l}")

        if self.vtable_calls:
            print(f"\n*** VTABLE CALLS:")
            for vc in self.vtable_calls:
                args_str = json.dumps(vc.get("args", {}), indent=None)
                print(f"    [{vc['name']}] from {vc['caller_function']}: {args_str}")

        if self.vmp_calls:
            print(f"\n*** VMP DIRECT CALLS:")
            for vc in self.vmp_calls:
                print(f"    [{vc['name']}] from 0x{vc['from']} ({vc.get('route', vc.get('lib_name', 'N/A'))})")

        print(f"\nResults saved to {OUTPUT_PATH}")


if __name__ == "__main__":
    emu = NLEmulator()
    emu.run()
