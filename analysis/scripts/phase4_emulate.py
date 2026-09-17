#!/usr/bin/env python3
"""
Phase 4A: Unicorn Emulation of Key Functions
Loads the binary into Unicorn at base 0x412A0000 and emulates
non-VMProtect'd functions to trace execution paths dynamically.
"""

import json
import os
import struct
import sys
import traceback

try:
    from unicorn import *
    from unicorn.x86_const import *
except ImportError:
    print("[Phase 4A] ERROR: unicorn not available, skipping emulation")
    # Write empty results
    os.makedirs("/tmp/nl_analysis/output", exist_ok=True)
    with open("/tmp/nl_analysis/output/phase4_emulation.json", "w") as f:
        json.dump({"error": "unicorn not available"}, f)
    sys.exit(0)

BINARY_PATH = "/tmp/nl_analysis/nl.bin"
OUTPUT_PATH = "/tmp/nl_analysis/output/phase4_emulation.json"
BASE_ADDR = 0x412A0000
STACK_ADDR = 0x70000000
STACK_SIZE = 0x100000  # 1MB stack
TEB_ADDR = 0x7FFE0000
PEB_ADDR = 0x7FFD0000
HEAP_ADDR = 0x10000000
HEAP_SIZE = 0x100000

# Known function addresses
FUNCTIONS = {
    0x41BC9450: "Requestor_Instance",
    0x41C16EA0: "ws_client_send_wrap",
    0x412A0A00: "entry_point",
    0x4200A118: "error_handler",
    0x41EBB510: "SHA256_transform",
    0x41DA0BA0: "mem_dispatcher",
}

# VMProtect'd functions - we can't emulate these
VMP_FUNCTIONS = {
    0x41BC78E0: "GetSerial",
    0x41BC98E0: "MakeRequest",
    0x41BC9670: "QueryLuaLibrary",
}

# Known data addresses
DATA_ADDRS = {
    0x42518C58: "g_pRequestor",
    0x41BF8341: "auth_token_ptr",
    0x42518C44: "g_hConsole",
}

# Common Windows API addresses we'll stub
WINDOWS_APIS = {
    0x77000000: "kernel32.GetModuleHandleA",
    0x77000010: "kernel32.GetProcAddress",
    0x77000020: "kernel32.VirtualAlloc",
    0x77000030: "kernel32.VirtualProtect",
    0x77000040: "kernel32.LoadLibraryA",
    0x77000050: "kernel32.GetLastError",
    0x77000060: "kernel32.CreateThread",
    0x77000070: "kernel32.EnterCriticalSection",
    0x77000080: "kernel32.LeaveCriticalSection",
    0x77000090: "kernel32.InitializeCriticalSection",
    0x770000A0: "kernel32.OutputDebugStringA",
    0x770000B0: "kernel32.GetTickCount",
    0x770000C0: "kernel32.Sleep",
    0x770000D0: "kernel32.HeapAlloc",
    0x770000E0: "kernel32.HeapFree",
    0x770000F0: "ws2_32.WSAStartup",
    0x77000100: "ws2_32.socket",
    0x77000110: "ws2_32.connect",
    0x77000120: "ws2_32.send",
    0x77000130: "ws2_32.recv",
    0x77000140: "ws2_32.closesocket",
}


class EmulationTracer:
    def __init__(self):
        self.results = {
            "function_traces": {},
            "memory_accesses": [],
            "external_calls": [],
            "string_refs": [],
            "data_accesses": {},
            "errors": [],
        }
        self.current_function = None
        self.instruction_count = 0
        self.max_instructions = 50000  # Safety limit per function
        self.binary_data = None
        self.binary_size = 0
        self.heap_ptr = HEAP_ADDR + 0x1000

    def load_binary(self):
        print("[Phase 4A] Loading binary...")
        with open(BINARY_PATH, "rb") as f:
            self.binary_data = f.read()
        self.binary_size = len(self.binary_data)
        print(f"  Binary size: {self.binary_size} bytes")

    def setup_unicorn(self):
        print("[Phase 4A] Setting up Unicorn emulator...")
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)

        # Map binary
        # Round up to page boundary
        binary_pages = ((self.binary_size + 0xFFF) // 0x1000) * 0x1000
        self.uc.mem_map(BASE_ADDR, binary_pages, UC_PROT_ALL)
        self.uc.mem_write(BASE_ADDR, self.binary_data)
        print(f"  Mapped binary: 0x{BASE_ADDR:08X} - 0x{BASE_ADDR + binary_pages:08X}")

        # Map stack
        self.uc.mem_map(STACK_ADDR, STACK_SIZE, UC_PROT_ALL)
        esp = STACK_ADDR + STACK_SIZE - 0x1000
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp)
        print(f"  Stack: 0x{STACK_ADDR:08X}, ESP=0x{esp:08X}")

        # Map TEB/PEB in a single 4-page region
        self.uc.mem_map(0x7FFC0000, 0x40000, UC_PROT_ALL)
        # Setup minimal TEB at 0x7FFE0000
        teb_data = bytearray(0x1000)
        # TEB.Self = TEB_ADDR
        struct.pack_into("<I", teb_data, 0x18, TEB_ADDR)
        # TEB.ProcessEnvironmentBlock = PEB_ADDR
        struct.pack_into("<I", teb_data, 0x30, PEB_ADDR)
        # TEB.ThreadId
        struct.pack_into("<I", teb_data, 0x24, 1)
        # TEB.ThreadLocalStoragePointer at offset 0x2C
        struct.pack_into("<I", teb_data, 0x2C, 0x7FFC1000)
        self.uc.mem_write(TEB_ADDR, bytes(teb_data))

        # Setup minimal PEB at 0x7FFD0000
        peb_data = bytearray(0x1000)
        # PEB.ImageBaseAddress
        struct.pack_into("<I", peb_data, 0x08, BASE_ADDR)
        self.uc.mem_write(PEB_ADDR, bytes(peb_data))
        print(f"  TEB: 0x{TEB_ADDR:08X}, PEB: 0x{PEB_ADDR:08X}")

        # Set up GDT for FS segment to point to TEB (Windows x86 convention)
        # We use a minimal GDT approach
        # For simplicity, use MSR-based FS base (not supported in 32-bit)
        # Instead, we rely on the hook_mem_invalid handler and direct memory access
        # Set FS register value - Unicorn in 32-bit mode uses segment selectors
        # We'll set up a GDT entry for FS
        GDT_ADDR = 0x7FFC0000
        GDT_LIMIT = 0x1000
        # Create GDT entry for FS segment pointing to TEB
        # GDT entry format: base(32) limit(20) flags
        def create_gdt_entry(base, limit, access, flags):
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

        gdt = bytearray(0x100)
        # Null entry (index 0)
        # CS entry (index 1, selector 0x08)
        gdt[0x08:0x10] = create_gdt_entry(0, 0xFFFFF, 0x9B, 0x0C)  # 32-bit code
        # DS entry (index 2, selector 0x10)
        gdt[0x10:0x18] = create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C)  # 32-bit data
        # SS entry (index 3, selector 0x18)
        gdt[0x18:0x20] = create_gdt_entry(0, 0xFFFFF, 0x93, 0x0C)  # 32-bit stack
        # FS entry (index 4, selector 0x23)  pointing to TEB
        gdt[0x20:0x28] = create_gdt_entry(TEB_ADDR, 0xFFF, 0xF3, 0x0C)
        self.uc.mem_write(GDT_ADDR, bytes(gdt))

        # Set GDTR
        self.uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, 0x100, 0))
        # Set segment registers
        self.uc.reg_write(UC_X86_REG_CS, 0x08)
        self.uc.reg_write(UC_X86_REG_DS, 0x10)
        self.uc.reg_write(UC_X86_REG_ES, 0x10)
        self.uc.reg_write(UC_X86_REG_SS, 0x18)
        self.uc.reg_write(UC_X86_REG_FS, 0x23)
        self.uc.reg_write(UC_X86_REG_GS, 0x10)

        # Map heap
        self.uc.mem_map(HEAP_ADDR, HEAP_SIZE, UC_PROT_ALL)
        print(f"  Heap: 0x{HEAP_ADDR:08X}")

        # Map Windows API stub region
        self.uc.mem_map(0x77000000, 0x10000, UC_PROT_ALL)
        # Fill with RET instructions
        ret_sled = b"\xC3" * 0x10000
        self.uc.mem_write(0x77000000, ret_sled)
        print("  Windows API stubs mapped at 0x77000000")

    def hook_code(self, uc, address, size, user_data):
        """Hook every instruction execution."""
        self.instruction_count += 1
        if self.instruction_count >= self.max_instructions:
            uc.emu_stop()
            return

        # Check if this is a call to an external address
        if size >= 5:
            try:
                code = uc.mem_read(address, size)
                if code[0] == 0xE8:  # CALL rel32
                    rel = struct.unpack("<i", bytes(code[1:5]))[0]
                    target = (address + 5 + rel) & 0xFFFFFFFF
                    self._handle_call(uc, address, target)
                elif code[0] == 0xFF:  # indirect call
                    pass  # Complex to decode, skip for now
            except Exception:
                pass

    def _handle_call(self, uc, call_addr, target):
        """Handle a call instruction."""
        # Check if calling a VMProtect'd function
        if target in VMP_FUNCTIONS:
            name = VMP_FUNCTIONS[target]
            self.results["external_calls"].append({
                "from": f"0x{call_addr:08X}",
                "to": f"0x{target:08X}",
                "name": name,
                "type": "vmp_function",
                "context": self._get_register_state(uc),
            })
            # Return a stub value
            uc.reg_write(UC_X86_REG_EAX, 1)

        # Check if calling a Windows API
        elif target in WINDOWS_APIS:
            name = WINDOWS_APIS[target]
            self.results["external_calls"].append({
                "from": f"0x{call_addr:08X}",
                "to": f"0x{target:08X}",
                "name": name,
                "type": "windows_api",
            })
            self._handle_api_stub(uc, name)

        # Check if calling outside the binary
        elif target < BASE_ADDR or target >= BASE_ADDR + self.binary_size:
            self.results["external_calls"].append({
                "from": f"0x{call_addr:08X}",
                "to": f"0x{target:08X}",
                "type": "external_unknown",
            })

    def _handle_api_stub(self, uc, name):
        """Return appropriate stub values for Windows APIs."""
        if "Alloc" in name:
            # Return a heap pointer
            ptr = self.heap_ptr
            self.heap_ptr += 0x1000
            uc.reg_write(UC_X86_REG_EAX, ptr)
        elif "GetModuleHandle" in name:
            uc.reg_write(UC_X86_REG_EAX, BASE_ADDR)
        elif "GetLastError" in name:
            uc.reg_write(UC_X86_REG_EAX, 0)
        elif "GetTickCount" in name:
            uc.reg_write(UC_X86_REG_EAX, 12345678)
        else:
            uc.reg_write(UC_X86_REG_EAX, 1)  # Generic success

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        """Hook memory reads/writes to known data addresses."""
        for data_addr, data_name in DATA_ADDRS.items():
            if data_addr <= address < data_addr + 256:
                access_type = "read" if access == UC_MEM_READ else "write"
                entry = {
                    "address": f"0x{address:08X}",
                    "data_name": data_name,
                    "type": access_type,
                    "size": size,
                    "function": self.current_function,
                }
                if access == UC_MEM_WRITE:
                    entry["value"] = f"0x{value:08X}" if size == 4 else str(value)
                self.results["memory_accesses"].append(entry)

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        """Handle invalid memory access - map the page and continue."""
        # Map the page
        page_addr = address & ~0xFFF
        try:
            uc.mem_map(page_addr, 0x1000, UC_PROT_ALL)
            return True
        except Exception:
            return False

    def _get_register_state(self, uc):
        """Get current register state."""
        return {
            "eax": f"0x{uc.reg_read(UC_X86_REG_EAX):08X}",
            "ecx": f"0x{uc.reg_read(UC_X86_REG_ECX):08X}",
            "edx": f"0x{uc.reg_read(UC_X86_REG_EDX):08X}",
            "ebx": f"0x{uc.reg_read(UC_X86_REG_EBX):08X}",
            "esp": f"0x{uc.reg_read(UC_X86_REG_ESP):08X}",
            "ebp": f"0x{uc.reg_read(UC_X86_REG_EBP):08X}",
            "esi": f"0x{uc.reg_read(UC_X86_REG_ESI):08X}",
            "edi": f"0x{uc.reg_read(UC_X86_REG_EDI):08X}",
            "eip": f"0x{uc.reg_read(UC_X86_REG_EIP):08X}",
        }

    def _read_string_at(self, uc, address, max_len=256):
        """Try to read a null-terminated string from memory."""
        try:
            data = bytes(uc.mem_read(address, max_len))
            null_idx = data.find(b"\x00")
            if null_idx > 0:
                s = data[:null_idx]
                try:
                    return s.decode("ascii")
                except UnicodeDecodeError:
                    return s.decode("latin-1")
        except Exception:
            pass
        return None

    def emulate_function(self, func_addr, func_name, setup_args=None):
        """Emulate a single function."""
        print(f"\n[Phase 4A] Emulating {func_name} at 0x{func_addr:08X}...")
        self.current_function = func_name
        self.instruction_count = 0

        trace = {
            "function": func_name,
            "address": f"0x{func_addr:08X}",
            "instructions_executed": 0,
            "external_calls_made": [],
            "strings_found": [],
            "status": "unknown",
        }

        try:
            # Reset stack
            esp = STACK_ADDR + STACK_SIZE - 0x1000
            self.uc.reg_write(UC_X86_REG_ESP, esp)
            self.uc.reg_write(UC_X86_REG_EBP, esp)

            # Push a return address (a RET instruction in our stub area)
            ret_addr = 0x77000000  # Points to our RET sled
            self.uc.mem_write(esp, struct.pack("<I", ret_addr))

            # Setup custom arguments if provided
            if setup_args:
                setup_args(self.uc, esp)

            # Clear external calls tracking for this function
            pre_ext_calls = len(self.results["external_calls"])

            # Add hooks
            hook_code = self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
            hook_mem = self.uc.hook_add(
                UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                self.hook_mem_access,
            )
            hook_invalid = self.uc.hook_add(
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                UC_HOOK_MEM_FETCH_UNMAPPED,
                self.hook_mem_invalid,
            )

            # Emulate
            try:
                self.uc.emu_start(func_addr, ret_addr, timeout=30 * UC_SECOND_SCALE,
                                  count=self.max_instructions)
                trace["status"] = "completed"
            except UcError as e:
                trace["status"] = f"stopped: {str(e)}"
                eip = self.uc.reg_read(UC_X86_REG_EIP)
                trace["stopped_at"] = f"0x{eip:08X}"

            trace["instructions_executed"] = self.instruction_count

            # Collect external calls made during this function
            trace["external_calls_made"] = self.results["external_calls"][pre_ext_calls:]

            # Check return value
            eax = self.uc.reg_read(UC_X86_REG_EAX)
            trace["return_value"] = f"0x{eax:08X}"

            # Try to read return value as string pointer
            ret_str = self._read_string_at(self.uc, eax)
            if ret_str and len(ret_str) > 3:
                trace["return_string"] = ret_str

            # Remove hooks
            self.uc.hook_del(hook_code)
            self.uc.hook_del(hook_mem)
            self.uc.hook_del(hook_invalid)

        except Exception as e:
            trace["status"] = f"error: {str(e)}"
            trace["traceback"] = traceback.format_exc()

        self.results["function_traces"][func_name] = trace
        print(f"  Status: {trace['status']}")
        print(f"  Instructions: {trace['instructions_executed']}")
        print(f"  Return: {trace.get('return_value', 'N/A')}")

    def scan_string_references(self):
        """Scan the binary for interesting string references in code."""
        print("\n[Phase 4A] Scanning for string references in code...")

        # Read Phase 1 results for string locations
        try:
            with open("/tmp/nl_analysis/output/phase1_results.json", "r") as f:
                phase1 = json.load(f)
        except Exception:
            print("  Phase 1 results not available, skipping string ref scan")
            return

        # Get interesting strings with code refs
        string_refs = phase1.get("string_code_refs", {})
        route_strings = []
        for s, info in string_refs.items():
            if any(cat in info.get("categories", []) for cat in
                   ["http_route", "api_endpoint", "url", "websocket_related"]):
                route_strings.append({
                    "string": s,
                    "va": info["string_va"],
                    "code_refs": info["code_refs"][:5],
                })

        self.results["string_refs"] = route_strings
        print(f"  Found {len(route_strings)} route/URL string references")

    def emulate_callers_of_key_functions(self):
        """Try to emulate functions that call key VMProtect'd functions."""
        print("\n[Phase 4A] Looking for callers of VMProtect'd functions...")

        # Read Phase 1 results for VMP call sites
        try:
            with open("/tmp/nl_analysis/output/phase1_results.json", "r") as f:
                phase1 = json.load(f)
        except Exception:
            print("  Phase 1 results not available, skipping caller emulation")
            return

        vmp_sites = phase1.get("vmp_call_sites", {})
        for func_name, sites in vmp_sites.items():
            print(f"\n  Callers of {func_name}: {len(sites)} sites")
            for i, site in enumerate(sites[:5]):  # Limit to 5 per function
                call_va = int(site["call_site_va"], 16)
                # Try to find the function start by scanning backwards for prologue
                func_start = self._find_function_start(call_va)
                if func_start:
                    self.emulate_function(
                        func_start,
                        f"caller_of_{func_name}_{i}_at_0x{func_start:08X}",
                    )

    def _find_function_start(self, address):
        """Find function start by scanning backwards for prologue."""
        offset = address - BASE_ADDR
        # Scan backwards up to 4KB
        for i in range(min(offset, 4096)):
            pos = offset - i
            if pos < 2:
                break
            # Check for push ebp; mov ebp, esp
            if (self.binary_data[pos] == 0x55 and
                ((self.binary_data[pos + 1] == 0x89 and self.binary_data[pos + 2] == 0xE5) or
                 (self.binary_data[pos + 1] == 0x8B and self.binary_data[pos + 2] == 0xEC))):
                return BASE_ADDR + pos
        return None

    def run(self):
        """Run all emulation tasks."""
        self.load_binary()
        self.setup_unicorn()

        # Emulate non-VMP functions
        for addr, name in FUNCTIONS.items():
            self.emulate_function(addr, name)

        # Scan string references
        self.scan_string_references()

        # Try to emulate callers of VMP'd functions
        self.emulate_callers_of_key_functions()

        # Save results
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"\n[Phase 4A] Results saved to {OUTPUT_PATH}")
        print("[Phase 4A] Complete.")


if __name__ == "__main__":
    tracer = EmulationTracer()
    tracer.run()
