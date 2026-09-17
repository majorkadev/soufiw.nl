// Ghidra post-analysis script for nl.bin
// Analyzes callers of key networking functions, decompiles them,
// and extracts protocol information.
// @category Analysis
// @author nl_analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.*;

public class nl_analysis extends GhidraScript {

    private static final String OUTPUT_FILE = "/tmp/nl_analysis/output/ghidra_results.txt";

    // Known function addresses
    private static final long BASE_ADDR = 0x412A0000L;
    private static final long[][] KNOWN_FUNCTIONS = {
        {0x41BC78E0L, 1}, // GetSerial (VMP)
        {0x41BC98E0L, 1}, // MakeRequest (VMP)
        {0x41BC9670L, 1}, // QueryLuaLibrary (VMP)
        {0x41BC9450L, 0}, // Requestor::Instance
        {0x41C16EA0L, 0}, // ws_client_send_wrap
        {0x412A0A00L, 0}, // entry_point
        {0x4200A118L, 0}, // error_handler
        {0x41EBB510L, 0}, // SHA256_transform
        {0x41DA0BA0L, 0}, // mem_dispatcher
    };
    private static final String[] KNOWN_FUNCTION_NAMES = {
        "GetSerial", "MakeRequest", "QueryLuaLibrary",
        "Requestor_Instance", "ws_client_send_wrap", "entry_point",
        "error_handler", "SHA256_transform", "mem_dispatcher"
    };

    // Known data addresses
    private static final long[] KNOWN_DATA = {
        0x42518C58L, // g_pRequestor
        0x41BF8341L, // auth_token_ptr
        0x42518C44L, // g_hConsole
    };
    private static final String[] KNOWN_DATA_NAMES = {
        "g_pRequestor", "auth_token_ptr", "g_hConsole"
    };

    // Encrypted region to mark as data
    private static final long ENCRYPTED_START = 0x425A0000L;
    private static final long ENCRYPTED_END = 0x4369FFFFL;

    private PrintWriter out;
    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        File outFile = new File(OUTPUT_FILE);
        outFile.getParentFile().mkdirs();
        out = new PrintWriter(new BufferedWriter(new FileWriter(outFile)));

        out.println("==========================================================");
        out.println("Ghidra Headless Analysis Results for nl.bin");
        out.println("==========================================================");
        out.println("Date: " + new Date());
        out.println();

        try {
            // Step 1: Label known addresses
            labelKnownAddresses();

            // Step 2: Create functions at non-VMP addresses
            createFunctions();

            // Step 3: Mark encrypted region as data
            markEncryptedRegion();

            // Wait for auto-analysis to settle
            out.println("[*] Waiting for auto-analysis...");
            out.flush();

            // Step 4: Initialize decompiler
            initDecompiler();

            // Step 5: Analyze xrefs and decompile callers
            analyzeXrefs();

            // Step 6: Find and analyze string references
            findStringReferences();

            // Step 7: Look for vtable patterns
            findVtablePatterns();

            out.println("\n[*] Analysis complete.");

        } catch (Exception e) {
            out.println("[ERROR] " + e.getMessage());
            e.printStackTrace(out);
        } finally {
            if (decomp != null) {
                decomp.dispose();
            }
            out.close();
        }
    }

    private Address makeAddr(long va) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
    }

    private void labelKnownAddresses() {
        out.println("\n--- Step 1: Labeling Known Addresses ---");

        SymbolTable symTable = currentProgram.getSymbolTable();

        for (int i = 0; i < KNOWN_FUNCTIONS.length; i++) {
            long va = KNOWN_FUNCTIONS[i][0];
            String name = KNOWN_FUNCTION_NAMES[i];
            try {
                Address addr = makeAddr(va);
                symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                out.println("  Labeled 0x" + Long.toHexString(va) + " as " + name);
            } catch (Exception e) {
                out.println("  Error labeling " + name + ": " + e.getMessage());
            }
        }

        for (int i = 0; i < KNOWN_DATA.length; i++) {
            long va = KNOWN_DATA[i];
            String name = KNOWN_DATA_NAMES[i];
            try {
                Address addr = makeAddr(va);
                symTable.createLabel(addr, name, SourceType.USER_DEFINED);
                out.println("  Labeled 0x" + Long.toHexString(va) + " as " + name);
            } catch (Exception e) {
                out.println("  Error labeling " + name + ": " + e.getMessage());
            }
        }
    }

    private void createFunctions() {
        out.println("\n--- Step 2: Creating Functions at Non-VMP Addresses ---");

        FunctionManager funcMgr = currentProgram.getFunctionManager();

        for (int i = 0; i < KNOWN_FUNCTIONS.length; i++) {
            long va = KNOWN_FUNCTIONS[i][0];
            boolean isVmp = KNOWN_FUNCTIONS[i][1] == 1;
            String name = KNOWN_FUNCTION_NAMES[i];

            if (isVmp) {
                out.println("  Skipping VMP'd " + name + " at 0x" + Long.toHexString(va));
                continue;
            }

            try {
                Address addr = makeAddr(va);
                Function existing = funcMgr.getFunctionAt(addr);
                if (existing == null) {
                    createFunction(addr, name);
                    out.println("  Created function " + name + " at 0x" + Long.toHexString(va));
                } else {
                    out.println("  Function already exists at 0x" + Long.toHexString(va) + ": " + existing.getName());
                }
            } catch (Exception e) {
                out.println("  Error creating " + name + ": " + e.getMessage());
            }
        }
    }

    private void markEncryptedRegion() {
        out.println("\n--- Step 3: Marking Encrypted Region ---");
        try {
            Address start = makeAddr(ENCRYPTED_START);
            Address end = makeAddr(ENCRYPTED_END);
            long size = ENCRYPTED_END - ENCRYPTED_START;
            out.println("  Encrypted region: 0x" + Long.toHexString(ENCRYPTED_START) +
                       " - 0x" + Long.toHexString(ENCRYPTED_END) +
                       " (" + size + " bytes)");
            // We don't clear here to not disrupt existing analysis, just note it
            out.println("  (Region noted for reference - skipping disassembly there)");
        } catch (Exception e) {
            out.println("  Error: " + e.getMessage());
        }
    }

    private void initDecompiler() {
        out.println("\n--- Step 4: Initializing Decompiler ---");
        decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");

        if (!decomp.openProgram(currentProgram)) {
            out.println("  ERROR: Failed to open program in decompiler");
            return;
        }
        out.println("  Decompiler initialized successfully");
    }

    private String decompileFunction(Function func, int timeoutSecs) {
        if (decomp == null || func == null) return null;

        try {
            DecompileResults results = decomp.decompileFunction(func, timeoutSecs, monitor);
            if (results != null && results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            } else if (results != null) {
                return "// Decompilation failed: " + results.getErrorMessage();
            }
        } catch (Exception e) {
            return "// Decompilation error: " + e.getMessage();
        }
        return null;
    }

    private void analyzeXrefs() {
        out.println("\n--- Step 5: Analyzing Cross-References and Decompiling Callers ---");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        // Analyze each known function
        for (int i = 0; i < KNOWN_FUNCTIONS.length; i++) {
            long va = KNOWN_FUNCTIONS[i][0];
            String name = KNOWN_FUNCTION_NAMES[i];

            out.println("\n  === References to " + name + " (0x" + Long.toHexString(va) + ") ===");

            try {
                Address addr = makeAddr(va);
                ReferenceIterator refIter = refMgr.getReferencesTo(addr);
                List<Reference> refList = new ArrayList<>();
                while (refIter.hasNext()) {
                    refList.add(refIter.next());
                    if (refList.size() > 200) break; // safety limit
                }
                Reference[] refs = refList.toArray(new Reference[0]);

                out.println("  Found " + refs.length + " references");

                Set<Function> callerFunctions = new HashSet<>();

                for (Reference ref : refs) {
                    Address fromAddr = ref.getFromAddress();
                    out.println("    Ref from 0x" + fromAddr + " type=" + ref.getReferenceType());

                    // Find the enclosing function
                    Function caller = funcMgr.getFunctionContaining(fromAddr);
                    if (caller != null) {
                        callerFunctions.add(caller);
                        out.println("      In function: " + caller.getName() +
                                   " at 0x" + caller.getEntryPoint());
                    } else {
                        out.println("      Not in a known function - attempting to create one");
                        // Try to find the function start by walking backwards
                        try {
                            disassemble(fromAddr);
                            caller = funcMgr.getFunctionContaining(fromAddr);
                            if (caller != null) {
                                callerFunctions.add(caller);
                                out.println("      Created function: " + caller.getName() +
                                           " at 0x" + caller.getEntryPoint());
                            }
                        } catch (Exception e) {
                            // Ignore
                        }
                    }
                }

                // Decompile unique caller functions
                out.println("\n  Decompiling " + callerFunctions.size() + " caller functions:");
                for (Function caller : callerFunctions) {
                    out.println("\n  --- Caller: " + caller.getName() +
                               " at 0x" + caller.getEntryPoint() + " ---");
                    String decompiled = decompileFunction(caller, 60);
                    if (decompiled != null) {
                        out.println(decompiled);
                    } else {
                        out.println("  (decompilation failed)");
                    }
                }

            } catch (Exception e) {
                out.println("  Error analyzing refs: " + e.getMessage());
            }
        }

        // Analyze data references
        out.println("\n\n--- Analyzing Data References ---");
        for (int i = 0; i < KNOWN_DATA.length; i++) {
            long va = KNOWN_DATA[i];
            String name = KNOWN_DATA_NAMES[i];

            out.println("\n  === References to " + name + " (0x" + Long.toHexString(va) + ") ===");

            try {
                Address addr = makeAddr(va);
                ReferenceIterator iter = refMgr.getReferencesTo(addr);
                Set<Function> referencingFunctions = new HashSet<>();

                int refCount = 0;
                while (iter.hasNext()) {
                    Reference ref = iter.next();
                    refCount++;
                    Address fromAddr = ref.getFromAddress();

                    Function func = funcMgr.getFunctionContaining(fromAddr);
                    if (func != null) {
                        referencingFunctions.add(func);
                        if (refCount <= 20) {
                            out.println("    Ref from 0x" + fromAddr +
                                       " in " + func.getName() +
                                       " type=" + ref.getReferenceType());
                        }
                    } else if (refCount <= 20) {
                        out.println("    Ref from 0x" + fromAddr + " (no function)");
                    }
                }
                out.println("  Total: " + refCount + " references from " +
                           referencingFunctions.size() + " functions");

                // Decompile up to 10 most interesting functions
                int decompCount = 0;
                for (Function func : referencingFunctions) {
                    if (decompCount >= 10) break;
                    out.println("\n  --- Function referencing " + name + ": " +
                               func.getName() + " at 0x" + func.getEntryPoint() + " ---");
                    String decompiled = decompileFunction(func, 60);
                    if (decompiled != null) {
                        out.println(decompiled);
                        decompCount++;
                    }
                }

            } catch (Exception e) {
                out.println("  Error: " + e.getMessage());
            }
        }
    }

    private void findStringReferences() {
        out.println("\n\n--- Step 6: Finding Network-Related String References ---");

        String[] searchPatterns = {
            "/api/", "/v1/", "/auth/", "/serial/", "/lua/", "/config/",
            "/user/", "/ws/", "websocket", "NLR/", "neverlose",
            "application/json", "Content-Type", "User-Agent",
            "Authorization", "Bearer", "token", "hash", "hwid",
            "POST", "GET", "PUT", "DELETE",
            "145.239.80.134", "30030", "30031",
        };

        Memory mem = currentProgram.getMemory();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();

        for (String pattern : searchPatterns) {
            try {
                byte[] patternBytes = pattern.getBytes("ASCII");
                Address searchAddr = currentProgram.getMinAddress();
                List<Address> found = new ArrayList<>();

                while (searchAddr != null && found.size() < 20) {
                    Address result = mem.findBytes(searchAddr, patternBytes, null, true, monitor);
                    if (result == null) break;
                    found.add(result);
                    searchAddr = result.add(1);
                }

                if (!found.isEmpty()) {
                    out.println("\n  Pattern \"" + pattern + "\" found at " + found.size() + " locations:");
                    for (Address addr : found) {
                        out.println("    0x" + addr);

                        // Read the full string at this location
                        try {
                            StringBuilder sb = new StringBuilder();
                            for (int j = 0; j < 256; j++) {
                                byte b = mem.getByte(addr.add(j));
                                if (b == 0 || b < 0x20 || b > 0x7E) break;
                                sb.append((char) b);
                            }
                            // Also read backwards to get the full string
                            StringBuilder prefix = new StringBuilder();
                            for (int j = 1; j < 128; j++) {
                                try {
                                    byte b = mem.getByte(addr.subtract(j));
                                    if (b == 0 || b < 0x20 || b > 0x7E) break;
                                    prefix.insert(0, (char) b);
                                } catch (Exception e) {
                                    break;
                                }
                            }
                            String fullStr = prefix.toString() + sb.toString();
                            if (!fullStr.equals(pattern)) {
                                out.println("      Full string: \"" + fullStr + "\"");
                            }
                        } catch (Exception e) {
                            // Ignore
                        }

                        // Find code that references this string address
                        ReferenceIterator refs = refMgr.getReferencesTo(addr);
                        while (refs.hasNext()) {
                            Reference ref = refs.next();
                            Address from = ref.getFromAddress();
                            Function func = funcMgr.getFunctionContaining(from);
                            if (func != null) {
                                out.println("      Referenced by " + func.getName() +
                                           " at 0x" + from);
                            } else {
                                out.println("      Referenced from 0x" + from);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                out.println("  Error searching for \"" + pattern + "\": " + e.getMessage());
            }
        }
    }

    private void findVtablePatterns() {
        out.println("\n\n--- Step 7: Analyzing Requestor Vtable ---");

        // The Requestor singleton at 0x42518C58 should point to an object
        // whose first DWORD is a vtable pointer. Read it.
        try {
            Memory mem = currentProgram.getMemory();
            Address singletonAddr = makeAddr(0x42518C58L);

            // Read the pointer value
            int ptrValue = mem.getInt(singletonAddr);
            out.println("  g_pRequestor (0x42518C58) = 0x" + Integer.toHexString(ptrValue));

            if (ptrValue != 0) {
                Address objAddr = makeAddr(ptrValue & 0xFFFFFFFFL);
                int vtablePtr = mem.getInt(objAddr);
                out.println("  Object at 0x" + Integer.toHexString(ptrValue) +
                           " vtable = 0x" + Integer.toHexString(vtablePtr));

                if (vtablePtr != 0) {
                    Address vtableAddr = makeAddr(vtablePtr & 0xFFFFFFFFL);
                    out.println("  Vtable entries:");
                    for (int i = 0; i < 20; i++) {
                        try {
                            int entry = mem.getInt(vtableAddr.add(i * 4));
                            String entryHex = "0x" + Integer.toHexString(entry);
                            FunctionManager funcMgr = currentProgram.getFunctionManager();
                            Function func = funcMgr.getFunctionAt(makeAddr(entry & 0xFFFFFFFFL));
                            String funcName = func != null ? " (" + func.getName() + ")" : "";
                            out.println("    [" + i + "] " + entryHex + funcName);
                        } catch (Exception e) {
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            out.println("  Error analyzing vtable: " + e.getMessage());
        }

        // Also look for the auth token
        out.println("\n  --- Auth Token Analysis ---");
        try {
            Memory mem = currentProgram.getMemory();
            Address tokenAddr = makeAddr(0x41BF8341L);
            StringBuilder tokenStr = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                byte b = mem.getByte(tokenAddr.add(i));
                if (b == 0) break;
                if (b >= 0x20 && b <= 0x7E) {
                    tokenStr.append((char) b);
                } else {
                    tokenStr.append(String.format("\\x%02X", b & 0xFF));
                }
            }
            out.println("  Auth token data at 0x41BF8341: \"" + tokenStr + "\"");
        } catch (Exception e) {
            out.println("  Error reading auth token: " + e.getMessage());
        }
    }
}
