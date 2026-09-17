// crypto_capture.cpp - Hook CryptoPP functions to capture AES-CBC key/IV
// + stack trace to find the full call chain above decrypt
//
// State machine (from binary analysis):
//   State 0x11: SetKey(key, 16, params)     @ 0x41E528A0
//   State 0x12: cipher_dispatch(cipher,iv,0) @ 0x41E51970
//   State 0x13: StreamTransformationFilter    @ 0x41E55D10
//
// Output: %TEMP%\crypto_capture.log

#include "internal_fixes.h"
#include "HookFn.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <intrin.h>

static FILE* g_clog = nullptr;
static char  g_log_path[MAX_PATH] = {};

static void open_clog()
{
    if (!g_clog) {
        GetTempPathA(MAX_PATH, g_log_path);
        strcat_s(g_log_path, "crypto_capture.log");
        g_clog = fopen(g_log_path, "w");
        if (g_clog) {
            fprintf(g_clog, "=== CryptoPP AES-128-CBC Key/IV Capture ===\n\n");
            fflush(g_clog);
            printf("[crypto_capture] Log: %s\n", g_log_path);
            fflush(stdout);
        }
    }
}

static void dump_hex(const char* label, const void* ptr, size_t len)
{
    if (!g_clog || !ptr) return;
    const uint8_t* p = (const uint8_t*)ptr;
    fprintf(g_clog, "%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) fprintf(g_clog, "  %04zX: ", i);
        fprintf(g_clog, "%02X ", p[i]);
        if (i % 16 == 15 || i == len - 1) fprintf(g_clog, "\n");
    }
}

static void dump_stack_trace(const char* label)
{
    if (!g_clog) return;
    fprintf(g_clog, "\n--- STACK TRACE: %s ---\n", label);
    printf("--- STACK TRACE: %s ---\n", label);

    void* frames[64];
    USHORT n = RtlCaptureStackBackTrace(0, 64, frames, NULL);
    for (USHORT i = 0; i < n; i++) {
        uint32_t addr = (uint32_t)(uintptr_t)frames[i];
        fprintf(g_clog, "  [%2d] 0x%08X\n", i, addr);
        printf("  [%2d] 0x%08X\n", i, addr);
    }

    fprintf(g_clog, "--- END STACK TRACE ---\n");
    fflush(g_clog);
    fflush(stdout);
}

// =====================================================================
// Hook 1: CryptoPP::SetKey @ 0x41E528A0
// __thiscall: ecx=this, stack: (const byte* key, uint32_t keyLen, void* params)
// =====================================================================
typedef void(__fastcall* setkey_fn)(void* thisptr, void* edx,
    const uint8_t* key, uint32_t keyLen, void* params);
static setkey_fn g_orig_setkey = nullptr;

static void __fastcall hooked_setkey(void* thisptr, void* edx,
    const uint8_t* key, uint32_t keyLen, void* params)
{
    open_clog();
    void* caller = _ReturnAddress();

    if (g_clog) {
        fprintf(g_clog, "\n======== SetKey (0x41E528A0) ========\n");
        fprintf(g_clog, "caller  = 0x%08X\n", (uint32_t)(uintptr_t)caller);
        fprintf(g_clog, "this    = 0x%08X\n", (uint32_t)(uintptr_t)thisptr);
        fprintf(g_clog, "keyLen  = %u\n", keyLen);

        if (key && keyLen > 0 && keyLen <= 64) {
            dump_hex("KEY", key, keyLen);
            fprintf(g_clog, "KEY_HEX: ");
            for (uint32_t i = 0; i < keyLen; i++) fprintf(g_clog, "%02X", key[i]);
            fprintf(g_clog, "\n");
        }

        dump_stack_trace("SetKey");
        fprintf(g_clog, "========\n\n");
        fflush(g_clog);
    }

    printf("[CRYPTO] SetKey from 0x%08X: keyLen=%u key=",
        (uint32_t)(uintptr_t)caller, keyLen);
    if (key && keyLen <= 64)
        for (uint32_t i = 0; i < keyLen; i++) printf("%02X", key[i]);
    printf("\n"); fflush(stdout);

    g_orig_setkey(thisptr, edx, key, keyLen, params);
}

// =====================================================================
// Hook 2: cipher_dispatch @ 0x41E51970
// =====================================================================
typedef void(__fastcall* dispatch_fn)(void* thisptr, void* edx,
    void* cipher_obj, const uint8_t* iv, uint32_t flags);
static dispatch_fn g_orig_dispatch = nullptr;

static void __fastcall hooked_dispatch(void* thisptr, void* edx,
    void* cipher_obj, const uint8_t* iv, uint32_t flags)
{
    open_clog();
    void* caller = _ReturnAddress();

    if (g_clog) {
        fprintf(g_clog, "\n======== cipher_dispatch (0x41E51970) ========\n");
        fprintf(g_clog, "caller = 0x%08X  flags = %u (%s)\n",
            (uint32_t)(uintptr_t)caller, flags, flags == 0 ? "DECRYPT" : "ENCRYPT");
        if (iv) {
            dump_hex("IV", iv, 16);
            fprintf(g_clog, "IV_HEX: ");
            for (int i = 0; i < 16; i++) fprintf(g_clog, "%02X", iv[i]);
            fprintf(g_clog, "\n");
        }
        fprintf(g_clog, "========\n\n");
        fflush(g_clog);
    }

    printf("[CRYPTO] cipher_dispatch from 0x%08X: flags=%u iv=",
        (uint32_t)(uintptr_t)caller, flags);
    if (iv) for (int i = 0; i < 16; i++) printf("%02X", iv[i]);
    else printf("(null)");
    printf("\n"); fflush(stdout);

    g_orig_dispatch(thisptr, edx, cipher_obj, iv, flags);
}

// =====================================================================
// Hook 3: StreamTransformationFilter @ 0x41E55D10
// =====================================================================
typedef void(__fastcall* stf_fn)(void* thisptr, void* edx,
    void* cipher, void* sink, uint32_t padding);
static stf_fn g_orig_stf = nullptr;

static void __fastcall hooked_stf(void* thisptr, void* edx,
    void* cipher, void* sink, uint32_t padding)
{
    open_clog();
    if (g_clog) {
        fprintf(g_clog, "\n======== STFilter (0x41E55D10) padding=%u ========\n\n", padding);
        fflush(g_clog);
    }
    printf("[CRYPTO] STFilter: padding=%u\n", padding);
    fflush(stdout);

    g_orig_stf(thisptr, edx, cipher, sink, padding);
}

// =====================================================================
// Install all hooks
// =====================================================================
void install_crypto_capture()
{
    printf("[crypto_capture] Installing hooks...\n");

    {
        void* tramp = nullptr;
        NTSTATUS st = HookFn((void*)0x41E528A0, (void*)hooked_setkey, 0, &tramp);
        if (NT_SUCCESS(st)) {
            g_orig_setkey = (setkey_fn)tramp;
            printf("[crypto_capture] Hooked SetKey          @ 0x41E528A0\n");
        } else printf("[crypto_capture] FAILED SetKey: 0x%08lX\n", st);
    }

    {
        void* tramp = nullptr;
        NTSTATUS st = HookFn((void*)0x41E51970, (void*)hooked_dispatch, 0, &tramp);
        if (NT_SUCCESS(st)) {
            g_orig_dispatch = (dispatch_fn)tramp;
            printf("[crypto_capture] Hooked cipher_dispatch @ 0x41E51970\n");
        } else printf("[crypto_capture] FAILED cipher_dispatch: 0x%08lX\n", st);
    }

    {
        void* tramp = nullptr;
        NTSTATUS st = HookFn((void*)0x41E55D10, (void*)hooked_stf, 0, &tramp);
        if (NT_SUCCESS(st)) {
            g_orig_stf = (stf_fn)tramp;
            printf("[crypto_capture] Hooked STFilter         @ 0x41E55D10\n");
        } else printf("[crypto_capture] FAILED STFilter: 0x%08lX\n", st);
    }

    printf("[crypto_capture] Log: %%TEMP%%\\crypto_capture.log\n");
    fflush(stdout);
}
