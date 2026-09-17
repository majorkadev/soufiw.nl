#include <windows.h>
#include <cstdio>
#include <cstring>
#include "neverlose.h"
#include "fun_stuff.h"

struct FunPatch {
    uintptr_t address;
    size_t count;
};

static const FunPatch g_fun_nops[] = {
    // Disable username bottom right corner profile block
    { 0x41606F3C, 5 },
    { 0x41606D28, 5 },
    { 0x41606DE6, 5 },
    { 0x41606E7C, 5 },
    { 0x41606BCD, 5 },  // separator
    { 0x41605B77, 4 },  // stop reserving bottom space for profile block

    // Big logo & top-left NEVERLOSE.CC text elements
    { 0x4151b2c1, 5 }, // logo image
    { 0x4151b2ca, 5 }, // logo background
    { 0x4151b37e, 5 }, // big NEVERLOSE.CC text rendering call

    // Separator 1
    { 0x4151b3bb, 5 },

    // Version / Build Date row
    { 0x4151b4de, 5 },
    { 0x4151b51d, 5 },
    { 0x4151b528, 5 },
    { 0x4151b53b, 5 },
    { 0x4151b545, 5 },

    // Build Type row
    { 0x4151b698, 5 },
    { 0x4151b6d7, 5 },
    { 0x4151b6e2, 5 },
    { 0x4151b6f2, 5 },
    { 0x4151b6fc, 5 },

    // Registered To row
    { 0x4151b8ba, 5 },
    { 0x4151b8f9, 5 },
    { 0x4151b904, 5 },
    { 0x4151b915, 5 },
    { 0x4151b91f, 5 },

    // Subscription Time row
    { 0x4151ba4f, 5 },
    { 0x4151ba8e, 5 },
    { 0x4151ba99, 5 },
    { 0x4151baac, 5 },
    { 0x4151bab6, 5 },

    // Big Logo background & image
    { 0x4151bcf6, 5 },
    { 0x4151bd36, 5 },

    // Separator 2
    { 0x4151bdb5, 5 },

    // Copyright text
    { 0x4151bd6f, 5 },
    { 0x4151bd79, 5 },

    // ConfigTabFooter market links
    { 0x41539402, 5 },
    { 0x415395c8, 6 },
    { 0x415395df, 5 },
    { 0x415395e9, 5 },
    { 0x415395f8, 5 },

    // ScriptsTabFooter market links
    { 0x41b5ecaf, 5 },
    { 0x41b5ee75, 6 },
    { 0x41b5ec5f, 5 },

    // Nade warning default
    { 0x413D68B0, 5 }
};

static void fix_OOF() {
    /* force out-of-field indicator to triangle */
    *(PBYTE)0x413AA111 = 0x57;

    /* remove glow */
    BYTE patch[] = { 0x6A, 0x00, 0x90, 0x90, 0x90 };
    std::memcpy((void*)0x41C4B63E, patch, sizeof(patch));
}

static void hide_legitbob() {
    DWORD stub = 0x412A53B0;
    std::memcpy((PVOID)0x4205BC78, &stub, sizeof(stub));
}

static int icon_color = 0xFFBCFF21;

static void nade_warning_caca() {
    // make timer circle 360 degrees
    *reinterpret_cast<float*>(0x413D7157) = 0.0f;
    *reinterpret_cast<float*>(0x420725B8) = 0.0f;
    *reinterpret_cast<float*>(0x42072540) = 1.0f;
    *reinterpret_cast<float*>(0x42072538) = 6.6f;

    static unsigned char thickness_patch[] = {
        0xC7, 0x44, 0x24, 0x14, // mov dword ptr [esp+0x14]
        0x00, 0x00, 0x00, 0x40  // thickness
    };

    static float* const pThickness = reinterpret_cast<float*>(&thickness_patch[4]);
    *pThickness = 1.5f;

    std::memcpy((PBYTE)0x413D714B, thickness_patch, sizeof(thickness_patch));

    BYTE jmp_patch[6] = { 0xE9, 0x32, 0x02, 0x00, 0x00, 0x90 }; // remove directional arrow under grenade warning 
    std::memcpy((PBYTE)0x41C56B57, jmp_patch, sizeof(jmp_patch));

    BYTE color_patch[5];
    color_patch[0] = 0xB8;
    std::memcpy(&color_patch[1], &icon_color, sizeof(int));
    std::memcpy((PBYTE)0x413D6F17, color_patch, sizeof(color_patch));

    BYTE nops[3] = { 0x90, 0x90, 0x90 };
    std::memcpy((PBYTE)0x413D6F1C, nops, sizeof(nops));
}

void apply_fun_stuff() {
    printf("[majorkadev] Applying fun_stuff UI & memory patches...\n"); fflush(stdout);

    for (const auto& p : g_fun_nops) {
        std::memset((void*)p.address, 0x90, p.count);
    }

    fix_OOF();
    hide_legitbob();
    nade_warning_caca();

    printf("[majorkadev] fun_stuff patches applied successfully!\n"); fflush(stdout);
}
