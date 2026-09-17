__forceinline static void fix_OOF() {
    /* force to triangle */
    *(PBYTE)0x413AA111 = 0x57;

    /* remove glow */
    BYTE patch[] = { 0x6A, 0x00, 0x90, 0x90, 0x90 };
    void* addr = (void*)0x41C4B63E;
    memcpy(addr, patch, sizeof(patch));
}

__forceinline static void hide_legitbob() {
    DWORD stub = 0x412A53B0;
    std::memcpy((PVOID)0x4205BC78, &stub, sizeof(stub));
}

static int icon_color = 0xFFBCFF21;

__forceinline static void nade_warning_caca() {
    /* TODO:
 
    * make the duration circle color white.
    * the inner circle's alpha has to be forced to 100
    * swap positions between icon and text (icon at the top, text at the bottom)
    
    */

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


    // change icon color
    BYTE color_patch[5];
    color_patch[0] = 0xB8;
    std::memcpy(&color_patch[1], &icon_color, sizeof(int));

    std::memcpy((PBYTE)0x413D6F17, color_patch, sizeof(color_patch));

    BYTE* cleanup_addr = reinterpret_cast<BYTE*>(0x413D6F1C);
    BYTE nops[3] = { 0x90, 0x90, 0x90 };
    std::memcpy(cleanup_addr, nops, sizeof(nops));
}

nops: (address, nop_count)

	// disable username bottom right corner menu thing
	{ 0x41606F3C, 5 },
	{ 0x41606D28, 5 },
	{ 0x41606DE6, 5 },
	{ 0x41606E7C, 5 },
	{ 0x41606BCD, 5 },  // separator
	{ 0x41605B77, 4 },  // stop reserving bottom space for profile block

	// Big logo
	{ 0x4151b2c1, 5 }, // logo image
	{ 0x4151b2ca, 5 }, // logo background
	{ 0x4151b37e, 5 }, // big NEVERLOSE.CC text

	// Separator 1
	{ 0x4151b3bb, 5 },

	// Version / Build Date row
	{ 0x4151b4de, 5 }, // call imgui_text
	{ 0x4151b51d, 5 }, // call draw_rect_alpha_blend
	{ 0x4151b528, 5 }, // call draw_rect_bordered
	{ 0x4151b53b, 5 }, // call imgui_text
	{ 0x4151b545, 5 }, // call draw_text_centered

	// Build Type row
	{ 0x4151b698, 5 }, // call imgui_text
	{ 0x4151b6d7, 5 }, // call draw_rect_alpha_blend
	{ 0x4151b6e2, 5 }, // call draw_rect_bordered
	{ 0x4151b6f2, 5 }, // call imgui_text
	{ 0x4151b6fc, 5 }, // call draw_text_centered

	// Registered To row
	{ 0x4151b8ba, 5 }, // call imgui_text
	{ 0x4151b8f9, 5 }, // call draw_rect_alpha_blend
	{ 0x4151b904, 5 }, // call draw_rect_bordered
	{ 0x4151b915, 5 }, // call imgui_text
	{ 0x4151b91f, 5 }, // call draw_text_centered

	// Subscription Time row
	{ 0x4151ba4f, 5 }, // call imgui_text
	{ 0x4151ba8e, 5 }, // call draw_rect_alpha_blend
	{ 0x4151ba99, 5 }, // call draw_rect_bordered
	{ 0x4151baac, 5 }, // call imgui_text
	{ 0x4151bab6, 5 }, // call draw_text_centered

	// Big Logo
	{ 0x4151bcf6, 5 }, // logo background
	{ 0x4151bd36, 5 }, // logo image

	// Separator 2
	{ 0x4151bdb5, 5 },

    // Copyright text
	{ 0x4151bd6f, 5 }, // call imgui_text
	{ 0x4151bd79, 5 }, // call draw_text_centered

	// ConfigTabFooter
	{ 0x41539402, 5 }, // renders market link text
	{ 0x415395c8, 6 }, // opens market URL on click
	{ 0x415395df, 5 }, // positions text before separator
	{ 0x415395e9, 5 }, // call draw_separator
	{ 0x415395f8, 5 }, // positions text after separator

	// ScriptsTabFooter
	{ 0x41b5ecaf, 5 }, // renders market link text
	{ 0x41b5ee75, 6 }, // opens market URL on click
	{ 0x41b5ec5f, 5 }, // separator 1
	
    // nade warning
	{ 0x413D68B0, 5 }