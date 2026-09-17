#include "neverlose.h"
#include "nops.h"
#include "internal_fixes.h"
#include "token.h"
#include "fun_stuff.h"

constexpr auto g_stupid_ahh_shit_flow_fix = std::to_array<DWORD>
({
    0x412EADC5,
    0x413129D2,
    0x41312D00,
    0x4133485D,
    0x41335068,
    0x4133CE9D,
    0x41340AF7,
    0x4134149A,
    0x4134185A,
    0x413534AF,
    0x4135F2BA,
    0x41368434,
    0x4136F4AE,
    0x413C1EE7,
    0x413C43A8,
    0x413D3AEF,
    0x413D5392,
    0x413D6481,
    0x413DC360,
    0x413DCD84,
    0x413E1A6F,
    0x413E472F,
    0x413E82AD,
    0x413E9204,
    0x413EBC8C,
    0x413F3D2F,
    0x413F838F,
    0x414000DB,
    0x414084DE,
    0x41409AC1,
    0x4140FFF7,
    0x4141485B,
    0x41414BB6,
    0x41415283,
    0x41419241,
    0x414196C3,
    0x4141AB52,
    0x4141B183,
    0x4141B655,
    0x4141BAB3,
    0x4141C2E6,
    0x4141FDB5,
    0x41420111,
    0x41420484,
    0x41439012,
    0x4143DED0,
    0x4146B4E8,
    0x414703B2,
    0x4147BD0C,
    0x414802FD,
    0x4148CE6F,
    0x4148D18E,
    0x4148D4A7,
    0x41493FCF,
    0x41495B74,
    0x414AD482,
    0x414B2D58,
    0x414B5F87,
    0x414B9BFF,
    0x414BBBB7,
    0x414BCAF3,
    0x414BDB3A,
    0x414BEB2B,
    0x414BFB2F,
    0x414C0C6B,
    0x414C4F25,
    0x414CFAA6,
    0x414D18C9,
    0x414D4963,
    0x414D4DB0,
    0x414D51C1,
    0x414D6281,
    0x414E4372,
    0x414FAD34,
    0x41503C9B,
    0x415041AA,
    0x415045B7,
    0x41504942,
    0x4150816B,
    0x41508EA6,
    0x41509281,
    0x415097B2,
    0x4150E146,
    0x4150E532,
    0x415113B7,
    0x41511718,
    0x41511FCF,
    0x4151EED3,
    0x415714E1,
    0x4157183A,
    0x41571CEA,
    0x415965A2,
    0x415A71F6,
    0x415A7A11,
    0x415B25F8,
    0x415B4D0F,
    0x415B78F9,
    0x415B9A1D,
    0x415DFBB3,
    0x415E3ABA,
    0x4185A75B,
    0x41976247,
    0x419B0199,
    });

static void last_resort_fixes()
{
	// init logging
	*(PHANDLE)0x42518C44 = GetStdHandle(STD_OUTPUT_HANDLE);
	//memset((PVOID)0x41C12B3E, 0x90, 6); // for websocketpp

	*(PSHORT)0x415F26C0 = 0xC3C3;
	*(PSHORT)0x41DA1080 = 0xC3C3;
	//*(PPVOID)0x42262DC8 = (PVOID)auth_token;
	*(PPVOID)0x41BF8341 = (PVOID)&auth_token;

	*(PBYTE)0x41B63BB0 = 0xC3;
	*(PBYTE)0x41DA128F = 0xEB;
	*(PSHORT)0x41580769 = 0xE967;
	*(PSHORT)0x41B64154 = 0xE967;

	*(PBYTE)0x41B582DC = 0x3;
	PVOID addr = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	*(PPVOID)0x424AFCC0 = addr;
	*(PDWORD)0x4479EE00 = (DWORD)addr + 0x1000;
	printf("Allocated at %p\n", addr);
};

void neverlose::fix_dump()
{
	printf("  [fix_dump] fix_imports()...\n"); fflush(stdout);
	fix_imports();
	printf("  [fix_dump] fix_imports() done\n"); fflush(stdout);

	printf("  [fix_dump] spoof_peb()...\n"); fflush(stdout);
	spoof_peb();
	printf("  [fix_dump] spoof_peb() done\n"); fflush(stdout);

	printf("  [fix_dump] spoof_kusd()...\n"); fflush(stdout);
	spoof_kusd();
	printf("  [fix_dump] spoof_kusd() done\n"); fflush(stdout);

	printf("  [fix_dump] spoof_cpuid()...\n"); fflush(stdout);
	spoof_cpuid();
	printf("  [fix_dump] spoof_cpuid() done\n"); fflush(stdout);

	printf("  [fix_dump] fix_interfaces()...\n"); fflush(stdout);
	fix_interfaces();
	printf("  [fix_dump] fix_interfaces() done\n"); fflush(stdout);

	printf("  [fix_dump] fix_cvars()...\n"); fflush(stdout);
	fix_cvars();
	printf("  [fix_dump] fix_cvars() done\n"); fflush(stdout);

	printf("  [fix_dump] fix_signatures()...\n"); fflush(stdout);
	fix_signatures();
	printf("  [fix_dump] fix_signatures() done\n"); fflush(stdout);

	printf("  [fix_dump] nop patching (%zu addrs)...\n", g_noped_addrs.size()); fflush(stdout);
	for (auto& [address, count] : g_noped_addrs) memset((PVOID)address, 0x90, count);
	printf("  [fix_dump] nop patching done\n"); fflush(stdout);

	printf("  [fix_dump] fix_mem_dispatcher()...\n"); fflush(stdout);
	fix_mem_dispatcher();
	printf("  [fix_dump] fix_mem_dispatcher() done\n"); fflush(stdout);

	printf("  [fix_dump] flow fix patching (%zu addrs)...\n", g_stupid_ahh_shit_flow_fix.size()); fflush(stdout);
	for (DWORD addr : g_stupid_ahh_shit_flow_fix) *(PBYTE)addr = 0xEB;
	printf("  [fix_dump] flow fix patching done\n"); fflush(stdout);

	printf("  [fix_dump] fix_sha256()...\n"); fflush(stdout);
	fix_sha256();
	printf("  [fix_dump] fix_sha256() done\n"); fflush(stdout);

	printf("  [fix_dump] hijack_requestor()...\n"); fflush(stdout);
	hijack_requestor();
	printf("  [fix_dump] hijack_requestor() done\n"); fflush(stdout);

	printf("  [fix_dump] last_resort_fixes()...\n"); fflush(stdout);
	last_resort_fixes();
	printf("  [fix_dump] last_resort_fixes() done\n"); fflush(stdout);

	printf("  [fix_dump] install_crypto_capture()...\n"); fflush(stdout);
	install_crypto_capture();
	printf("  [fix_dump] install_crypto_capture() done\n"); fflush(stdout);

	printf("  [fix_dump] apply_fun_stuff()...\n"); fflush(stdout);
	apply_fun_stuff();
	printf("  [fix_dump] apply_fun_stuff() done\n"); fflush(stdout);
};