#include "neverlose.h"
#include "cpuid_emulator.h"
#include "KUSER_SHARED_DATA_SPOOF.h"

void cpuid_emulator(CONTEXT* ctx)
{
    DWORD leaf = ctx->Eax;
    DWORD subleaf = ctx->Ecx;

    if (leaf < 0x80000000)
    {
        switch (leaf)
        {
        case 0x00000000:
            ctx->Eax = 0x10;
            ctx->Ebx = 0x68747541;
            ctx->Ecx = 0x444D4163;
            ctx->Edx = 0x69746E65;
            return;
        case 0x00000001:
            ctx->Eax = 0x0A60F12;
            ctx->Ebx = 0x100800;
            ctx->Ecx = 0x7ED8320B;
            ctx->Edx = 0x178BFBFF;
            return;
        case 0x00000005:
            ctx->Eax = 0x40;
            ctx->Ebx = 0x40;
            ctx->Ecx = 0x3;
            ctx->Edx = 0x11;
            return;
        case 0x00000006:
            ctx->Eax = 0x4;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x1;
            ctx->Edx = 0x0;
            return;
        case 0x00000007:
            if (subleaf == 0)
            {
                ctx->Eax = 0x1;
                ctx->Ebx = 0x0F1BF97A9;
                ctx->Ecx = 0x405FCE;
                ctx->Edx = 0x10000010;
                return;
            }
            else if (subleaf == 1)
            {
                ctx->Eax = 20;
                ctx->Ebx = 0;
                ctx->Ecx = 0;
                ctx->Edx = 0;
                return;
            }
        case 0x00000002:
        case 0x00000003:
        case 0x00000004:
        case 0x00000008:
        case 0x00000009:
        case 0x0000000A:
        case 0x0000000C:
        case 0x0000000E:
            ctx->Eax = 0;
            ctx->Ebx = 0;
            ctx->Ecx = 0;
            ctx->Edx = 0;
            return;
        case 0x0000000B:
            ctx->Eax = 0x1;
            ctx->Ebx = 0x2;
            ctx->Ecx = 0x100;
            ctx->Edx = 0x6;
            return;
        case 0x0000000D:
            ctx->Eax = 0x2E7;
            ctx->Ebx = 0x980;
            ctx->Ecx = 0x988;
            ctx->Edx = 0x0;
            return;
        case 0x0000000F:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x0FF;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x2;
            return;
        case 0x00000010:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x2;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        default:
            return;
        };
    }
    else
    {
        switch (leaf)
        {
        case 0x80000009:
        case 0x8000000B:
        case 0x8000000C:
        case 0x8000000D:
        case 0x8000000E:
        case 0x8000000F:
        case 0x80000010:
        case 0x80000011:
        case 0x80000012:
        case 0x80000013:
        case 0x80000014:
        case 0x80000015:
        case 0x80000016:
        case 0x80000017:
        case 0x80000018:
        case 0x8000001C:
        case 0x80000023:
        case 0x80000024:
        case 0x80000025:
        case 0x80000027:
        case 0x80000028:
            ctx->Eax = 0;
            ctx->Ebx = 0;
            ctx->Ecx = 0;
            ctx->Edx = 0;
            return;
        case 0x80000000:
            ctx->Eax = 0x80000028;
            ctx->Ebx = 0x68747541;
            ctx->Ecx = 0x444D4163;
            ctx->Edx = 0x69746E65;
            return;
        case 0x80000001:
            ctx->Eax = 0x0A60F12;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x75C237FF;
            ctx->Edx = 0x2FD3FBFF;
            return;
        case 0x80000002:
            ctx->Eax = 0x20444D41;
            ctx->Ebx = 0x657A7952;
            ctx->Ecx = 0x2037206E;
            ctx->Edx = 0x30303737;
            return;
        case 0x80000003:
            ctx->Eax = 0x2D382058;
            ctx->Ebx = 0x65726F43;
            ctx->Ecx = 0x6F725020;
            ctx->Edx = 0x73736563;
            return;
        case 0x80000004:
            ctx->Eax = 0x2020726F;
            ctx->Ebx = 0x20202020;
            ctx->Ecx = 0x20202020;
            ctx->Edx = 0x202020;
            return;
        case 0x80000005:
            ctx->Eax = 0xFF48FF40;
            ctx->Ebx = 0xFF48FF40;
            ctx->Ecx = 0x20080140;
            ctx->Edx = 0x20080140;
            return;
        case 0x80000006:
            ctx->Eax = 0x5C002200;
            ctx->Ebx = 0x6C004200;
            ctx->Ecx = 0x4006140;
            ctx->Edx = 0x1009140;
            return;
        case 0x80000007:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x3B;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x6799;
            return;
        case 0x80000008:
            ctx->Eax = 0x3030;
            ctx->Ebx = 0x791EF257;
            ctx->Ecx = 0x400F;
            ctx->Edx = 0x10000;
            return;
        case 0x8000000A:
            ctx->Eax = 0x1;
            ctx->Ebx = 0x8000;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x1EBFBCFF;
            return;
        case 0x80000019:
            ctx->Eax = 0xF048F040;
            ctx->Ebx = 0xF0400000;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001A:
            ctx->Eax = 0x6;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001B:
            ctx->Eax = 0xBFF;
            ctx->Ebx = 0x0;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001D:
            ctx->Eax = 0x4121;
            ctx->Ebx = 0x1C0003F;
            ctx->Ecx = 0x3F;
            ctx->Edx = 0x0;
            return;
        case 0x8000001E:
            ctx->Eax = 0xC;
            ctx->Ebx = 0x106;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x8000001F:
            ctx->Eax = 0x1;
            ctx->Ebx = 0xB3;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x80000020:
            ctx->Eax = 0x0;
            ctx->Ebx = 0x1E;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x80000021:
            ctx->Eax = 0x62FCF;
            ctx->Ebx = 0x15C;
            ctx->Ecx = 0x0;
            ctx->Edx = 0x0;
            return;
        case 0x80000022:
            ctx->Eax = 0x7;
            ctx->Ebx = 0x84106;
            ctx->Ecx = 0x3;
            ctx->Edx = 0x0;
            return;
        case 0x80000026:
            ctx->Eax = 0x1;
            ctx->Ebx = 0x2;
            ctx->Ecx = 0x100;
            ctx->Edx = 0x0C;
            return;
        default:
            return;
        };
    };
};

static const char errfmt[] =
"NL has been stopped due to fatal error.\n\n"
"[0x%p] Technical information:\nError code: 0x%X\nAddress: 0x%X (%c 0x%X)\nAttempt to %s data at address: 0x%X"
"\n\nEAX = 0x%X\nEBX = 0x%X\nECX = 0x%X\n"
"EDX = 0x%X\nESI = 0x%X\nEDI = 0x%X\nEBP = 0x%X\nESP = 0x%X\nEIP = 0x%X"
"\n\nStack Image (15 Executive DWORDs):"
"\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X\n0x%X";

static __forceinline const char* mnemonic_type(uint32_t info0)
{
	switch (info0)
	{
	case 0:
		return "read";
	case 1:
		return "write";
	case 8:
		return "execute";
	default:
		return "unknown operation";
	};
};

static __forceinline bool IsExecutableAddress(PVOID Address)
{
    MEMORY_BASIC_INFORMATION mbi{ 0 };
    if (!VirtualQuery(Address, &mbi, sizeof(mbi))) return false;

    if (mbi.State != MEM_COMMIT) return false;

    switch (mbi.Protect & 0xFF)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    };
};

LONG NTAPI nl_veh(struct _EXCEPTION_POINTERS* ExceptionInfo)
{	
    if (!g_neverlose.in_range(ExceptionInfo->ExceptionRecord->ExceptionAddress)) return EXCEPTION_CONTINUE_SEARCH;

	if (ExceptionInfo && ExceptionInfo->ExceptionRecord && ExceptionInfo->ContextRecord)
	{
		PEXCEPTION_RECORD rec = ExceptionInfo->ExceptionRecord;
		PCONTEXT ctx = ExceptionInfo->ContextRecord;

		if (rec->ExceptionAddress && rec->ExceptionCode == EXCEPTION_BREAKPOINT)
		{
            for (DWORD address : g_veh_cpuid_emus)
            {
                if (address == (DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress)
                {
                    cpuid_emulator(ctx);
                    ctx->Eip += 2;
                    //printf("[0x%p] Spoofed CPUID at 0x%p\n", NtCurrentThreadId(), ExceptionInfo->ExceptionRecord->ExceptionAddress);
                    return EXCEPTION_CONTINUE_EXECUTION;
                };
            };
		}
		else if (rec->ExceptionAddress == NULL && rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
			return EXCEPTION_CONTINUE_EXECUTION;

		char errbuff[1024];
		
        uint32_t addr = (uint32_t)ExceptionInfo->ExceptionRecord->ExceptionAddress;
        INT32 addr_diff = (INT32)addr - (INT32)g_neverlose.base();
		const char* mnemonic = mnemonic_type(ExceptionInfo->ExceptionRecord->ExceptionInformation[0]);
		uint32_t mnemonic_addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        PPVOID esp_frame = (PPVOID)ctx->Esp;
        DWORD addrs[35]{ 0 };
        size_t i = 0; 
        size_t j = 0;
        while (j < 35)
        {
            if (IsExecutableAddress(esp_frame[i]))
                addrs[j++] = (DWORD)esp_frame[i];
            i++;
        };
        sprintf_s(errbuff, sizeof(errbuff), errfmt, NtCurrentThreadId(), ExceptionInfo->ExceptionRecord->ExceptionCode, addr, (addr_diff < 0 ? '-' : '+'), abs(addr_diff),
            mnemonic, mnemonic_addr, ctx->Eax, ctx->Ebx,
            ctx->Ecx, ctx->Edx, ctx->Esi, ctx->Edi,
            ctx->Ebp, ctx->Esp, ctx->Eip, addrs[0], addrs[1],
            addrs[2], addrs[3], addrs[4], addrs[5],
            addrs[6], addrs[7], addrs[8], addrs[9],
            addrs[10], addrs[11], addrs[12], addrs[13],
            addrs[14]);
		MessageBoxA(0, errbuff, 0, MB_ICONERROR);
		return EXCEPTION_CONTINUE_EXECUTION;
	};
	return EXCEPTION_CONTINUE_SEARCH;
};

void neverlose::set_veh()
{
	AddVectoredExceptionHandler(0, nl_veh);
	ENTER_LOGGER(logman) << "Added Vectored Exception Handler " << nl_veh << '\n';
};