#include "HookFn.h"

static void FixRels(PVOID Address, PVOID Trampoline)
{
    BYTE* og = (BYTE*)Address;
    INT32 absolete = 0;
    
    switch (*og)
    {
    case 0xE8:
    case 0xE9:
        absolete = ((INT32)og + *(INT32*)(og + 1) + 5);
        *(INT32*)((BYTE*)Trampoline + 1) = absolete - (INT32)Trampoline - 5;
        break;
    case 0x0F:
        if (og[1] >= 0x80 && og[1] < 0x90)
        {
            absolete = ((INT32)og + *(INT32*)(og + 2) + 6);
            *(INT32*)((BYTE*)Trampoline + 2) = absolete - (INT32)Trampoline - 6;
        };
        break;
    default:
        break;
    };
};

NTSTATUS HookFn(void* Dst, void* Src, SIZE_T NopBytes, void** TrampOut, size_t TrampOffset)
{
    NTSTATUS status = STATUS_SUCCESS;

    INT32 rel32 = (INT32)((BYTE*)Src - (BYTE*)Dst - 5);
    DWORD OldProto{ 0 };
    SIZE_T regsize = 5 + NopBytes;
    LPVOID baseaddr = Dst;
    SIZE_T localRegSize = regsize;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &baseaddr, &localRegSize, PAGE_EXECUTE_READWRITE, &OldProto);
    if (!NT_SUCCESS(status)) goto fail;

    if (TrampOut)
    {
        PVOID pTramp = nullptr;
        size_t tramp_copy_size = regsize - TrampOffset;
        SIZE_T TrampSizeLocal = tramp_copy_size + 5;

        status = NtAllocateVirtualMemory(NtCurrentProcess(), &pTramp, 0, &TrampSizeLocal, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(status)) goto fail;

        memcpy(pTramp, (char*)Dst + TrampOffset, tramp_copy_size);

        FixRels((char*)Dst + TrampOffset, pTramp);

        *((char*)pTramp + tramp_copy_size) = 0xE9;
        *(INT32*)((BYTE*)pTramp + tramp_copy_size + 1) = (INT32)((BYTE*)Dst + regsize - ((BYTE*)pTramp + tramp_copy_size) - 5);

        *TrampOut = pTramp;
    };

    *(BYTE*)Dst = 0xE9;
    *(INT32*)((BYTE*)Dst + 1) = rel32;

    if (NopBytes)
        memset((char*)Dst + 5, 0x90, NopBytes);

    status = NtProtectVirtualMemory(NtCurrentProcess(), &baseaddr, &regsize, OldProto, &OldProto);
    if (NT_SUCCESS(status))
        status = NtFlushInstructionCache(NtCurrentProcess(), Dst, regsize);
fail:
    return status;
};
