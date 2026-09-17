#include "internal_fixes.h"
#include "HookFn.h"
#include "FindPattern.h"
#include <cstdio>
#include "detours.h"
#include <vector>

enum operation_t
{
    OPERATION_REGISTER_HOOK = 1,
    OPERATION_EMPLACE_HOOKS,
    OPERATION_ERASE_HOOKS,
    OPERATION_SIGSCAN = 6,
};

#pragma pack(push, 1)
struct sigscan_t
{
    PVOID64 Base;
    PVOID64 Signature;
    size_t Length;
    PVOID64 Result;
};

struct hook_t
{
    PVOID64 Address;
    PVOID64 Hook;
    PVOID64 pTrampoline;
};
#pragma pack(pop)

struct HookDesc
{
    bool IsActive;
    PVOID Address;
    PVOID Trampoline;
    PVOID Hook;
};

const char* optostr[] =
{
    NULL,
    "OPERATION_REGISTER_HOOK",
    "OPERATION_EMPLACE_HOOKS",
    "OPERATION_ERASE_HOOKS",
    NULL, NULL,
    "OPERATION_SIGSCAN",
};
static auto& g_HkDesc = *reinterpret_cast<std::vector<HookDesc>*>(0x42500C44);
static bool TransactionAlive = false;
BOOL __cdecl hkMemDispatcher(operation_t type, void* ptr)
{
    BOOL result = FALSE;

    //printf("[0x%p] MemDispatcher(%s, 0x%p)", NtCurrentThreadId(), optostr[type], ptr);
    switch (type)
    {
    case OPERATION_SIGSCAN:
    {
        auto* data = (sigscan_t*)ptr;
        data->Result = FindPattern(data->Base, 0x7FFFFFFF, (PBYTE)data->Signature, data->Length, 0xCC, 0);
        //printf(" -> 0x%llX", data->Result);
        result = TRUE;
    };
    break;
    case OPERATION_REGISTER_HOOK:
    {
        if (!TransactionAlive)
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            TransactionAlive = true;
        };

        auto* data = (hook_t*)ptr;
        PVOID pTramp = data->Address;
        if (data->Address == (PBYTE)GetModuleHandle(L"engine.dll") + 0xF0470) return TRUE;
        if (DetourAttachEx(&pTramp, data->Hook, (PDETOUR_TRAMPOLINE*)data->pTrampoline, NULL, NULL) == NO_ERROR)
        {
            //printf(" 0x%llX -> 0x%llX", data->Address, *(PVOID64*)data->pTrampoline);
            result = TRUE;
        }
        else
            result = FALSE;
    };
    break;
    case OPERATION_EMPLACE_HOOKS:
        if (TransactionAlive)
        {
            DetourTransactionCommit();
            TransactionAlive = false;
            result = TRUE;
        }
        else
            result = FALSE;
        break;
    case OPERATION_ERASE_HOOKS:
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        for (auto& hook : g_HkDesc)
        {
            if (hook.IsActive && hook.Trampoline)
            {
                DetourDetach(&hook.Trampoline, hook.Hook);
                hook.IsActive = false;
            };
        };
        DetourTransactionCommit();
        result = TRUE;
    };
    break;
    default:
        break;
    };
    //printf("\n");
    return result;
};


void fix_mem_dispatcher()
{
	HookFn((PVOID)0x41DA0BA0, hkMemDispatcher, 0);
};