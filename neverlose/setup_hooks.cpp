#include <intrin.h>

#include "neverlose.h"
#include "HookFn.h"
#include <winsock2.h>
#include <vector>
#include "json.hpp"
#include "neverlosesdk.hpp"

HMODULE WaitForSingleModule(const char* module_name)
{
    HMODULE mod = nullptr;
    while (!mod)
    {
        mod = GetModuleHandleA(module_name);
        Sleep(0);
    };
    return mod;
};

/*
ANON:
*ppNodeName = "185.194.177.104";
*ppServiceName = "30030";
*/

void WSAAPI ProceedGetAddrInfo(PVOID retaddr, PCSTR* ppNodeName, PCSTR* ppServiceName)
{
    PVOID pBase = NULL;
    if (RtlPcToFileHeader(retaddr, &pBase) == (PVOID)0x412A0000)
    {
        printf("[0x%p] getaddrinfo(%s, %s)\n", NtCurrentThreadId(), *ppNodeName, *ppServiceName);
        *ppNodeName = "127.0.0.1";
        *ppServiceName = "30030";
    };
};

void* getaddr_tram = nullptr;
INT __declspec(naked) WSAAPI hkgetaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult)
{
    __asm
    {
        push ebp
        mov ebp, esp
        lea eax, [ebp + 12]
        push eax
        lea eax, [ebp + 8]
        push eax
        push[ebp + 4]
        call ProceedGetAddrInfo
        mov esp, ebp
        pop ebp

        push ebp
        mov ebp, esp
        jmp getaddr_tram
    };
};

NTSTATUS hkterm(HANDLE, NTSTATUS)
{
    printf("Terminated from 0x%p\n", _ReturnAddress());
    RtlExitUserThread(STATUS_SUCCESS);
    return STATUS_SUCCESS;
};

void hkexit(int)
{
    printf("exit from 0x%p\n", _ReturnAddress());
    RtlExitUserThread(STATUS_SUCCESS);
};

void* quer_tram = 0;
NTSTATUS NTAPI hkNtQueryValueKey(
    HANDLE KeyHandle,
    PCUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
)
{
    //if (_ReturnAddress() <= (PVOID)0x50000000)
    //{
    ULONG size = 0;
    NtQueryKey(KeyHandle, KeyNameInformation, NULL, 0, &size);
    if (size)
    {
        PKEY_NAME_INFORMATION pkni = (PKEY_NAME_INFORMATION)malloc(size);
        if (pkni && NT_SUCCESS(NtQueryKey(KeyHandle, KeyNameInformation, pkni, size, &size)))
        {
            printf("[0x%p] 0x%p NtQueryValueKey(%.*ls)\n", NtCurrentThreadId(), _ReturnAddress(), pkni->NameLength/sizeof(*pkni->Name), pkni->Name);
        };

        //NtSuspendProcess(NtCurrentProcess());
    };
    return reinterpret_cast<decltype(&NtQueryValueKey)>(quer_tram)(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
};

struct WMProtectDate
{
    unsigned short wYear;
    unsigned char bMonth;
    unsigned char bDay;
};

struct VMProtectSerialNumberData
{
    int nState;
    wchar_t wUserName[256];
    wchar_t wEMail[256];
    WMProtectDate dtExpire;
    WMProtectDate dtMaxBuild;
    int bRunningTime;
    unsigned char nUserDataLength;
    unsigned char bUserData[255];
};

void __stdcall errhandl(std::exception& ec, PVOID a2)
{
    printf("[0x%p] 0x%p Throwed(0x%p): %s\n", NtCurrentThreadId(), _ReturnAddress(), a2, ec.what());
    NtSuspendProcess(NtCurrentProcess());
};

void __fastcall performmenu(neverlosesdk::gui::Menu& menu)
{
    menu.IsOpen = !menu.IsOpen;
};

void* sndtram = 0;
void __fastcall hksend(void* hdl, void* edx, void* a1, void* const payload, size_t size)
{
    printf("[0x%p] 0x%p client::send_wrap(0x%p, 0x%X)\n", NtCurrentThreadId(), _ReturnAddress(), payload, size);
	//NtSuspendProcess(NtCurrentProcess());
    reinterpret_cast<void(__thiscall*)(void*, void*, void* const, size_t)>(sndtram)(hdl, a1, payload, size);
};

void neverlose::setup_hooks()
{
    HMODULE WS2 = WaitForSingleModule("ws2_32.dll");
    FARPROC getaddrinfo = GetProcAddress(WS2, "getaddrinfo");
    getaddr_tram = (PBYTE)getaddrinfo + 5;
    HookFn(getaddrinfo, hkgetaddrinfo, 0);

    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

    FARPROC ntterm = GetProcAddress(ntdll, "NtTerminateProcess");
    HookFn(ntterm, hkterm, 0);
    HookFn((PVOID)0x42026080, hkexit, 0);
    
    //FARPROC ntquerkey = GetProcAddress(ntdll, "NtQueryValueKey");
    //quer_tram = GET_DEF_TRAM(ntquerkey);
    //HookFn(ntquerkey, hkNtQueryValueKey, 0, &quer_tram);
    
    HookFn((PVOID)0x4200A118, errhandl, 0);
    HookFn((PVOID)0x415E9086, performmenu, 0);
    HookFn((PVOID)0x41609C80, performmenu, 0);

    HookFn((PVOID)0x41C16EA0, hksend, 0, &sndtram);
};