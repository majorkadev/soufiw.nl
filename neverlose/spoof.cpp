#include "neverlose.h"
#include "HookFn.h"
#include <winsock2.h>
#include <vector>
#include "diskpas.h"
#include <iphlpapi.h>
#include <array>
#include <intrin.h>

struct DeviceIoStack
{
    PVOID Retaddr;
    HANDLE FileHandle;
    HANDLE Event;
    PIO_APC_ROUTINE ApcRoutine;
    PVOID ApcContext;
    PIO_STATUS_BLOCK IoStatusBlock;
    ULONG IoControlCode;
    PVOID InputBuffer;
    ULONG InputBufferLength;
    PVOID OutputBuffer;
    ULONG OutputBufferLength;
};

BOOL NTAPI HandleDeviceIo(DeviceIoStack* args)
{
    PVOID pBase = NULL;
    if (RtlPcToFileHeader(args->Retaddr, &pBase) == (PVOID)0x412A0000)
    {
        memcpy(args->OutputBuffer, diskpas_rawData, args->OutputBufferLength);
        printf("Spoofed Disk info!\n");
        return TRUE;
    };
    return FALSE;
};

void* deviceio_tram = nullptr;
NTSTATUS __declspec(naked) NTAPI hkNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
    __asm
    {
        push ebp
        mov ebp, esp
        lea eax, [ebp + 4]
        push eax
        call HandleDeviceIo
        test eax, eax
        mov esp, ebp
        pop ebp
        je callog
        ret 0x28
        callog:
        mov eax, 0x001B0007
        jmp deviceio_tram
    };
};

void* vertram = 0;
NTSTATUS NTAPI hkRtlGetVersion(PRTL_OSVERSIONINFOW VersionInformation)
{
    PVOID pBase = NULL;
    if (RtlPcToFileHeader(_ReturnAddress(), &pBase) == (PVOID)0x412A0000 && _ReturnAddress() != (PVOID)0x44791149 && _ReturnAddress() != (PVOID)0x44791216)
    {
        VersionInformation->dwOSVersionInfoSize = 0;
        VersionInformation->dwMajorVersion = 0xA;
        VersionInformation->dwMinorVersion = 0;
        VersionInformation->dwBuildNumber = 0x00005867;
        VersionInformation->dwPlatformId = 0x2;
        memset(VersionInformation->szCSDVersion, 0, sizeof(VersionInformation->szCSDVersion));
        printf("[0x%p] 0x%p spoofed RtlGetVersion!\n", NtCurrentThreadId(), _ReturnAddress());
        return STATUS_SUCCESS;
    };
    return reinterpret_cast<decltype(&RtlGetVersion)>(vertram)(VersionInformation);
};

/*
A067DC37
xFF
03E72EFF
NTFS
*/

const BYTE volname[] =
{
    0x20, 0x81, 0x24, 0x60, 0xA8, 0xFF, 0x32,
    0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x20, 0x81, 0x24, 0x60,
    0xA8, 0xFF, 0x32, 0x3B, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
    0x81, 0x24, 0x60, 0xA8, 0xFF, 0x32, 0x3B,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xC0, 0x03, 0x00, 0x00, 0x1C,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
    0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
void* kbasevw = 0;
BOOL WINAPI hkGetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags,
    PWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{

    //printf("[0x%p] 0x%p GetVolumeInformationW\n", NtCurrentThreadId(), _ReturnAddress());
    if (_ReturnAddress() == (PVOID)0x415E8828)
    {
        size_t copy = nVolumeNameSize < sizeof(volname) ? nVolumeNameSize : sizeof(volname);
        memcpy(lpVolumeNameBuffer, volname, copy);
        wcscpy_s(lpFileSystemNameBuffer, nFileSystemNameSize, L"NTFS");
        *lpVolumeSerialNumber = 0xA067DC37;
        *lpMaximumComponentLength = 0xFF;
        *lpFileSystemFlags = 0x03E72EFF;
        return TRUE;
    };
    return reinterpret_cast<decltype(&GetVolumeInformationW)>(kbasevw)(lpRootPathName, lpVolumeNameBuffer,
        nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
};

struct adapter_t
{
    const char* Name;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
};

constexpr auto g_spoofed_adapters = std::to_array<adapter_t>
({
    { "{8AD76F14-7DA1-4786-9706-2A3E545BCADD}", { 0xD8, 0x43, 0xAE, 0x96, 0x4E, 0xD8, 0x00, 0x00 } },
    { "{D584346C-AF4E-47CC-B402-B9FB34A569BC}", { 0x7A, 0x79, 0x19, 0x12, 0x93, 0xC3, 0x00, 0x00 } },
    { "{88A9926E-8033-4628-9A18-C20AB9B2A574}", { 0x2C, 0x98, 0x11, 0x1A, 0xD2, 0x24, 0x00, 0x00 } },
    { "{44E3B917-A89B-48C5-B871-B72158E6A845}", { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { "{A06F2639-34F6-4DBB-B736-5C8CB14D3B10}", { 0x2C, 0x98, 0x11, 0x1A, 0xD2, 0x23, 0x00, 0x00 } },
    { "{423DC722-6046-4D7E-93A1-619D9663BEE2}", { 0x2E, 0x98, 0x11, 0x1A, 0xF2, 0x03, 0x00, 0x00 } },
    { "{30604C72-5277-49DB-ADF2-4F8F1AC4A893}", { 0x2E, 0x98, 0x11, 0x1A, 0xE2, 0x13, 0x00, 0x00 } },
    });

void* adapterstram = 0;
ULONG WINAPI hkGetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
    PVOID pBase = NULL;
    if (RtlPcToFileHeader(_ReturnAddress(), &pBase) == (PVOID)0x412A0000)
    {
        printf("[0x%p] 0x%p GetAdaptersInfo\n", NtCurrentThreadId(), _ReturnAddress());
        if (*SizePointer < sizeof(IP_ADAPTER_INFO) * 7)
        {
            *SizePointer = sizeof(IP_ADAPTER_INFO) * 7;
            return ERROR_BUFFER_OVERFLOW;
        };
        memset(AdapterInfo, 0, sizeof(IP_ADAPTER_INFO) * 7);
        for (size_t i = 0; i < g_spoofed_adapters.size(); i++)
        {
            if (i == g_spoofed_adapters.size() - 1)
                AdapterInfo[i].Next = NULL;
            else
                AdapterInfo[i].Next = &AdapterInfo[i + 1];

            AdapterInfo[i].ComboIndex = 0;
            AdapterInfo[i].Index = i + 1;
            AdapterInfo[i].Type = MIB_IF_TYPE_ETHERNET;
            AdapterInfo[i].DhcpEnabled = FALSE;
            AdapterInfo[i].HaveWins = FALSE;
            AdapterInfo[i].AddressLength = 6;

            strcpy(AdapterInfo[i].Description, "Intel(R) Ethernet Connection");
            strcpy(AdapterInfo[i].IpAddressList.IpAddress.String, "192.168.0.1");
            strcpy(AdapterInfo[i].IpAddressList.IpMask.String, "255.255.255.0");
            strcpy(AdapterInfo[i].AdapterName, g_spoofed_adapters[i].Name);
            memcpy(AdapterInfo[i].Address, g_spoofed_adapters[i].Address, MAX_ADAPTER_ADDRESS_LENGTH);
        };

        return ERROR_SUCCESS;
    };

    return reinterpret_cast<decltype(&GetAdaptersInfo)>(adapterstram)(AdapterInfo, SizePointer);
};

void neverlose::spoof()
{

    HookFn(GetProcAddress(GetModuleHandle(L"iphlpapi.dll"), "GetAdaptersInfo"), hkGetAdaptersInfo, 0, &adapterstram);

    HMODULE ndtll = GetModuleHandle(L"ntdll.dll");
    FARPROC ntdevicefile = GetProcAddress(ndtll, "NtDeviceIoControlFile");
    deviceio_tram = GET_DEF_TRAM(ntdevicefile);
    HookFn(ntdevicefile, hkNtDeviceIoControlFile, 0);

    FARPROC ntterm = GetProcAddress(ndtll, "NtTerminateProcess");

    FARPROC getver = GetProcAddress(ndtll, "RtlGetVersion");
    HookFn(getver, hkRtlGetVersion, 0, &vertram);

    kbasevw = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "GetVolumeInformationW");
    HookFn(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetVolumeInformationW"), hkGetVolumeInformationW, 0);
};