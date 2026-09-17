#include "ServerLauncher.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <thread>
#include <chrono>

static LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");

static void RestoreNtOpenFile(HANDLE hProcess)
{
    if (!ntOpenFile)
        return;

    char originalBytes[5];
    memcpy(originalBytes, ntOpenFile, 5);
    WriteProcessMemory(hProcess, ntOpenFile, originalBytes, 5, NULL);
    printf("[+] NtOpenFile restored in target\n");
}

int main()
{
    const char* lpDLLName = "neverlose.dll";
    char lpFullDLLPath[MAX_PATH];

    SetConsoleTitleA("neverlose injector");
    printf("Place neverlose.dll next to this injector.\n");

    ServerLauncher::EnsureServerRunning();

    printf("Waiting for CS:GO...\n");

    HWND window = nullptr;
    DWORD dwProcessID = 0;

    while (!window)
    {
        window = FindWindowA("Valve001", nullptr);
        if (window)
        {
            GetWindowThreadProcessId(window, &dwProcessID);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    printf("[+] Found CS:GO (PID: %lu)\n", dwProcessID);

    if (!GetFullPathNameA(lpDLLName, MAX_PATH, lpFullDLLPath, nullptr))
    {
        printf("[-] Failed to resolve DLL path.\n");
        return 1;
    }

    printf("[+] DLL: %s\n", lpFullDLLPath);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
    {
        printf("[-] Failed to open process. Run as administrator.\n");
        return 1;
    }

    RestoreNtOpenFile(hProcess);

    SIZE_T pathLen = lstrlenA(lpFullDLLPath) + 1;
    LPVOID allocatedMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMem)
    {
        printf("[-] VirtualAllocEx failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Allocated memory at 0x%p\n", allocatedMem);

    if (!WriteProcessMemory(hProcess, allocatedMem, lpFullDLLPath, pathLen, NULL))
    {
        printf("[-] WriteProcessMemory failed.\n");
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    FARPROC lpLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!lpLoadLibrary)
    {
        printf("[-] Failed to find LoadLibraryA.\n");
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] LoadLibraryA at 0x%p\n", (void*)lpLoadLibrary);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lpLoadLibrary, allocatedMem, 0, nullptr);
    if (!hThread || hThread == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateRemoteThread failed.\n");
        VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Remote thread created. Injecting...\n");
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocatedMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("[+] Injected successfully.\n");
    return 0;
}
