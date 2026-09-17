#include "neverlose.h"
#include "ServerLauncher.h"

NTSTATUS NTAPI MainThread(LPVOID lpThreadParameter)
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	printf("[+] MainThread started (hModule=0x%p)\n", lpThreadParameter);
	fflush(stdout);

	ServerLauncher::EnsureServerRunning();

	printf("[*] Calling map()...\n"); fflush(stdout);
	g_neverlose.map((HMODULE)lpThreadParameter);
	printf("[+] map() done (base=0x%p)\n", g_neverlose.base()); fflush(stdout);

	printf("[*] Waiting for serverbrowser.dll...\n"); fflush(stdout);
	while (!GetModuleHandleW(L"serverbrowser.dll"))
		Sleep(100);
	printf("[+] serverbrowser.dll loaded\n"); fflush(stdout);

	printf("[*] Calling fix_dump()...\n"); fflush(stdout);
	g_neverlose.fix_dump();
	printf("[+] fix_dump() done\n"); fflush(stdout);

	printf("[*] Calling set_veh()...\n"); fflush(stdout);
	g_neverlose.set_veh();
	printf("[+] set_veh() done\n"); fflush(stdout);

	printf("[*] Calling setup_hooks()...\n"); fflush(stdout);
	g_neverlose.setup_hooks();
	printf("[+] setup_hooks() done\n"); fflush(stdout);

	printf("[*] Calling spoof()...\n"); fflush(stdout);
	g_neverlose.spoof();
	printf("[+] spoof() done\n"); fflush(stdout);

	printf("[+] All init done. Automatically calling entry()...\n"); fflush(stdout);
	Sleep(100);

	printf("[*] Calling entry()...\n"); fflush(stdout);
	g_neverlose.entry();
	printf("[+] entry() returned\n"); fflush(stdout);

	return STATUS_SUCCESS;
};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		OutputDebugStringA("[neverlose] DllMain: DLL_PROCESS_ATTACH\n");
		HANDLE hThread;
		NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), MainThread, hinstDLL, THREAD_CREATE_FLAGS_NONE, 0, 0, 0, NULL);
		if (NT_SUCCESS(status))
		{
			OutputDebugStringA("[neverlose] DllMain: thread created OK\n");
			NtClose(hThread);
		}
		else
		{
			char buf[128];
			sprintf(buf, "[neverlose] DllMain: NtCreateThreadEx FAILED (0x%08lX)\n", status);
			OutputDebugStringA(buf);
			return FALSE;
		}
	};

	return TRUE;
};