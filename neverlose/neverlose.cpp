#include "neverlose.h"

void neverlose::panic(const char* fmt, ...)
{
	char buffer[1024];

	va_list va;
	va_start(va, fmt);
	vsprintf(buffer, fmt, va);
	va_end(va);

	MessageBoxA(0, buffer, 0, MB_ICONERROR);
	NtTerminateProcess(NtCurrentProcess(), STATUS_UNSUCCESSFUL);
};

void neverlose::map(HMODULE hModule)
{
	hThis = hModule;
	HRSRC hRes = FindResource(hThis, MAKEINTRESOURCE(IDR_BINARY), L"BINARY");

	if (!hRes)
		panic("Failed to locate cheat binary!");

	HGLOBAL hResData = LoadResource(hThis, hRes);

	if (!hResData)
		panic("Failed to load cheat binary!");

	LPVOID pData = LockResource(hResData);

	if (!pData)
		panic("Failed to lock cheat binary!");

	DWORD Size = SizeofResource(hThis, hRes);

	// Stupid fallback?
	if (Size)
		imageSize = Size;

	if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddr, NULL, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		panic("Failed to allocate cheat base!");

	ENTER_LOGGER(logman) << "Allocated cheat base at " << baseAddr << '\n';

	if (!NT_SUCCESS(NtWriteVirtualMemory(NtCurrentProcess(), baseAddr, pData, imageSize, NULL)))
		panic("Failed to write cheat image!");
};

PVOID neverlose::load_res_to_mem(int idr, const char* rcname) const
{
	HRSRC hRes = FindResource(hThis, MAKEINTRESOURCE(idr), L"BINARY");

	if (!hRes)
		panic("Failed to find %s binary!", rcname);

	HGLOBAL hResData = LoadResource(hThis, hRes);

	if (!hResData)
		panic("Failed to load %s binary!", rcname);

	LPVOID pData = LockResource(hResData);

	if (!pData)
		panic("Failed to lock %s binary!", rcname);

	DWORD Size = SizeofResource(hThis, hRes);

	PVOID addr = NULL;
	SIZE_T size = Size;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		panic("Failed to allocate %s image!", rcname);

	if (!NT_SUCCESS(NtWriteVirtualMemory(NtCurrentProcess(), addr, pData, Size, NULL)))
		panic("Failed to write %s image!", rcname);

	return addr;
};