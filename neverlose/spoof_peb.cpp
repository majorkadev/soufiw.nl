#include "neverlose.h"
#include "PEB_SPOOF.h"
#include "ArenaAllocator.h"
#include "HookFn.h"

void neverlose::spoof_peb()
{
	auto logger = ENTER_LOGGER(logman);

	PVOID fake_peb = NULL;
	SIZE_T fake_peb_size = 0x1000;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &fake_peb, 0, &fake_peb_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		panic("Failed to allocate fake PEB!");

	*((BYTE*)fake_peb + 0xA8) = 0x20;

	logger << "Allocated fake PEB at " << fake_peb << '\n';

	ArenaAllocator<peb_spoof> peb_spoof_arena(g_peb_spoofs.size());

	for (auto& [address, reg] : g_peb_spoofs)
	{
		auto* ppeb_spoof_tram = peb_spoof_arena.construct(fake_peb, reg);
		size_t beyond_bytes = reg == REG::EAX ? 1 : 2;
		NTSTATUS hkstatus = HookFn((PVOID)address, ppeb_spoof_tram->data, beyond_bytes, (PVOID*)&ppeb_spoof_tram->JumpBackAddr, 5 + beyond_bytes);
		if (NT_SUCCESS(hkstatus))
			logger << "Spoofed PEB at " << (PVOID)address << '\n';
		else
			logger << "Failed to spoof PEB at " << (PVOID)address << " with status: " << std::hex << hkstatus << std::dec << '\n';
	};
};
