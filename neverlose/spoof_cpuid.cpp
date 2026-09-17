#include "neverlose.h"
#include "cpuid_emulator.h"
#include "ArenaAllocator.h"
#include "HookFn.h"

void neverlose::spoof_cpuid()
{
	auto logger = ENTER_LOGGER(logman);

	PVOID cpuid_emu = load_res_to_mem(IDR_CPUID_EMU, "cpuid emulator");
	logger << "Loaded CPUID emulator at " << cpuid_emu << '\n';

	ArenaAllocator<cpuid_emu_emplacement> cpuid_emu_arena(g_cpuid_emus.size());

	for (auto& [address, nops] : g_cpuid_emus)
	{
		auto* pcpuid_tramp = cpuid_emu_arena.construct(cpuid_emu);
		NTSTATUS hkstatus = HookFn((PVOID)address, pcpuid_tramp->data, nops, (PVOID*)&pcpuid_tramp->JumpBackAddr, 2);
		if (NT_SUCCESS(hkstatus))
			logger << "Emplaced CPUID emulator at " << (PVOID)address << '\n';
		else
			logger << "Failed to emplace CPUID emulator at " << (PVOID)address << " with status: " << std::hex << hkstatus << std::dec << '\n';
	};

	for (DWORD bp_addr : g_veh_cpuid_emus)
	{
		*(PBYTE)bp_addr = 0xCC;
		*((PBYTE)bp_addr + 1) = 0x58;
	};
};