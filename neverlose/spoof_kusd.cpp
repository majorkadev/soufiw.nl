#include "neverlose.h"
#include "KUSER_SHARED_DATA_SPOOF.h"
#include "ArenaAllocator.h"
#include "HookFn.h"
void neverlose::spoof_kusd()
{
	auto logger = ENTER_LOGGER(logman);

	PVOID kuser = load_res_to_mem(IDR_KUSER_SHARED, "KUSER_SHARED_DATA");
	logger << "Loaded fake KUSER_SHARED_DATA block at " << kuser << '\n';
	ArenaAllocator<kuser_data_spoof> kuser_arena(g_kuser_spoofs.size());

	if (!kuser_arena.has_scene())
		panic("Failed to allocate KUSER_SHARED_DATA spoof arena!");

	for (auto& [address, reg, nops] : g_kuser_spoofs)
	{
		auto* pspoof_block = kuser_arena.construct(reg, kuser);
		NTSTATUS hkstatus = HookFn((PVOID)address, pspoof_block->data, nops, (PVOID*)&pspoof_block->JumpBackAddr);

		// gownocode
		if (address == 0x431CD6B3)
		{
			BYTE* jmphere = (BYTE*)(pspoof_block->JumpBackAddr + 2);
			*(INT32*)(jmphere + 1) = 0x42922E5D - (INT32)jmphere - 5;
		};

		if (NT_SUCCESS(hkstatus))
			logger << "Spoofed KUSER_SHARED_DATA at " << (PVOID)address << '\n';
		else
			logger << "Failed to spoof KUSER_SHARED_DATA at " << (PVOID)address << " with status: " << std::hex << hkstatus << std::dec << '\n';
	};
};