#ifndef NEVERLOSE_KUSER_SHARED_DATA_SPOOF_H
#define NEVERLOSE_KUSER_SHARED_DATA_SPOOF_H
#include <array>
#include "REGS.h"

struct kuser_data_spoof_info
{
	uintptr_t address;
	REG reg;
	size_t nops;
};

constexpr auto g_kuser_spoofs = std::to_array<kuser_data_spoof_info>
({
	{ 0x42E1614F, REG::EAX, 2 },
	{ 0x4292094C, REG::EAX, 3 },
	{ 0x4279B4B0, REG::EAX, 2 },
	{ 0x4282E5B6, REG::EAX, 6 },
	{ 0x4278815E, REG::ECX, 2 },
	{ 0x42B15516, REG::ECX, 3 },
	{ 0x434C48EF, REG::ECX, 2 },
	{ 0x42AB63D3, REG::EDX, 2 },
	{ 0x431CD6B3, REG::EDX, 2 },
});

constexpr BYTE DEF_KUSER_SPOOF[] =
{
	// cmp reg, 7FFE0000h
	0x81, 0xCC, 0x00, 0x00, 0xFE, 0x7F,
	// jb +18h
	0x0F, 0x82, 0x18, 0x00, 0x00, 0x00,
	// cmp reg, 7FFE1000h
	0x81, 0xCC, 0x00, 0x10, 0xFE, 0x7F,
	// ja +0Ch
	0x0F, 0x87, 0x0C, 0x00, 0x00, 0x00,
	// sub reg, 7FFE0000h
	0x81, 0xCC, 0x00, 0x00, 0xFE, 0x7F,
	// add reg, spoof
	0x81, 0xCC, 0x00, 0x00, 0x00, 0x00,
	// jmp [var]
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
	// pad
	0x00, 0x00, 0x00, 0x00,
	// var
	0x00, 0x00, 0x00, 0x00
};

#pragma pack(push, 1)
struct kuser_data_spoof
{
	union
	{
		BYTE data[50];
		struct
		{
			BYTE Reserved0;
			BYTE RegCmp0;
			DWORD Comperand0;
			BYTE Jump0[6];
			BYTE Reserved1;
			BYTE RegCmp1;
			DWORD Comperand1;
			BYTE Jump1[6];
			BYTE Reserved2;
			BYTE RegSub;
			DWORD Substacted;
			BYTE Reserved3;
			BYTE RegAdd;
			DWORD Added;
			BYTE JmpOpcode[2];
			DWORD JmpBackVarAddr;
			BYTE Pad[4];
			DWORD JumpBackAddr;
		};
	};

	kuser_data_spoof(REG reg, PVOID spoofed_addr)
	{
		memcpy(data, DEF_KUSER_SPOOF, 50);

		BYTE r = static_cast<BYTE>(reg);

		RegCmp0 = static_cast<BYTE>(0xF8 | r);
		RegCmp1 = static_cast<BYTE>(0xF8 | r);
		RegSub = static_cast<BYTE>(0xE8 | r);
		RegAdd = static_cast<BYTE>(0xC0 | r);

		Added = (DWORD)spoofed_addr;
		JmpBackVarAddr = (DWORD)&JumpBackAddr;
	};
};
#pragma pack(pop)

#endif // NEVERLOSE_KUSER_SHARED_DATA_SPOOF_H