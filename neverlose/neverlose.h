#ifndef NEVERLOSE_NEVERLOSE_H
#define NEVERLOSE_NEVERLOSE_H
#define PHNT_VERSION PHNT_WINDOWS_10
#include <phnt_windows.h>
#include <phnt.h>
#include "logger.h"
#include "resource.h"
#include <array>

class neverlose
{
	PVOID load_res_to_mem(int idr, const char* rcname) const;
	[[noreturn]] static void panic(const char* fmt, ...);

	neverlose(const neverlose&) = delete;
	neverlose(neverlose&&) = delete;
	neverlose& operator=(const neverlose&) = delete;

	void fix_imports();
	void spoof_peb();
	void spoof_cpuid();
	void spoof_kusd();
	void fix_interfaces();
	void fix_cvars();
	void fix_signatures();
public:
	neverlose() : baseAddr((PVOID)0x412A0000), imageSize(0x3501000), logman(), hThis(nullptr) {};
	void map(HMODULE hThis);
	void fix_dump();
	void spoof();
	void setup_hooks();
	void entry();
	void set_veh();
	bool in_range(void* addr) const { return addr >= baseAddr && addr < ((char*)baseAddr + imageSize); };
	void* base() const { return baseAddr; };
private:
	PVOID baseAddr;
	SIZE_T imageSize;
	clog_manager logman;
	HINSTANCE hThis;
};

inline neverlose g_neverlose;

#endif // NEVERLOSE_NEVERLOSE_H