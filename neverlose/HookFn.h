#ifndef NEVERLOSE_HOOKFN_H
#define NEVERLOSE_HOOKFN_H
#include <phnt_windows.h>
#include <phnt.h>

#define GET_DEF_TRAM(addr) ((char*)addr + 0x5);

NTSTATUS HookFn(void* Dst, void* Src, SIZE_T NopBytes, void** TrampOut = NULL, size_t TrampOffset = 0);

#endif // NEVERLOSE_HOOKFN_H