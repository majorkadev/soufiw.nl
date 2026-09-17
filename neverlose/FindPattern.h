#ifndef NEVERLOSE_FIND_PATTERN_H
#define NEVERLOSE_FIND_PATTERN_H
#include <phnt_windows.h>
#include <phnt.h>

#define PATTERN(signature) signature, sizeof(signature)-1

void generate_shift_table(BYTE out[256], const PBYTE pattern, size_t pattern_len, BYTE wild_card);

void* FindPattern(void* base, size_t scan_size, const PBYTE pattern, size_t pattern_len, BYTE wild_card, size_t offset);

#endif // NEVERLOSE_FIND_PATTERN_H