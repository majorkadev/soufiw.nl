#include "FindPattern.h"

void generate_shift_table(BYTE out[256], const PBYTE pattern, size_t pattern_len, BYTE wild_card)
{
	size_t i = pattern_len;

	for (; i; i--)
		if (pattern[i] == wild_card) break;

	size_t max_shift = pattern_len - i;
	if (pattern_len == i)
		max_shift = 1;

	memset(out, max_shift, 256);

	for (size_t j = pattern_len - max_shift; j < pattern_len; j++)
		out[pattern[j]] = pattern_len - j;
};

void* FindPattern(void* base, size_t scan_size, const PBYTE pattern, size_t pattern_len, BYTE wild_card, size_t offset)
{
	BYTE shift_table[256];

	pattern_len -= 1;

	generate_shift_table(shift_table, pattern, pattern_len, (BYTE)wild_card);

	PBYTE  cursor = (PBYTE)base;
	PBYTE  bound = cursor + scan_size - pattern_len;
	while (cursor <= bound)
	{
		size_t i = pattern_len;
		while (true)
		{
			if (pattern[i] != wild_card && cursor[i] != pattern[i])
			{
				cursor += shift_table[cursor[pattern_len]];
				break;
			};

			if (!i) return cursor + offset;
			i--;
		};
	};
	return nullptr;
};