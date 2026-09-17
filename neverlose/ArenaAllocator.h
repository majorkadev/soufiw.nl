#ifndef NEVERLOSE_ARENA_ALLOCATOR_H
#define NEVERLOSE_ARENA_ALLOCATOR_H
#include <phnt_windows.h>
#include <phnt.h>
#include <utility>

template<typename T>
class ArenaAllocator
{
	using type = T;
	using pointer = T*;
	using reference = T&;
	using size_type = SIZE_T;

	size_type capacity;
	size_type cursor;
	size_type allocation_size;
	PVOID arena;
public:
	ArenaAllocator(size_t initial_capacity) : capacity(initial_capacity), cursor(0), allocation_size(0), arena(nullptr)
	{
		SIZE_T Size = initial_capacity * sizeof(type);
		PVOID Addr = NULL;

		if (NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &Addr, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		{
			arena = Addr;
			allocation_size = Size;
		};
	};

	//~ArenaAllocator()
	//{
	//	for (size_t i = 0; i < cursor; i++)
	//		((pointer)arena)[i].~T();
	//
	//	NtFreeVirtualMemory(NtCurrentProcess(), &arena, &allocation_size, MEM_RELEASE);
	//};

	bool has_scene() const { return arena != NULL && allocation_size > 0; };

	template<typename ...Args>
	pointer construct(Args&&... args)
	{
		pointer cobj = &((pointer)arena)[cursor++];

		new (cobj) type(std::forward<Args>(args)...);
		return cobj;
	};
};

#endif // NEVERLOSE_ARENA_ALLOCATOR_H