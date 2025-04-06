#pragma once
#include <windows.h>
#include "libScyHV.hpp"

//defs
#define PAGE_SIZE 4096
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// structs
typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, * PPHYSICAL_MEMORY_RANGE;

// glbals
extern void* g_mmonp_MmPfnDatabase;

//funcs
NTSTATUS InitializeMmPfnDatabase(ScyVDM::cVDM& vdm);
PVOID MmGetVirtualForPhysical(ScyVDM::cVDM& vdm, PHYSICAL_ADDRESS PhysicalAddress);
PHYSICAL_MEMORY_RANGE* MmGetPhysicalMemoryRanges(ScyVDM::cVDM& vdm);

//Helper

// Makros
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

// Typedefinitions
using MmGetVirtualForPhysical_t = PVOID(*)(PHYSICAL_ADDRESS PhysicalAddress);
using MmGetPhysicalMemoryRanges_t = PHYSICAL_MEMORY_RANGE * (*)();
