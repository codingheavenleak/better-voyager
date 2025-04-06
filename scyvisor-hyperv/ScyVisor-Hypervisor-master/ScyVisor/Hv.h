#pragma once
#include "PayLoad.h"

extern PSCYVISOR_T PayLoadDataPtr;
#if WINVER == 2302  
// Search for 0F 01 C3 (VMRESUME)  
// Check the function before – it often contains VMRUN, VMSAVE, or WRMSR.  
// If VMRESUME fails, there is usually a jump to an error handler (JMP or CALL).


#define INTEL_VMEXIT_HANDLER_SIG "\xFB\x8B\xD6\x0B\x54\x24\x30\xE8\x00\x00\x00\x00\xE9"
#define INTEL_VMEXIT_HANDLER_MASK "xxxxxxxx????x"
#else
#define INTEL_VMEXIT_HANDLER_SIG "\x65\xC6\x04\x25\x6D\x00\x00\x00\x00\x48\x8B\x4C\x24\x00\x48\x8B\x54\x24\x00\xE8\x00\x00\x00\x00\xE9"
#define INTEL_VMEXIT_HANDLER_MASK "xxxxxxxxxxxxx?xxxx?x????x"
#endif


//need testing on AMD windows 11 build 24H2 \\ to find the correct function sigscan for 0f 01 d8 (vmrun)
#define AMD_VMEXIT_HANDLER_SIG "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9"
#define AMD_VMEXIT_HANDLER_MASK "x????xxxxx"

#define AMD_VMCB_HANDLER_SIG "\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x81\x00\x00\x00\x00\x48\x8B\x88"
#define AMD_VMCB_HANDLER_MASK "xxxxx????xxx????xxx????xxx"

static_assert(sizeof(AMD_VMEXIT_HANDLER_SIG) == sizeof(AMD_VMEXIT_HANDLER_MASK), "signature does not match mask size!");
static_assert(sizeof(AMD_VMCB_HANDLER_SIG) == sizeof(AMD_VMCB_HANDLER_MASK), "signature does not match mask size!");
static_assert(sizeof(INTEL_VMEXIT_HANDLER_SIG) == sizeof(INTEL_VMEXIT_HANDLER_MASK), "signature does not match mask size!");

#define HV_ALLOC_SIZE 0x1900000
/// <summary>
/// manually map module into hyper-v's extended relocation section...
/// </summary>
/// <param name="ScyvisorData">all the data needed to map the module...</param>
/// <param name="ImageBase">base address of the payload...</param>
/// <returns></returns>
VOID* MapModule(PSCYVISOR_T ScyvisorData, UINT8* ImageBase);

/// <summary>
/// hook vmexit handler...
/// </summary>
/// <param name="HypervBase">base address of hyper-v</param>
/// <param name="HypervSize">hyper-v size (SizeOfImage in memory)</param>
/// <param name="VmExitHook">vmexit hook function address (where to jump too)</param>
/// <returns></returns>
VOID* HookVmExit(VOID* HypervBase, VOID* HypervSize, VOID* VmExitHook);

/// <summary>
/// populates a Scyvisor_T structure passed by reference...
/// </summary>
/// <param name="ScyvisorData">pass by ref Scyvisor_T...</param>
/// <param name="HypervAlloc">hyper-v module base...</param>
/// <param name="HypervAllocSize">hyper-v module size...</param>
/// <param name="PayLoadBase">payload base address...</param>
/// <param name="PayLoadSize">payload module size...</param>
VOID MakeScyvisorData
(
	PSCYVISOR_T ScyvisorData,
	VOID* HypervAlloc,
	UINT64 HypervAllocSize,
	VOID* PayLoadBase,
	UINT64 PayLoadSize
);