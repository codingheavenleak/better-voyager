#pragma once

#include "Utils.h"
#include "PagingTables.h"
#include <Library/ShellLib.h>

// Macro to get NT headers from a PE image
#define NT_HEADER(x) ((EFI_IMAGE_NT_HEADERS64*)(((UINT64)(x)) + ((EFI_IMAGE_DOS_HEADER*)(x))->e_lfanew))

// Section characteristics for Read-Write-Execute permissions
#if WINVER == 2302
#define SECTION _RWX(EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_MEM_EXECUTE)
#else
#define SECTION_RWX (EFI_IMAGE_SCN_MEM_WRITE | \
                     EFI_IMAGE_SCN_CNT_CODE | \
                     EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA | \
                     EFI_IMAGE_SCN_MEM_EXECUTE | \
                     EFI_IMAGE_SCN_CNT_INITIALIZED_DATA | \
                     EFI_IMAGE_SCN_MEM_READ)
#endif
// Alignment macros (align must be a power of 2)
// Align x down to the nearest multiple of align
#define P2ALIGNDOWN(x, align) ((x) & -(align))
// Align x up to the nearest multiple of align
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

// External declaration for PayLoad
extern VOID* PayLoad;

// Structure definition for Scyvisor
#pragma pack(push, 1)
typedef struct _SCYVISOR_T
{
    UINT64 VmExitHandlerRva;
    UINT64 HypervModuleBase;
    UINT64 HypervModuleSize;
    UINT64 ModuleBase;
    UINT64 ModuleSize;
    UINT32 VmcbBase;
    UINT32 VmcbLink;
    UINT32 VmcbOff;
} Scyvisor_T, * PSCYVISOR_T;
#pragma pack(pop)

// File path definitions
#define WINDOWS_BOOTMGFW_PATH L"\\efi\\microsoft\\boot\\bootmgfw.efi"

// Function prototypes
UINT32 PayLoadSize(VOID);
VOID* PayLoadEntry(VOID* ModuleBase);
VOID* AddSection(VOID* ImageBase, CHAR8* SectionName, UINT32 VirtualSize, UINT32 Characteristics);