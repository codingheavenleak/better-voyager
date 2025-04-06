#pragma once
#include "globals.h"

#define PORT_COM1 0x3F8
#define PORT_COM2 0x2F8
#define PORT_COM3 0x3E8
#define BAUD_RATE 115200

#define BL_MEMORY_ATTRIBUTE_RWX 0x424000
#define BL_MEMORY_TYPE_APPLICATION 0xE0000012
#define SEC_TO_MS(seconds) seconds * 1000000
#define SECTION_RWX (EFI_IMAGE_SCN_MEM_READ | EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_MEM_EXECUTE)
#define SECTION_NAME "pUGN"

#define RtlZeroMemory(Destination,Length) memset((Destination),0,(Length))

void __outdword(unsigned short, unsigned long);
VOID __outbytestring(UINT16 Port, UINT8* Buffer, UINT32 Count);
void __outbyte(unsigned short Port, unsigned char Data);
#pragma intrinsic(__outbytestring)
#pragma intrinsic(__outbyte)

unsigned char __inbyte(unsigned short Port);

static CHAR8 dbg_buffer[0x100];
#define DBG_PRINT(...) \
	AsciiSPrint(dbg_buffer, sizeof dbg_buffer, __VA_ARGS__); \
	__outbytestring(PORT_COM1, dbg_buffer, AsciiStrLen(dbg_buffer))

#define RESOLVE_RVA(SIG_RESULT, RIP_OFFSET, RVA_OFFSET) \
	(*(INT32*)(((UINT64)SIG_RESULT) + RVA_OFFSET)) + ((UINT64)SIG_RESULT) + RIP_OFFSET

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;	// 16
	LIST_ENTRY InMemoryOrderLinks;	// 32
	LIST_ENTRY InInitializationOrderLinks; // 48
	UINT64 ModuleBase; // 56
	UINT64 EntryPoint; // 64
	UINTN SizeOfImage; // 72
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY, **PPLDR_DATA_TABLE_ENTRY;

// taken from umap (btbd)
BOOLEAN CheckMask(CHAR8* base, CHAR8* pattern, CHAR8* mask);
UINT32 GetPeFileImageSize(VOID* InPePtr);
VOID* FindPattern(CHAR8* base, UINTN size, CHAR8* pattern, CHAR8* mask);
VOID* GetExport(UINT8* base, CHAR8* export);
VOID MemCopy(VOID* dest, VOID* src, UINTN size);
VOID* MemSet(VOID* dest, int val, UINT32 len);
EFI_IMAGE_NT_HEADERS64* GetPeFileHeader(VOID* InPePtr);
EFI_IMAGE_SECTION_HEADER* GetPeFirstSection(VOID* PePtr);
VOID FixRelocImage(VOID* PeMemPtr);
VOID* GetExportByIndex(UINT8* ModuleBase, UINT16 Index);
VOID MapPeSection(VOID* PeFilePtr, VOID* PeMemPtr);
VOID Sleep(const UINTN seconds);


typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, * PCPUID;

__forceinline int MemCmp(const void* s1, const void* s2, UINT32 n)
{
    const unsigned char* p1 = s1;
    const unsigned char* end1 = p1 + n;
    const unsigned char* p2 = s2;
    int d = 0;
    for (;;)
    {
        if (d || p1 >= end1)
            break;

        d = (int)*p1++ - (int)*p2++;
        if (d || p1 >= end1)
            break;

        d = (int)*p1++ - (int)*p2++;
        if (d || p1 >= end1)
            break;

        d = (int)*p1++ - (int)*p2++;
        if (d || p1 >= end1)
            break;

        d = (int)*p1++ - (int)*p2++;
    }
    return d;
}

__forceinline UINT32 GetCPUVendor()
{
    CPUID data = { 0 };
    char vendor[0x20] = { 0 };
    __cpuid((int*)&data, 0);
    *(int*)(vendor) = data.ebx;
    *(int*)(vendor + 4) = data.edx;
    *(int*)(vendor + 8) = data.ecx;

    if (MemCmp(vendor, "GenuineIntel", 12) == 0)
        return 1;
    if (MemCmp(vendor, "AuthenticAMD", 12) == 0)
        return 2;

    return 0;
}
