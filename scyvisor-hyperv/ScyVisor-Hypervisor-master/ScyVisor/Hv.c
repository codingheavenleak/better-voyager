#include "Hv.h"
#include "PayloadBytes.h"

PSCYVISOR_T PayLoadDataPtr = NULL;


VOID MakeScyvisorData(PSCYVISOR_T ScyvisorData, VOID* HypervAlloc, UINT64 HypervAllocSize, VOID* PayLoadBase, UINT64 PayLoadSize)
{
    if (!ScyvisorData || !HypervAlloc || !PayLoadBase) return;

    ScyvisorData->HypervModuleBase = (UINT64)HypervAlloc;
    ScyvisorData->HypervModuleSize = HypervAllocSize;
    ScyvisorData->ModuleBase = (UINT64)PayLoadBase;
    ScyvisorData->ModuleSize = PayLoadSize;

    VOID* Handler = FindPattern(HypervAlloc, HypervAllocSize, INTEL_VMEXIT_HANDLER_SIG, INTEL_VMEXIT_HANDLER_MASK);
    UINT64 HandlerCall, HandlerCallRip, HandlerFunc;

    if (Handler) // Intel
    {
#if WINVER == 2302
        HandlerCall = (UINT64)Handler + 7;
#else
        HandlerCall = (UINT64)Handler + 19;
#endif
        HandlerCallRip = HandlerCall + 5;
        HandlerFunc = HandlerCallRip + *(INT32*)(HandlerCall + 1);
    }
    else // AMD
    {
        Handler = FindPattern(HypervAlloc, HypervAllocSize, (VOID*)AMD_VMEXIT_HANDLER_SIG, (VOID*)AMD_VMEXIT_HANDLER_MASK);
        if (!Handler) return;

        HandlerCallRip = (UINT64)Handler + 5;
        HandlerFunc = HandlerCallRip + *(INT32*)((UINT64)Handler + 1);

        //UINT64 VmcbAddr = FindPattern(HypervAlloc, HypervAllocSize, (VOID*)AMD_VMCB_HANDLER_SIG, (VOID*)AMD_VMCB_HANDLER_MASK);
        //if (VmcbAddr)
        //{
        //    VmcbAddr += 5;
        //    ScyvisorData->VmcbBase = *(UINT32*)VmcbAddr;
        //    ScyvisorData->VmcbLink = *(UINT32*)(VmcbAddr + 7);
        //    ScyvisorData->VmcbOff = *(UINT32*)(VmcbAddr + 14);
        //}
    }

    ScyvisorData->VmExitHandlerRva = ((UINT64)PayLoadEntry(PayLoadBase)) - HandlerFunc;
}

VOID* MapModule(PSCYVISOR_T ScyvisorData, UINT8* ImageBase)
{
    if (!ScyvisorData || !ImageBase) return NULL;

    EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)ImageBase;
    if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE) return NULL;

    EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(ImageBase + dosHeaders->e_lfanew);
    EFI_IMAGE_NT_HEADERS64* ntHeadersNew = (EFI_IMAGE_NT_HEADERS64*)(ScyvisorData->ModuleBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != EFI_IMAGE_NT_SIGNATURE) return NULL;

    MemCopy(ScyvisorData->ModuleBase, ImageBase, ntHeaders->OptionalHeader.SizeOfHeaders);

    EFI_IMAGE_SECTION_HEADER* sections = (EFI_IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
    UINT64 totSize = 0;
    for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        EFI_IMAGE_SECTION_HEADER* section = &sections[i];
        if (section->SizeOfRawData)
        {
            MemCopy(ScyvisorData->ModuleBase + section->VirtualAddress,
                ImageBase + section->PointerToRawData,
                section->SizeOfRawData);
            totSize += section->SizeOfRawData;
        }
    }

    secure_zero_memory(ImageBase, totSize + ntHeaders->OptionalHeader.SizeOfHeaders);
    secure_zero_memory(AmdPayload, sizeof(AmdPayload));
    secure_zero_memory(IntelPayload, sizeof(IntelPayload));

    EFI_IMAGE_EXPORT_DIRECTORY* ExpDir = (EFI_IMAGE_EXPORT_DIRECTORY*)(
        ScyvisorData->ModuleBase + ntHeadersNew->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    UINT32* Address = (UINT32*)(ScyvisorData->ModuleBase + ExpDir->AddressOfFunctions);
    UINT32* Name = (UINT32*)(ScyvisorData->ModuleBase + ExpDir->AddressOfNames);
    UINT16* Ordinal = (UINT16*)(ScyvisorData->ModuleBase + ExpDir->AddressOfNameOrdinals);

    for (UINT32 i = 0; i < ExpDir->NumberOfNames; i++)
    {
        if (AsciiStrStr((CHAR8*)ScyvisorData->ModuleBase + Name[i], "voyager_context"))
        {
            *(Scyvisor_T*)(ScyvisorData->ModuleBase + Address[Ordinal[i]]) = *ScyvisorData;
            break;
        }
    }

    EFI_IMAGE_DATA_DIRECTORY* baseRelocDir = &ntHeadersNew->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (baseRelocDir->VirtualAddress)
    {
        EFI_IMAGE_BASE_RELOCATION* reloc = (EFI_IMAGE_BASE_RELOCATION*)(ScyvisorData->ModuleBase + baseRelocDir->VirtualAddress);
        for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; )
        {
            UINT32 relocCount = (reloc->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
            UINT16* relocData = (UINT16*)((UINT8*)reloc + sizeof(EFI_IMAGE_BASE_RELOCATION));
            UINT8* relocBase = ScyvisorData->ModuleBase + reloc->VirtualAddress;

            for (UINT32 i = 0; i < relocCount; ++i, ++relocData)
            {
                if ((*relocData >> 12) == EFI_IMAGE_REL_BASED_DIR64)
                {
                    UINT64* rva = (UINT64*)(relocBase + (*relocData & 0xFFF));
                    *rva = (UINT64)(ScyvisorData->ModuleBase + (*rva - ntHeadersNew->OptionalHeader.ImageBase));
                }
            }

            currentSize += reloc->SizeOfBlock;
            reloc = (EFI_IMAGE_BASE_RELOCATION*)relocData;
        }
    }
    return ScyvisorData->ModuleBase + ntHeadersNew->OptionalHeader.AddressOfEntryPoint;
}






VOID* HookVmExit(VOID* HypervBase, VOID* HypervSize, VOID* VmExitHook)
{
    VOID* Handler = FindPattern(HypervBase, HypervSize, INTEL_VMEXIT_HANDLER_SIG, INTEL_VMEXIT_HANDLER_MASK);
    UINT64 HandlerCall, HandlerCallRip, HandlerFunc;
    INT32 NewRVA;

    if (Handler) // Intel
    {
#if WINVER == 2302
        HandlerCall = (UINT64)Handler + 7;
#else
        HandlerCall = (UINT64)Handler + 19;
#endif
        HandlerCallRip = HandlerCall + 5;
        HandlerFunc = HandlerCallRip + *(INT32*)(HandlerCall + 1);
    }
    else // AMD
    {
        Handler = FindPattern(HypervBase, HypervSize, AMD_VMEXIT_HANDLER_SIG, AMD_VMEXIT_HANDLER_MASK);
        if (!Handler) return NULL;

        HandlerCall = (UINT64)Handler;
        HandlerCallRip = HandlerCall + 5;
        HandlerFunc = HandlerCallRip + *(INT32*)(HandlerCall + 1);
    }

    NewRVA = (INT32)((INT64)VmExitHook - HandlerCallRip);
    *(INT32*)(HandlerCall + 1) = NewRVA;

    return (VOID*)HandlerFunc;
}
