#include "WinLoad.h"

 INLINE_HOOK WinLoadImageShitHook;
 INLINE_HOOK WinLoadAllocateImageHook;

 BOOLEAN HyperVloading = FALSE;
 BOOLEAN InstalledHvLoaderHook = FALSE;
 BOOLEAN ExtendedAllocation = FALSE;
 BOOLEAN HookedHyperV = FALSE;
 UINT64 AllocationCount = 0;

#if WINVER == 2302
 EFI_STATUS EFIAPI BlLdrLoadImage(VOID* Arg1, VOID* Arg2, VOID* Arg3, VOID* Arg4, VOID* Arg5,
     VOID* Arg6, VOID* Arg7, VOID* Arg8, VOID* Arg9,
     VOID* Arg10, VOID* Arg11, VOID* Arg12, VOID* Arg13, VOID* Arg14, VOID* Arg15,
     VOID* Arg16, VOID* Arg17)
#else
 EFI_STATUS EFIAPI BlLdrLoadImage(VOID* Arg1, CHAR16* ModulePath, CHAR16* ModuleName, VOID* Arg4, VOID* Arg5,
     VOID* Arg6, VOID* Arg7, PPLDR_DATA_TABLE_ENTRY lplpTableEntry, VOID* Arg9,
     VOID* Arg10, VOID* Arg11, VOID* Arg12, VOID* Arg13, VOID* Arg14, VOID* Arg15,
     VOID* Arg16)
#endif
 {
#if WINVER == 2302
     CHAR16* ImagePath = (CHAR16*)Arg3;
     CHAR16* ModuleName = (CHAR16*)Arg4;
#endif

     HyperVloading = !StrCmp(ModuleName, L"hv.exe");
     DisableInlineHook(&WinLoadImageShitHook);

     EFI_STATUS Result;
#if WINVER == 2302
     Result = ((LDR_LOAD_IMAGE)WinLoadImageShitHook.Address)(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6, Arg7, Arg8,
         Arg9, Arg10, Arg11, Arg12, Arg13, Arg14, Arg15, Arg16, Arg17);
#else
     Result = ((LDR_LOAD_IMAGE)WinLoadImageShitHook.Address)(Arg1, ModulePath, ModuleName, Arg4, Arg5, Arg6, Arg7, lplpTableEntry,
         Arg9, Arg10, Arg11, Arg12, Arg13, Arg14, Arg15, Arg16);
#endif

     

     if (!HookedHyperV)
         EnableInlineHook(&WinLoadImageShitHook);

     if (!StrCmp(ModuleName, L"hv.exe") && !HookedHyperV)
     {
         HookedHyperV = TRUE;
         Scyvisor_T ScyData;

#if WINVER == 2302
         const PLDR_DATA_TABLE_ENTRY entry = *(PPLDR_DATA_TABLE_ENTRY)Arg9;
         MakeScyvisorData(&ScyData, (VOID*)entry->ModuleBase, entry->SizeOfImage, AddSection((VOID*)entry->ModuleBase, SECTION_NAME, PayLoadSize(), SECTION_RWX), PayLoadSize());
         HookVmExit((void*)ScyData.HypervModuleBase, (void*)ScyData.HypervModuleSize, MapModule(&ScyData, PayLoad));
#else
         PLDR_DATA_TABLE_ENTRY entry = *lplpTableEntry;
         MakeScyvisorData(&ScyData,(VOID*)entry->ModuleBase, entry->SizeOfImage, AddSection((VOID*)entry->ModuleBase, SECTION_NAME,PayLoadSize(), SECTION_RWX), PayLoadSize());
         HookVmExit((void*)ScyData.HypervModuleBase, (void*)ScyData.HypervModuleSize, MapModule(&ScyData, PayLoad));

#endif
         entry->SizeOfImage = NT_HEADER(entry->ModuleBase)->OptionalHeader.SizeOfImage;
     }

     return Result;
 }

UINT64 EFIAPI BlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID* unused, UINT32 Value)
{
    if (HyperVloading && !ExtendedAllocation && ++AllocationCount == 2)
    {
        ExtendedAllocation = TRUE;
        imageSize += PayLoadSize();
        memoryType = BL_MEMORY_ATTRIBUTE_RWX;
    }

    DisableInlineHook(&WinLoadAllocateImageHook);
    UINT64 Result = ((ALLOCATE_IMAGE_BUFFER)WinLoadAllocateImageHook.Address)(imageBuffer, imageSize, memoryType, attributes, unused, Value);

    if (!ExtendedAllocation)
        EnableInlineHook(&WinLoadAllocateImageHook);

    return Result;
}