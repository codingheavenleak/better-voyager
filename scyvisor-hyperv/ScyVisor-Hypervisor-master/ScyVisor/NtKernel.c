#include "NtKernel.h"



VOID FixImport(VOID* PeMemPtr, VOID* KernelOsPtr)
{
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)PeMemPtr;
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)PeMemPtr + DosHeader->e_lfanew);
	UINT32 import_va = NtHeader->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if (import_va == 0)
	{
		return;
	}

	IMAGE_IMPORT_DESCRIPTOR* current_import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((UINT64)(PeMemPtr)+import_va);


	while (current_import_descriptor->FirstThunk) {

		char* module_name = (char*)((UINT64)(PeMemPtr)+current_import_descriptor->Name);
		if (AsciiStrCmp2(module_name, "ntoskrnl.exe") != 0)
		{
			continue;
		}

		PIMAGE_THUNK_DATA64 current_first_thunk = (PIMAGE_THUNK_DATA64)((UINT64)(PeMemPtr)+current_import_descriptor->FirstThunk);
		PIMAGE_THUNK_DATA64 current_originalFirstThunk = (PIMAGE_THUNK_DATA64)((UINT64)(PeMemPtr)+current_import_descriptor->DUMMYUNIONNAME.OriginalFirstThunk);

		while (current_originalFirstThunk->u1.Function) {
			EFI_IMAGE_IMPORT_BY_NAME* thunk_data = (EFI_IMAGE_IMPORT_BY_NAME*)((UINT64)(PeMemPtr)+current_originalFirstThunk->u1.AddressOfData);
			char* funName = thunk_data->Name;
			UINT64* funAddr = (UINT64*)&current_first_thunk->u1.Function;

			void* knFunAddress = GetExport(KernelOsPtr, funName);

			if (knFunAddress)
			{
				*funAddr = knFunAddress;
			}

			++current_originalFirstThunk;
			++current_first_thunk;
		}


		++current_import_descriptor;
	}
}



VOID MapPeImage(VOID* PeFilePtr, VOID* PeMemPtr, VOID* KernelOsPtr)
{
	// check pe
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)PeFilePtr;
	if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
		return;
	}
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)PeFilePtr + DosHeader->e_lfanew);

	//展开节
	MapPeSection(PeFilePtr, PeMemPtr);

	//修复重定位
	FixRelocImage(PeMemPtr);

	//修复导入表
	FixImport(PeMemPtr, KernelOsPtr);

}

