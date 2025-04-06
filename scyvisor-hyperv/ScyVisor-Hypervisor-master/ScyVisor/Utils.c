#include "Utils.h"

BOOLEAN CheckMask(CHAR8* base, CHAR8* pattern, CHAR8* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return FALSE;

	return TRUE;
}

VOID* FindPattern(CHAR8* base, UINTN size, CHAR8* pattern, CHAR8* mask)
{
	size -= AsciiStrLen(mask);
	for (UINTN i = 0; i <= size; ++i)
	{
		VOID* addr = &base[i];
		if (CheckMask(addr, pattern, mask))
			return addr;
	}
	return NULL;
}


UINT32 GetPeFileImageSize(VOID* InPePtr)
{
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)InPePtr;
	if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)InPePtr + DosHeader->e_lfanew);
	return NtHeader->OptionalHeader.SizeOfImage;
}

VOID* GetExport(UINT8* ModuleBase, CHAR8* export)
{
	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)ModuleBase;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(ModuleBase + dosHeaders->e_lfanew);
	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	EFI_IMAGE_EXPORT_DIRECTORY* exports = (EFI_IMAGE_EXPORT_DIRECTORY*)(ModuleBase + exportsRva);
	UINT32* nameRva = (UINT32*)(ModuleBase + exports->AddressOfNames);

	for (UINT32 i = 0; i < exports->NumberOfNames; ++i)
	{
		CHAR8* func = (CHAR8*)(ModuleBase + nameRva[i]);
		if (AsciiStrCmp(func, export) == 0)
		{
			UINT32* funcRva = (UINT32*)(ModuleBase + exports->AddressOfFunctions);
			UINT16* ordinalRva = (UINT16*)(ModuleBase + exports->AddressOfNameOrdinals);
			return (VOID*)(((UINT64)ModuleBase) + funcRva[ordinalRva[i]]);
		}
	}
	return NULL;
}

VOID MapPeSection(VOID* PeFilePtr, VOID* PeMemPtr)
{
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)PeFilePtr;
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)PeFilePtr + DosHeader->e_lfanew);
	MemCopy(PeMemPtr, PeFilePtr, NtHeader->OptionalHeader.SizeOfHeaders);

	EFI_IMAGE_SECTION_HEADER* current_image_section = GetPeFirstSection(PeMemPtr);

	for (auto i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i) {
		if ((current_image_section[i].Characteristics & EFI_IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
			continue;
		void* local_section = (void*)((UINT64)(PeMemPtr)+current_image_section[i].VirtualAddress);
		MemCopy(local_section, (void*)((UINT64)(PeFilePtr)+current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
	}
}

VOID* GetExportByIndex(UINT8* ModuleBase, UINT16 Index)
{
	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)ModuleBase;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(ModuleBase + dosHeaders->e_lfanew);
	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	EFI_IMAGE_EXPORT_DIRECTORY* exports = (EFI_IMAGE_EXPORT_DIRECTORY*)(ModuleBase + exportsRva);

	if (Index >= exports->NumberOfFunctions)
		return NULL;

	UINT32* funcRva = (UINT32*)(ModuleBase + exports->AddressOfFunctions);
	UINT64 exportAddress = ((UINT64)ModuleBase) + funcRva[Index];

	return (VOID*)exportAddress;
}

VOID MemCopy(VOID* dest, VOID* src, UINTN size) 
{
	for (UINT8* d = dest, *s = src; size--; *d++ = *s++);
}

VOID* MemSet(VOID* dest, int val, UINT32 len)
{
	unsigned char* ptr = (unsigned char*)(dest);
	while (len-- > 0)
		*ptr++ = val;

	return dest;
}


EFI_IMAGE_NT_HEADERS64* GetPeFileHeader(VOID* InPePtr)
{
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)InPePtr;
	if (DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)InPePtr + DosHeader->e_lfanew);
	return NtHeader;
}


EFI_IMAGE_SECTION_HEADER* GetPeFirstSection(VOID* PePtr)
{
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)PePtr;
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)PePtr + DosHeader->e_lfanew);
	return (EFI_IMAGE_SECTION_HEADER*)((UINT64)NtHeader + sizeof(EFI_IMAGE_NT_HEADERS64));
}

VOID FixRelocImage(VOID* PeMemPtr)
{
	EFI_IMAGE_DOS_HEADER* DosHeader = (EFI_IMAGE_DOS_HEADER*)PeMemPtr;
	EFI_IMAGE_NT_HEADERS64* NtHeader = (EFI_IMAGE_NT_HEADERS64*)((UINT64)PeMemPtr + DosHeader->e_lfanew);


	INT64 DeltaOffset = (INT64)((UINT64)PeMemPtr - NtHeader->OptionalHeader.ImageBase);
	if (!DeltaOffset) {
		return;
	}

	UINT32 reloc_va = NtHeader->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (!reloc_va)
	{
		return;
	}


	EFI_IMAGE_BASE_RELOCATION* current_base_relocation = (EFI_IMAGE_BASE_RELOCATION*)(((UINT64)PeMemPtr) + reloc_va);
	EFI_IMAGE_BASE_RELOCATION* reloc_end = (EFI_IMAGE_BASE_RELOCATION*)((UINT64)current_base_relocation + NtHeader->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {

		UINT32 va = current_base_relocation->VirtualAddress;

		UINT64 address = (UINT64)(PeMemPtr)+va;
		UINT16* item = (UINT16*)((UINT64)(current_base_relocation)+sizeof(EFI_IMAGE_BASE_RELOCATION));
		UINT32 count = (current_base_relocation->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16);

		for (int i = 0; i < count; ++i)
		{
			UINT16 type = item[i] >> 12;
			UINT16 offset = item[i] & 0xFFF;

			if (type == EFI_IMAGE_REL_BASED_DIR64)
			{
				*(UINT64*)(address + offset) += DeltaOffset;
			}

		}
		current_base_relocation = (EFI_IMAGE_BASE_RELOCATION*)((UINT64)(current_base_relocation)+current_base_relocation->SizeOfBlock);
	}

}

VOID Sleep(const UINTN seconds)
{
	gBS->Stall(seconds * 1000 * 1000);
}