#include "PayLoad.h"

VOID* PayLoad = NULL;

UINT32 PayLoadSize(VOID)
{
	EFI_IMAGE_DOS_HEADER* RecordDosImageHeader = (EFI_IMAGE_DOS_HEADER*)PayLoad;// PayLoad;
	if (RecordDosImageHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return 0;

	EFI_IMAGE_NT_HEADERS64* RecordNtHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT64)RecordDosImageHeader + RecordDosImageHeader->e_lfanew);
	if (RecordNtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return 0;

	return RecordNtHeaders->OptionalHeader.SizeOfImage + 0x1000;
}

VOID* PayLoadEntry(VOID* ModuleBase)
{
	EFI_IMAGE_DOS_HEADER* RecordDosImageHeader = (EFI_IMAGE_DOS_HEADER*)PayLoad;// PayLoad;
	if (RecordDosImageHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* RecordNtHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT64)RecordDosImageHeader + RecordDosImageHeader->e_lfanew);
	if (RecordNtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	return (VOID*)((UINT64)ModuleBase + RecordNtHeaders->OptionalHeader.AddressOfEntryPoint);
}

VOID* AddSection(VOID* ImageBase, CHAR8* SectionName, UINT32 VirtualSize, UINT32 Characteristics)
{
	EFI_IMAGE_DOS_HEADER* dosHeader = (EFI_IMAGE_DOS_HEADER*)ImageBase;
	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)((UINT64)ImageBase + dosHeader->e_lfanew);

	UINT16 sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	EFI_IMAGE_FILE_HEADER* fileHeader = &(ntHeaders->FileHeader);

	EFI_IMAGE_SECTION_HEADER* firstSectionHeader = (EFI_IMAGE_SECTION_HEADER*)(((UINT64)fileHeader) + sizeof(EFI_IMAGE_FILE_HEADER) + sizeOfOptionalHeader);

	UINT32 numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	UINT32 sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	UINT32 fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

	EFI_IMAGE_SECTION_HEADER* newSectionHeader = &firstSectionHeader[numberOfSections];
	EFI_IMAGE_SECTION_HEADER* lastSectionHeader = &firstSectionHeader[numberOfSections - 1];

	MemCopy(&newSectionHeader->Name, SectionName, AsciiStrLen(SectionName));
	newSectionHeader->Misc.VirtualSize = VirtualSize;
	newSectionHeader->VirtualAddress =
		P2ALIGNUP(lastSectionHeader->VirtualAddress +
			lastSectionHeader->Misc.VirtualSize, sectionAlignment);

	newSectionHeader->SizeOfRawData = P2ALIGNUP(VirtualSize, fileAlignment);
	newSectionHeader->Characteristics = Characteristics;

	newSectionHeader->PointerToRawData =
		(UINT32)(lastSectionHeader->PointerToRawData +
			lastSectionHeader->SizeOfRawData);

	++ntHeaders->FileHeader.NumberOfSections;
	ntHeaders->OptionalHeader.SizeOfImage =
		P2ALIGNUP(newSectionHeader->VirtualAddress +
			newSectionHeader->Misc.VirtualSize, sectionAlignment);

	return ((UINT64)ImageBase) + newSectionHeader->VirtualAddress;
}


