#pragma once
#include <Windows.h>
#define ANYSIZE_ARRAY 1
#define PML4E_ENTRIES 512


struct virt_addr_t {
	union {
		uintptr_t value;
		struct {
			uintptr_t offset : 12;
			uintptr_t pt_index : 9;
			uintptr_t pd_index : 9;
			uintptr_t pdpt_index : 9;
			uintptr_t pml4_index : 9;
			uintptr_t reserved : 16;
		};
	};
};

typedef struct _FAR_JMP_16
{
	UCHAR  OpCode;  // = 0xe9
	USHORT Offset;
} FAR_JMP_16;

typedef struct _FAR_TARGET_32
{
	ULONG Offset;
	USHORT Selector;
} FAR_TARGET_32;

typedef struct _PSEUDO_DESCRIPTOR_32 {
	USHORT Limit;
	ULONG Base;
} PSEUDO_DESCRIPTOR_32;

#pragma pack(pop)
typedef union _KGDTENTRY64
{
	struct
	{
		USHORT  LimitLow;
		USHORT  BaseLow;
		union
		{
			struct
			{
				UCHAR   BaseMiddle;
				UCHAR   Flags1;
				UCHAR   Flags2;
				UCHAR   BaseHigh;
			} Bytes;

			struct
			{
				ULONG   BaseMiddle : 8;
				ULONG   Type : 5;
				ULONG   Dpl : 2;
				ULONG   Present : 1;
				ULONG   LimitHigh : 4;
				ULONG   System : 1;
				ULONG   LongMode : 1;
				ULONG   DefaultBig : 1;
				ULONG   Granularity : 1;
				ULONG   BaseHigh : 8;
			} Bits;
		};
		ULONG BaseUpper;
		ULONG MustBeZero;
	};
	ULONG64 Alignment;
} KGDTENTRY64, * PKGDTENTRY64;

typedef union _KIDTENTRY64
{
	struct
	{
		USHORT OffsetLow;
		USHORT Selector;
		USHORT IstIndex : 3;
		USHORT Reserved0 : 5;
		USHORT Type : 5;
		USHORT Dpl : 2;
		USHORT Present : 1;
		USHORT OffsetMiddle;
		ULONG OffsetHigh;
		ULONG Reserved1;
	};
	ULONG64 Alignment;
} KIDTENTRY64, * PKIDTENTRY64;

typedef union _KGDT_BASE
{
	struct
	{
		USHORT BaseLow;
		UCHAR BaseMiddle;
		UCHAR BaseHigh;
		ULONG BaseUpper;
	};
	ULONG64 Base;
} KGDT_BASE, * PKGDT_BASE;

typedef union _KGDT_LIMIT
{
	struct
	{
		USHORT LimitLow;
		USHORT LimitHigh : 4;
		USHORT MustBeZero : 12;
	};
	ULONG Limit;
} KGDT_LIMIT, * PKGDT_LIMIT;

#define PSB_GDT32_MAX       3

typedef struct _KDESCRIPTOR
{
	USHORT Pad[3];
	USHORT Limit;
	PVOID Base;
} KDESCRIPTOR, * PKDESCRIPTOR;

typedef struct _KDESCRIPTOR32
{
	USHORT Pad[3];
	USHORT Limit;
	ULONG Base;
} KDESCRIPTOR32, * PKDESCRIPTOR32;

typedef struct _KSPECIAL_REGISTERS
{
	ULONG64 Cr0;
	ULONG64 Cr2;
	ULONG64 Cr3;
	ULONG64 Cr4;
	ULONG64 KernelDr0;
	ULONG64 KernelDr1;
	ULONG64 KernelDr2;
	ULONG64 KernelDr3;
	ULONG64 KernelDr6;
	ULONG64 KernelDr7;
	KDESCRIPTOR Gdtr;
	KDESCRIPTOR Idtr;
	USHORT Tr;
	USHORT Ldtr;
	ULONG MxCsr;
	ULONG64 DebugControl;
	ULONG64 LastBranchToRip;
	ULONG64 LastBranchFromRip;
	ULONG64 LastExceptionToRip;
	ULONG64 LastExceptionFromRip;
	ULONG64 Cr8;
	ULONG64 MsrGsBase;
	ULONG64 MsrGsSwap;
	ULONG64 MsrStar;
	ULONG64 MsrLStar;
	ULONG64 MsrCStar;
	ULONG64 MsrSyscallMask;
} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE
{
	KSPECIAL_REGISTERS SpecialRegisters;
	CONTEXT ContextFrame;
} KPROCESSOR_STATE, * PKPROCESSOR_STATE;

typedef struct _PROCESSOR_START_BLOCK* PPROCESSOR_START_BLOCK;

typedef struct _PROCESSOR_START_BLOCK
{
	FAR_JMP_16 Jmp;
	ULONG CompletionFlag;
	PSEUDO_DESCRIPTOR_32 Gdt32;
	PSEUDO_DESCRIPTOR_32 Idt32;
	KGDTENTRY64 Gdt[PSB_GDT32_MAX + 1];
	ULONG64 TiledCr3;
	FAR_TARGET_32 PmTarget;
	FAR_TARGET_32 LmIdentityTarget;
	PVOID LmTarget;
	PPROCESSOR_START_BLOCK SelfMap;
	ULONG64 MsrPat;
	ULONG64 MsrEFER;
	KPROCESSOR_STATE ProcessorState;
} PROCESSOR_START_BLOCK;
#pragma warning(pop)


typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union
	{
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	}
	;
	ULONG_PTR SizeInBytes;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;




struct ListEntry {
	struct ListEntry* Flink;
	struct ListEntry* Blink;
};

struct UnicodeString {
	unsigned short Length;
	unsigned short MaximumLength;
	wchar_t* Buffer;
};

struct PebLdrData {
	unsigned long Length;
	unsigned long Initialized;
	const char* SsHandle;
	ListEntry InLoadOrderModuleList;
	ListEntry InMemoryOrderModuleList;
	ListEntry InInitializationOrderModuleList;
};

struct PEB64 {
	unsigned char Reserved1[2];
	unsigned char BeingDebugged;
	unsigned char Reserved2[1];
	const char* Reserved3[2];
	PebLdrData* Ldr;
};

struct LdrDataTableEntry {
	ListEntry InLoadOrderModuleList;
	ListEntry InMemoryOrderLinks;
	ListEntry InInitializationOrderModuleList;
	void* DllBase;
	void* EntryPoint;

	union {
		unsigned long SizeOfImage;
		const char* Dummy;
	};

	UnicodeString FullDllName;
	UnicodeString BaseDllName;
};

struct ImageDosHeader {
	unsigned short E_Magic;
	unsigned short E_Cblp;
	unsigned short E_Cp;
	unsigned short E_Crlc;
	unsigned short E_Cparhdr;
	unsigned short E_Minalloc;
	unsigned short E_Maxalloc;
	unsigned short E_Ss;
	unsigned short E_Sp;
	unsigned short E_Csum;
	unsigned short E_Ip;
	unsigned short E_Cs;
	unsigned short E_Lfarlc;
	unsigned short E_Ovno;
	unsigned short E_Res[4];
	unsigned short E_Oemid;
	unsigned short E_Oeminfo;
	unsigned short E_Res2[10];
	long E_Lfanew;
};

struct ImageFileHeader {
	unsigned short Machine;
	unsigned short NumberOfSections;
	unsigned long TimeDateStamp;
	unsigned long PointerToSymbolTable;
	unsigned long NumberOfSymbols;
	unsigned short SizeOfOptionalHeader;
	unsigned short Characteristics;
};

struct ImageExportDirectory {
	unsigned long Characteristics;
	unsigned long TimeDateStamp;
	unsigned short MajorVersion;
	unsigned short MinorVersion;
	unsigned long Name;
	unsigned long Base;
	unsigned long NumberOfFunctions;
	unsigned long NumberOfNames;
	unsigned long AddressOfFunctions;
	unsigned long AddressOfNames;
	unsigned long AddressOfNameOrdinals;
};

struct ImageDataDirectory {
	unsigned long VirtualAddress;
	unsigned long Size;
};

struct ImageOptionalHeader {
	unsigned short Magic;
	unsigned char MajorLinkerVersion;
	unsigned char MinorLinkerVersion;
	unsigned long SizeOfCode;
	unsigned long SizeOfInitializedData;
	unsigned long SizeOfUninitializedData;
	unsigned long AddressOfEntryPoint;
	unsigned long BaseOfCode;
	unsigned long long ImageBase;
	unsigned long SectionAlignment;
	unsigned long FileAlignment;
	unsigned short MajorOperatingSystemVersion;
	unsigned short MinorOperatingSystemVersion;
	unsigned short MajorImageVersion;
	unsigned short MinorImageVersion;
	unsigned short MajorSubsystemVersion;
	unsigned short MinorSubsystemVersion;
	unsigned long Win32VersionValue;
	unsigned long SizeOfImage;
	unsigned long SizeOfHeaders;
	unsigned long CheckSum;
	unsigned short Subsystem;
	unsigned short DllCharacteristics;
	unsigned long long SizeOfStackReserve;
	unsigned long long SizeOfStackCommit;
	unsigned long long SizeOfHeapReserve;
	unsigned long long SizeOfHeapCommit;
	unsigned long LoaderFlags;
	unsigned long NumberOfRvaAndSizes;
	ImageDataDirectory DataDirectory[16];
};

struct ImageNtHeaders {
	unsigned long Signature;
	ImageFileHeader FileHeader;
	ImageOptionalHeader OptionalHeader;
};


//PAGING STRUCTURES
typedef struct _MMPTE_HARDWARE
{
	struct
	{
		unsigned __int64 Valid : 1;
		unsigned __int64 Dirty1 : 1;
		unsigned __int64 Owner : 1;
		unsigned __int64 WriteThrough : 1;
		unsigned __int64 CacheDisable : 1;
		unsigned __int64 Accessed : 1;
		unsigned __int64 Dirty : 1;
		unsigned __int64 LargePage : 1;
		unsigned __int64 Global : 1;
		unsigned __int64 CopyOnWrite : 1;
		unsigned __int64 Unused : 1;
		unsigned __int64 Write : 1;
		unsigned __int64 PageFrameNumber : 40;
		unsigned __int64 ReservedForSoftware : 4;
		unsigned __int64 WsleAge : 4;
		unsigned __int64 WsleProtection : 3;
		unsigned __int64 NoExecute : 1;
	};
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE_PROTOTYPE
{
	struct /* bitfield */
	{
		unsigned __int64 Valid : 1;
		unsigned __int64 DemandFillProto : 1;
		unsigned __int64 HiberVerifyConverted : 1;
		unsigned __int64 ReadOnly : 1;
		unsigned __int64 SwizzleBit : 1;
		unsigned __int64 Protection : 5;
		unsigned __int64 Prototype : 1;
		unsigned __int64 Combined : 1;
		unsigned __int64 Unused1 : 4;
		__int64 ProtoAddress : 48;
	};
} MMPTE_PROTOTYPE, * PMMPTE_PROTOTYPE;

typedef struct _MMPTE_SOFTWARE
{
	struct /* bitfield */
	{
		unsigned __int64 Valid : 1;
		unsigned __int64 PageFileReserved : 1;
		unsigned __int64 PageFileAllocated : 1;
		unsigned __int64 ColdPage : 1;
		unsigned __int64 SwizzleBit : 1;
		unsigned __int64 Protection : 5;
		unsigned __int64 Prototype : 1;
		unsigned __int64 Transition : 1;
		unsigned __int64 PageFileLow : 4;
		unsigned __int64 UsedPageTableEntries : 10;
		unsigned __int64 ShadowStack : 1;
		unsigned __int64 Unused : 5;
		unsigned __int64 PageFileHigh : 32;
	};
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE;

typedef struct _MMPTE_TIMESTAMP
{
	struct /* bitfield */
	{
		unsigned __int64 MustBeZero : 1;
		unsigned __int64 Unused : 3;
		unsigned __int64 SwizzleBit : 1;
		unsigned __int64 Protection : 5;
		unsigned __int64 Prototype : 1;
		unsigned __int64 Transition : 1;
		unsigned __int64 PageFileLow : 4;
		unsigned __int64 Reserved : 16;
		unsigned __int64 GlobalTimeStamp : 32;
	};
} MMPTE_TIMESTAMP, * PMMPTE_TIMESTAMP;

typedef struct _MMPTE_TRANSITION
{
	struct /* bitfield */
	{
		unsigned __int64 Valid : 1;
		unsigned __int64 Write : 1;
		unsigned __int64 Spare : 1;
		unsigned __int64 IoTracker : 1;
		unsigned __int64 SwizzleBit : 1;
		unsigned __int64 Protection : 5;
		unsigned __int64 Prototype : 1;
		unsigned __int64 Transition : 1;
		unsigned __int64 PageFrameNumber : 40;
		unsigned __int64 Unused : 12;
	};
} MMPTE_TRANSITION, * PMMPTE_TRANSITION;

typedef struct _MMPTE_SUBSECTION
{
	struct /* bitfield */
	{
		unsigned __int64 Valid : 1;
		unsigned __int64 Unused0 : 3;
		unsigned __int64 SwizzleBit : 1;
		unsigned __int64 Protection : 5;
		unsigned __int64 Prototype : 1;
		unsigned __int64 ColdPage : 1;
		unsigned __int64 Unused1 : 3;
		unsigned __int64 ExecutePrivilege : 1;
		__int64 SubsectionAddress : 48;
	};
} MMPTE_SUBSECTION, * PMMPTE_SUBSECTION;

typedef struct _MMPTE_LIST
{
	struct /* bitfield */
	{
		unsigned __int64 Valid : 1;
		unsigned __int64 OneEntry : 1;
		unsigned __int64 filler0 : 2;
		unsigned __int64 SwizzleBit : 1;
		unsigned __int64 Protection : 5;
		unsigned __int64 Prototype : 1;
		unsigned __int64 Transition : 1;
		unsigned __int64 filler1 : 16;
		unsigned __int64 NextEntry : 36;
	};
} MMPTE_LIST, * PMMPTE_LIST;

typedef struct _MMPTE
{
	union
	{
		union
		{
			unsigned __int64 Long;
			volatile unsigned __int64 VolatileLong;
			struct _MMPTE_HARDWARE Hard;
			struct _MMPTE_PROTOTYPE Proto;
			struct _MMPTE_SOFTWARE Soft;
			struct _MMPTE_TIMESTAMP TimeStamp;
			struct _MMPTE_TRANSITION Trans;
			struct _MMPTE_SUBSECTION Subsect;
			struct _MMPTE_LIST List;
		};
	} u;
} MMPTE, * PMMPTE;


typedef struct _MMPFN
{
	union
	{
		struct _LIST_ENTRY ListEntry;
		struct
		{
			union
			{
				struct _SINGLE_LIST_ENTRY NextSlistPfn;
				void* Next;
			} u1;
			union
			{
				struct _MMPTE* PteAddress;
				unsigned __int64 PteLong;
			};
			struct _MMPTE OriginalPte;
		};
	};

	union
	{
		struct
		{
			unsigned short ReferenceCount;
			unsigned char PageLocation : 3;
			unsigned char WriteInProgress : 1;
			unsigned char Modified : 1;
			unsigned char ReadInProgress : 1;
			unsigned char CacheAttribute : 2;
		};
		unsigned long EntireField;
	} u3;

	union
	{
		struct
		{
			unsigned __int64 PteFrame : 40;
			unsigned __int64 ResidentPage : 1;
			unsigned __int64 Partition : 10;
			unsigned __int64 PageIdentity : 3;
		};
		unsigned __int64 EntireField;
	} u4;
} MMPFN, * PMMPFN;