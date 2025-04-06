#include "sys.h"
#include <sstream>
#include <iostream>
#include <iomanip> 
#include <ntstatus.h>
#include <winternl.h>

//prototypes
using MmGetVirtualForPhysical_t = PVOID(*)(PHYSICAL_ADDRESS PhysicalAddress);
using MmGetPhysicalMemoryRanges_t = PHYSICAL_MEMORY_RANGE * (*)();



void* memmem(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len)
{
    if (needle_len == 0) return (void*)haystack;
    if (haystack_len < needle_len) return nullptr;
    for (size_t i = 0; i <= haystack_len - needle_len; ++i)
    {
        if (memcmp((char*)haystack + i, needle, needle_len) == 0)
            return (void*)((char*)haystack + i);
    }
    return nullptr;
}


void* g_mmonp_MmPfnDatabase;

NTSTATUS InitializeMmPfnDatabase(ScyVDM::cVDM& vdm)
{
    struct MmPfnDatabaseSearchPattern
    {
        const UCHAR* bytes;
        SIZE_T bytes_size;
        bool hard_coded;
    };

    MmPfnDatabaseSearchPattern patterns;

    // Windows 10 x64 Build 14332+
    static const UCHAR kPatternWin10x64[] = {
        0x48, 0x8B, 0xC1,        // mov     rax, rcx
        0x48, 0xC1, 0xE8, 0x0C,  // shr     rax, 0Ch
        0x48, 0x8D, 0x14, 0x40,  // lea     rdx, [rax + rax * 2]
        0x48, 0x03, 0xD2,        // add     rdx, rdx
        0x48, 0xB8,              // mov     rax, 0FFFFFA8000000008h
    };

    patterns.bytes = kPatternWin10x64;
    patterns.bytes_size = sizeof(kPatternWin10x64);
    patterns.hard_coded = true;

    void* p_MmGetVirtualForPhysical = util::get_kmodule_export("ntoskrnl.exe", "MmGetVirtualForPhysical");
    if (!p_MmGetVirtualForPhysical) {
        std::cout << "Failed to get MmGetVirtualForPhysical address" << std::endl;
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    std::cout << "MmGetVirtualForPhysical address: " << p_MmGetVirtualForPhysical << std::endl;

    UCHAR buffer[0x100];
    ScyHV::read_km(buffer, p_MmGetVirtualForPhysical, sizeof(buffer));

    std::stringstream ss;
    ss << "First 16 bytes of buffer: ";
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << ss.str() << std::endl;

   

    auto found = reinterpret_cast<UCHAR*>(memmem(buffer, sizeof(buffer), patterns.bytes, patterns.bytes_size));
    if (!found) {
        std::cout << "Pattern not found in buffer" << std::endl;
        return STATUS_UNSUCCESSFUL;
    }

    std::cout << "Pattern found at offset: " << (found - buffer) << std::endl;

    found += patterns.bytes_size;
    if (patterns.hard_coded) {
        g_mmonp_MmPfnDatabase = *reinterpret_cast<void**>(found);
    }
    else {
        const auto mmpfn_address = *reinterpret_cast<ULONG_PTR*>(found);
        ScyHV::read_km(&g_mmonp_MmPfnDatabase, reinterpret_cast<void*>(mmpfn_address), sizeof(g_mmonp_MmPfnDatabase));
    }

    g_mmonp_MmPfnDatabase = PAGE_ALIGN(g_mmonp_MmPfnDatabase);

    std::cout << "g_mmonp_MmPfnDatabase: " << g_mmonp_MmPfnDatabase << std::endl;

    return STATUS_SUCCESS;
}

PVOID MmGetVirtualForPhysical(ScyVDM::cVDM& vdm, PHYSICAL_ADDRESS PhysicalAddress)
{
    static void* p_MmGetVirtualForPhysical = util::get_kmodule_export("ntoskrnl.exe", "MmGetVirtualForPhysical");

    // std::cout << "MmGetVirtualForPhysical address: " << p_MmGetVirtualForPhysical << std::endl;
    // std::cout << "Input PhysicalAddress: 0x" << std::hex << PhysicalAddress.QuadPart << std::endl;

    PVOID result = nullptr;
    result = vdm.syscall<MmGetVirtualForPhysical_t>(p_MmGetVirtualForPhysical, PhysicalAddress);

    // std::cout << "Result of MmGetVirtualForPhysical: " << result << std::endl;
    return result;
}

PHYSICAL_MEMORY_RANGE* MmGetPhysicalMemoryRanges(ScyVDM::cVDM& vdm)
{
    static void* p_MmGetPhysicalMemoryRanges = util::get_kmodule_export("ntoskrnl.exe", "MmGetPhysicalMemoryRanges");

    // std::cout << "MmGetPhysicalMemoryRanges address: " << p_MmGetPhysicalMemoryRanges << std::endl;

    PHYSICAL_MEMORY_RANGE* result = nullptr;
    result = vdm.syscall<MmGetPhysicalMemoryRanges_t>(p_MmGetPhysicalMemoryRanges);

    // std::cout << "Result of MmGetPhysicalMemoryRanges: " << result << std::endl;

    /*
    if (result != nullptr) {
        for (int i = 0; i < 5; i++) {
            PHYSICAL_MEMORY_RANGE range;
            ScyHV::read_km(&range, &result[i], sizeof(PHYSICAL_MEMORY_RANGE));

            if (range.BaseAddress.QuadPart == 0 && range.NumberOfBytes.QuadPart == 0) {
                break;
            }

            std::cout << "Range " << i << ": BaseAddress = 0x" << std::hex << range.BaseAddress.QuadPart
                << ", NumberOfBytes = 0x" << range.NumberOfBytes.QuadPart << std::endl;
        }
    }
    */

    return result;
}