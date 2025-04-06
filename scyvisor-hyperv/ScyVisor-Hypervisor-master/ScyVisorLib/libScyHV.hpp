#pragma once
#include "ScyVisor.h"
#include <intrin.h>
#include <type_traits>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "structs.h"
#include "util/util.hpp"
#include "lic.h"


namespace ScyHV {
    namespace detail {
        bool& get_initialized();
    }
}

#define VMEXIT_KEY ScyHV::vmexitkey
#define PAGE_4KB 0x1000
#define PAGE_2MB PAGE_4KB * 512
#define PAGE_1GB PAGE_2MB * 512


#define SCY_SUCCESS                  ScyHV::vmxroot_error_t::error_success
#define SCY_PML4E_NOT_PRESENT        ScyHV::vmxroot_error_t::pml4e_not_present
#define SCY_PDPTE_NOT_PRESENT        ScyHV::vmxroot_error_t::pdpte_not_present
#define SCY_PDE_NOT_PRESENT          ScyHV::vmxroot_error_t::pde_not_present
#define SCY_PTE_NOT_PRESENT          ScyHV::vmxroot_error_t::pte_not_present
#define SCY_TRANSLATE_FAILURE        ScyHV::vmxroot_error_t::vmxroot_translate_failure
#define SCY_INVALID_SELF_REF_PML4E   ScyHV::vmxroot_error_t::invalid_self_ref_pml4e
#define SCY_INVALID_MAPPING_PML4E    ScyHV::vmxroot_error_t::invalid_mapping_pml4e
#define SCY_INVALID_HOST_VIRTUAL     ScyHV::vmxroot_error_t::invalid_host_virtual
#define SCY_INVALID_GUEST_PHYSICAL   ScyHV::vmxroot_error_t::invalid_guest_physical
#define SCY_INVALID_GUEST_VIRTUAL    ScyHV::vmxroot_error_t::invalid_guest_virtual
#define SCY_PAGE_TABLE_INIT_FAILED   ScyHV::vmxroot_error_t::page_table_init_failed


using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;

#ifndef _PPEB_
#define _PPEB_
typedef struct _PEB* PPEB;
#endif




namespace ScyVDM
{
    extern LIBSCYHV_API std::atomic<void*> syscall_address;

}

namespace ScyHV
{



    constexpr std::pair<const char*, const char*> syscall_hook = { "NtShutdownSystem", "ntdll.dll" };

    using PsLookupProcessByProcessId = NTSTATUS(__fastcall*)(ULONG64, PVOID*);
    using PsLookupProcessByProcessId_t = NTSTATUS(*)(HANDLE ProcessId, PEPROCESS* Process);
    using PsGetProcessSectionBaseAddress = PVOID(__fastcall*)(ULONG64);
    using PsGetProcessPeb = PVOID(__fastcall*)(ULONG64);
    using ObfReferenceObject = LONG_PTR(*)(PVOID);


    extern u64 RandomKey;
    extern u64 KernelCr3;
    extern u64 MyCr3;
    extern u64 ProcessCr3;
    extern u64 NtShutdownSystemPa;
    extern u64 NtShutdownSystemVa;
    extern u64 ImageBase;
    extern u64 ProcessPeb;
    extern u64 MemCopy;
    extern u64 PsLookupPeproc;
    extern u64 ObDereferenceObject;
    extern u64 ProcBaseProt;
    extern u64 ProcPebProt;
    extern u64 GuardReg;

	LIBSCYHV_API void set_secret_key(const std::string& key);
    LIBSCYHV_API const std::string& get_secret_key();
    LIBSCYHV_API auto my_dtb() -> guest_phys_t;
    LIBSCYHV_API auto get_pid(const wchar_t* proc_name) -> std::uint32_t;
    LIBSCYHV_API auto get_proc_base(std::uint32_t pid) -> uint32_t;
    LIBSCYHV_API auto get_proc_dtb(std::uint32_t pid) -> std::uintptr_t;
    LIBSCYHV_API auto get_eac_dtb(std::uint32_t pid) -> std::uintptr_t;
	LIBSCYHV_API auto init() -> bool;
    LIBSCYHV_API void check_initialization();
    LIBSCYHV_API auto initPTB() -> bool;
    LIBSCYHV_API auto get_kmodule_address() -> bool;
    LIBSCYHV_API auto translate(guest_virt_t virt_addr) -> guest_phys_t;
    LIBSCYHV_API auto read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> vmxroot_error_t;
    LIBSCYHV_API auto write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> vmxroot_error_t;
    LIBSCYHV_API auto read_km(void* dst, void* src, std::size_t size) -> void;
    LIBSCYHV_API auto write_km(void* dst, void* src, std::size_t size) -> void;
    LIBSCYHV_API auto copy_virt(guest_phys_t dirbase_src, guest_virt_t virt_src, guest_phys_t dirbase_dest,
        guest_virt_t virt_dest, u64 size) -> vmxroot_error_t;

    extern "C" auto hypercall(u64 key, ScyHV::vmexit_command_t command, ScyHV::pcommand_t data) -> vmxroot_error_t;

    template <class T>
    auto read(guest_virt_t virt_addr) -> T
    {
        T buffer;
        auto result = copy_virt(ProcessCr3, virt_addr, MyCr3, (guest_virt_t)&buffer, sizeof(T));

        if (result != SCY_SUCCESS)
            return {};

        return buffer;
    }

    template <class T>
    auto write(guest_virt_t virt_addr, const T& data) -> void
    {
        copy_virt(MyCr3, (guest_virt_t)&data, ProcessCr3, virt_addr, sizeof(T));
    }



}

namespace ScyVDM
{
    constexpr std::pair<const char*, const char*> syscall_hook = { "NtShutdownSystem", "ntdll.dll" };
    inline std::atomic<bool> is_page_found = false;
    inline std::uint16_t nt_page_offset;
    inline std::uint32_t nt_rva;
    inline std::uint8_t* ntoskrnl;
    using read_phys_t = std::function<bool(void*, void*, std::size_t)>;
    using write_phys_t = std::function<bool(void*, void*, std::size_t)>;

    class cVDM
    {
    public:
        static cVDM& getInstance() {
            static cVDM instance(_read_phys, _write_phys);
            return instance;
        }

        void set_read(read_phys_t& read_func);
        void set_write(write_phys_t& write_func);

        template <class T, class ... Ts>
        __forceinline std::invoke_result_t<T, Ts...> syscall(void* addr, Ts ... args) const
        {
            static const auto proc =
                GetProcAddress(
                    LoadLibraryA(syscall_hook.second),
                    syscall_hook.first
                );

            static std::mutex syscall_mutex;
            syscall_mutex.lock();

            // jmp [rip+0x0]
            std::uint8_t jmp_code[] =
            {
                0xff, 0x25, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            };

            std::uint8_t orig_bytes[sizeof jmp_code];
            *reinterpret_cast<void**>(jmp_code + 6) = addr;
            read_phys(syscall_address.load(), orig_bytes, sizeof orig_bytes);

            // execute hook...
            write_phys(syscall_address.load(), jmp_code, sizeof jmp_code);
            auto result = reinterpret_cast<T>(proc)(args ...);
            write_phys(syscall_address.load(), orig_bytes, sizeof orig_bytes);

            syscall_mutex.unlock();
            return result;
        }

        template <class T>
        __forceinline auto rkm(std::uintptr_t addr) -> T
        {
            T buffer;
            ScyHV::read_km((void*)&buffer, (void*)addr, sizeof(T));
            return buffer;
        }

        template <class T>
        __forceinline void wkm(std::uintptr_t addr, const T& value)
        {
            ScyHV::write_km((void*)addr, (void*)&value, sizeof(T));
        }


        __forceinline auto get_peprocess(std::uint32_t pid) -> PEPROCESS
        {
            static const auto ps_lookup_peproc = util::get_kmodule_export("ntoskrnl.exe", "PsLookupProcessByProcessId");

            PEPROCESS peproc = nullptr;
            syscall<ScyHV::PsLookupProcessByProcessId_t>(ps_lookup_peproc, reinterpret_cast<HANDLE>(pid), &peproc);
            return peproc;
        }



        __forceinline auto get_peb(std::uint32_t pid) -> PPEB
        {
            static const auto get_peb = util::get_kmodule_export("ntoskrnl.exe", "PsGetProcessPeb");

            return syscall<PPEB(*)(PEPROCESS)>(get_peb, get_peprocess(pid));
        }

    private:
        cVDM(read_phys_t& read_func, write_phys_t& write_func);
        cVDM(const cVDM&) = delete;
        cVDM& operator=(const cVDM&) = delete;

        void locate_syscall(std::uintptr_t begin, std::uintptr_t end) const;
        bool valid_syscall(void* syscall_addr) const;

        read_phys_t read_phys;
        write_phys_t write_phys;

        static read_phys_t _read_phys;
        static write_phys_t _write_phys;
    };

    extern LIBSCYHV_API cVDM& vdm;
}