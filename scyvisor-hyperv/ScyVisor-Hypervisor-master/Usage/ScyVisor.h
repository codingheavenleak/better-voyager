#pragma once

#define LIBSCYHV_API

#include <Windows.h>
#include <cstdint>
#include <string>
#include <map>


namespace ScyHV
{
    using u8 = unsigned char;
    using u16 = unsigned short;
    using u32 = unsigned int;
    using u64 = unsigned long long;

    using guest_virt_t = u64; // Alias for guest virtual addresses. unsign long long
    using guest_phys_t = u64; // Alias for guest physical addresses. unsign long long
    using host_virt_t = u64;
    using host_phys_t = u64;
    extern unsigned long long vmexitkey;

    enum class vmexit_command_t
    {
        init_page_tables = 0x30,
        read_guest_phys,
        write_guest_phys,
        copy_guest_virt,
        get_dirbase,
        translate,
        status,
    };

    /// <summary>
    /// Error codes that can be returned by the functions.
    /// </summary>
    enum class vmxroot_error_t
    {
        error_success,               // Action succeeded
        pml4e_not_present,           // PML4E entry is not present
        pdpte_not_present,           // PDPTE entry is not present
        pde_not_present,             // PDE entry is not present
        pte_not_present,             // PTE entry is not present
        vmxroot_translate_failure,   // Address translation failed
        invalid_self_ref_pml4e,      // Invalid self-referencing PML4E entry
        invalid_mapping_pml4e,       // Invalid PML4E mapping
        invalid_host_virtual,        // Invalid host virtual address
        invalid_guest_physical,      // Invalid guest physical address
        invalid_guest_virtual,       // Invalid guest virtual address
        page_table_init_failed       // Page table initialization failed
    };



    typedef union _command_t
    {
        struct _copy_phys
        {
            host_phys_t  phys_addr;
            guest_virt_t buffer;
            u64 size;
        } copy_phys;

        struct _copy_virt
        {
            guest_phys_t dirbase_src;
            guest_virt_t virt_src;
            guest_phys_t dirbase_dest;
            guest_virt_t virt_dest;
            u64 size;
        } copy_virt;

        struct _translate_virt
        {
            guest_virt_t virt_src;
            guest_phys_t phys_addr;
        } translate_virt;

        guest_phys_t dirbase;

    } command_t, * pcommand_t;

    // Public error macros
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

    // Auth function
    LIBSCYHV_API void set_secret_key(const std::string& key);


    // Original ScyHV functions

    /// <summary>
    /// Initializes scyVisor. Must called at the start of the program.
    /// </summary>
    /// <returns>Error code of type `bool`</returns>
    LIBSCYHV_API auto init() -> bool;



    /// <summary>
    /// Initializes the page tables for the guest.
    /// </summary>
    /// <returns>`true` if initialization was successful, otherwise `false`.</returns>
    LIBSCYHV_API auto initPTB() -> bool;

    /// <summary>
    /// Retrieves the physical address of the current DTB (Directory Table Base) of the guest.
    /// </summary>
    /// <returns>Physical address of the DTB.</returns>
    LIBSCYHV_API auto my_dtb() -> guest_phys_t;

    /// <summary>
    /// Retrieves the process ID (PID) of a process by its name.
    /// </summary>
    /// <param name="proc_name"> - Name of the process (e.g., "notepad.exe").</param>
    /// <returns>PID of the process.</returns>
    LIBSCYHV_API auto get_pid(const wchar_t* proc_name) -> std::uint32_t;

    /// <summary>
    /// Retrieves the base address of a process in memory.
    /// </summary>
    /// <param name="pid"> - Process ID (PID).</param>
    /// <returns>Virtual base address of the process.</returns>
    LIBSCYHV_API auto get_proc_base(std::uint32_t pid) -> uint32_t;

    /// <summary>
    /// Retrieves the Directory Table Base (DTB) of a process.
    /// </summary>
    /// <param name="pid"> - Process ID (PID) of the target process.</param>
    /// <returns>Directory Table Base (DTB) of the process as a uintptr_t.</returns>
    LIBSCYHV_API auto get_proc_dtb(std::uint32_t pid) -> uintptr_t;

    /// <summary>
    /// Retrieves the shuffeld Directory Table Base (DTB) of a EAC Process.
    /// Only use this one for EAC protected Games that shuffle the CR3.
    /// like Rust, Fortnite, Apex Legends
    /// </summary>
    /// <param name="pid"> - Process ID (PID) of the EAC target process.</param>
    /// <returns>cached Directory Table Base (DTB) of the EAC process as a uintptr_t.</returns>
    LIBSCYHV_API auto get_eac_dtb(std::uint32_t pid) -> uintptr_t;

    /// <summary>
    /// Retrieves the address of a kernel module.
    /// </summary>
    /// <returns>`true` if the address was successfully retrieved, otherwise `false`.</returns>
    LIBSCYHV_API auto get_kmodule_address() -> bool;

    /// <summary>
    /// Translates a guest virtual address to a physical address.
    /// </summary>
    /// <param name="virt_addr"> - Guest virtual address.</param>
    /// <returns>Guest physical address.</returns>
    LIBSCYHV_API auto translate(guest_virt_t virt_addr) -> guest_phys_t;

    /// <summary>
    /// Reads data from a guest physical address.
    /// </summary>
    /// <param name="phys_addr"> - Physical address to read from.</param>
    /// <param name="buffer"> - Buffer to store the read data.</param>
    /// <param name="size"> - Number of bytes to read.</param>
    /// <returns>Error code of type `vmxroot_error_t`</returns>
    LIBSCYHV_API auto read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> vmxroot_error_t;

    /// <summary>
    /// Writes data to a guest physical address.
    /// </summary>
    /// <param name="phys_addr"> - Physical address to write to.</param>
    /// <param name="buffer"> - Buffer containing the data to write.</param>
    /// <param name="size"> - Number of bytes to write.</param>
    /// <returns>Error code of type `vmxroot_error_t`</returns>
    LIBSCYHV_API auto write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> vmxroot_error_t;

    /// <summary>
    /// Reads data from kernel memory.
    /// </summary>
    /// <param name="UmDst"> - Destination buffer in usermode for the read data.</param>
    /// <param name="KrnlSrc"> - Source address in kernel memory.</param>
    /// <param name="size"> - Number of bytes to read.</param>
    LIBSCYHV_API auto read_km(void* UmDst, void* KrnlSrc, size_t size) -> void;

    /// <summary>
    /// Writes data to kernel memory.
    /// </summary>
    /// <param name="KrnlDst"> - Destination address in kernel memory.</param>
    /// <param name="UmSrc"> - Usermode Source buffer containing the data to write.</param>
    /// <param name="size"> - Number of bytes to write.</param>
    LIBSCYHV_API auto write_km(void* KrnlDst, void* UmSrc, size_t size) -> void;

    /// <summary>
    /// Copies data between virtual addresses in different address spaces.
    /// </summary>
    /// <param name="dirbase_src"> - Directory Table Base (DTB) of the source address space.</param>
    /// <param name="virt_src"> - Source virtual address.</param>
    /// <param name="dirbase_dest"> - DTB of the destination address space.</param>
    /// <param name="virt_dest"> - Destination virtual address.</param>
    /// <param name="size"> - Number of bytes to copy.</param>
    /// <returns>Error code of type `vmxroot_error_t`</returns>
    LIBSCYHV_API auto copy_virt(guest_phys_t dirbase_src, guest_virt_t virt_src, guest_phys_t dirbase_dest,
        guest_virt_t virt_dest, u64 size) -> vmxroot_error_t;

    /// <summary>
    /// Reads a value from a guest virtual address.
    /// </summary>
    /// <param name="virt_addr"> - Guest virtual address.</param>
    /// <returns>The value read from memory.</returns>
    template <class T>
    auto read(guest_virt_t virt_addr) -> T;

    /// <summary>
    /// Writes a value to a guest virtual address.
    /// </summary>
    /// <param name="virt_addr"> - Guest virtual address.</param>
    /// <param name="data"> - The value to write to memory.</param>
    template <class T>
    auto write(guest_virt_t virt_addr, const T& data) -> void;

    /// <summary>
    /// Executes a system call by dynamically modifying kernel memory.
    /// </summary>
    /// <typeparam name="T">The function pointer type of the system call.</typeparam>
    /// <typeparam name="Ts">The parameter types of the system call.</typeparam>
    /// <param name="addr">The memory address of the system call to execute.</param>
    /// <param name="args">The arguments to pass to the system call.</param>
    /// <returns>The result of the system call execution.</returns>
    template <class T, class ... Ts>
    LIBSCYHV_API std::invoke_result_t<T, Ts...> syscall(void* addr, Ts ... args);

    /// <summary>
    /// Structure describing a page of physical memory.
    /// </summary>
#pragma pack(push, 1)
    struct PhysicalMemoryPage
    {
        uint8_t type;                  // Type of the memory resource
        uint8_t shareDisposition;      // Sharing status
        uint16_t flags;                // Memory flags
        uint64_t pBegin;               // Start of the physical memory page
        uint32_t sizeButNotExactly;    // Approximate size of the page
        uint32_t pad;                  // Padding

        // Constants for large memory resources
        static constexpr uint16_t cm_resource_memory_large_40{ 0x200 };
        static constexpr uint16_t cm_resource_memory_large_48{ 0x400 };
        static constexpr uint16_t cm_resource_memory_large_64{ 0x800 };

        /// <summary>
        /// Returns the exact size of the memory resource.
        /// </summary>
        /// <returns>Size of the memory resource.</returns>
        LIBSCYHV_API uint64_t size() const noexcept;
    };
#pragma pack(pop)
}

namespace util {
    /// <summary>
    /// Retrieves the base address of a kernel module by its name.
    /// </summary>
    /// <param name="module_name"> - Name of the kernel module to find.</param>
    /// <returns>Base address of the kernel module as a std::uintptr_t.</returns>
    LIBSCYHV_API auto get_kmodule_base(const char* module_name) -> std::uintptr_t;

    /// <summary>
    /// Retrieves the address of an exported function from a kernel module.
    /// </summary>
    /// <param name="module_name"> - Name of the kernel module containing the export.</param>
    /// <param name="export_name"> - Name of the exported function to find.</param>
    /// <param name="rva"> - If true, returns the Relative Virtual Address instead of the absolute address.</param>
    /// <returns>Pointer to the exported function, or nullptr if not found.</returns>
    LIBSCYHV_API auto get_kmodule_export(const char* module_name, const char* export_name, bool rva = false) -> void*;

    /// <summary>
    /// Retrieves the IMAGE_FILE_HEADER from a given base address of a PE file.
    /// </summary>
    /// <param name="base_addr"> - Base address of the PE file in memory.</param>
    /// <returns>Pointer to the IMAGE_FILE_HEADER structure.</returns>
    LIBSCYHV_API auto get_file_header(void* base_addr) -> PIMAGE_FILE_HEADER;
}

namespace ScyVDM
{
    class LIBSCYHV_API cVDM;
}
