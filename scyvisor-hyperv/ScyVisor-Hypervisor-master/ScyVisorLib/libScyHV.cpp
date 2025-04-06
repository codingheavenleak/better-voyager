#include <sstream>
#include "ScyVisor.h"
#include "libScyHV.hpp"
#include <iostream>
#include <ntstatus.h>
#include <winternl.h>
#include "lic.h"
#include "r0.hpp"

namespace ScyHV {
    namespace detail {
        bool& get_initialized() {
            static bool initialized = false;
            return initialized;
        }
    }
}

unsigned long long ScyHV::vmexitkey = 0x1419394384145284;

void ScyHV::check_initialization()
{
    if (!detail::get_initialized())
    {
        std::cerr << "ERROR: ScyHV::init() was not called. Terminating program to prevent BSOD." << std::endl;
        std::cerr << "Exiting in 3 seconds..." << std::endl;
        Sleep(3000);
        ExitProcess(1);
    }
}

namespace ScyVDM {


    read_phys_t cVDM::_read_phys = [](void* addr, void* buffer, std::size_t size) -> bool {
        const auto read_result = ScyHV::read_phys((u64)addr, (u64)buffer, size);
        return read_result == ScyHV::vmxroot_error_t::error_success;
        };

    write_phys_t cVDM::_write_phys = [](void* addr, void* buffer, std::size_t size) -> bool {
        const auto write_result = ScyHV::write_phys((u64)addr, (u64)buffer, size);
        return write_result == ScyHV::vmxroot_error_t::error_success;
        };

    LIBSCYHV_API cVDM& vdm = cVDM::getInstance();
}


static std::string secret_key = "";

LIBSCYHV_API void ScyHV::set_secret_key(const std::string& key)
{
    secret_key = key;
}

LIBSCYHV_API const std::string& ScyHV::get_secret_key()
{
    return secret_key;
}

LIBSCYHV_API auto ScyHV::initPTB() -> bool {
  
    BOOL bRet = false;
    PUCHAR Data = (PUCHAR)malloc(0x1000);
    if (Data == NULL)
        return false;

    ULONG Cr3Offset = ULONG(FIELD_OFFSET(PROCESSOR_START_BLOCK, ProcessorState) + FIELD_OFFSET(KSPECIAL_REGISTERS, Cr3));
    for (DWORD_PTR Addr = 0; Addr < 0x100000; Addr += 0x1000)
    {
        if (ScyHV::read_phys((ULONG64)Addr, (ULONG64)(void*)Data, 0x1000) == SCY_SUCCESS)
        {
            if (0x00000001000600E9 != (0xFFFFFFFFFFFF00FF & *(UINT64*)(Data)))
                continue;

            if (0xFFFFF80000000000 != (0xFFFFF80000000003 & *(UINT64*)(Data + FIELD_OFFSET(PROCESSOR_START_BLOCK, LmTarget))))
                continue;

            if (0xFFFFFF0000000FFF & *(UINT64*)(Data + Cr3Offset))
                continue;

            KernelCr3 = *(UINT64*)(Data + Cr3Offset);
            bRet = true;
            break;
        }
    }
    if (Data)
        free(Data);

    return bRet;
}

LIBSCYHV_API auto ScyHV::my_dtb()->guest_phys_t
{
    ScyHV::check_initialization();
    command_t command;
    auto result = hypercall(VMEXIT_KEY, vmexit_command_t::get_dirbase, &command);

    if (result != SCY_SUCCESS)
        return {};

    return command.dirbase;
}

LIBSCYHV_API auto ScyHV::get_pid(const wchar_t* proc_name) -> std::uint32_t
{
    ScyHV::check_initialization();
    PROCESSENTRY32 proc_info;
    proc_info.dwSize = sizeof(proc_info);

    HANDLE proc_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (proc_snapshot == INVALID_HANDLE_VALUE)
        return NULL;

    Process32First(proc_snapshot, &proc_info);
    if (!wcscmp(proc_info.szExeFile, proc_name))
    {
        CloseHandle(proc_snapshot);
        return proc_info.th32ProcessID;
    }

    while (Process32Next(proc_snapshot, &proc_info))
    {
        if (!wcscmp(proc_info.szExeFile, proc_name))
        {
            CloseHandle(proc_snapshot);
            return proc_info.th32ProcessID;
        }
    }

    CloseHandle(proc_snapshot);
    return NULL;
}

LIBSCYHV_API auto ScyHV::init() -> bool {
    if (detail::get_initialized()) {
        std::cout << "ScyHV already initialized." << std::endl;
        return true;
    }

    if (!loadWinsockFunctions()) {
        std::cout << "Failed to load Winsock functions." << std::endl;
        return false;
    }

    std::string encryptedKey = xorEncrypt(get_secret_key(), XOR_KEY);
    std::string hexEncryptedKey = bytesToHexString(encryptedKey);
    std::string ipInfo = getClientIPInfo();
    std::string dateTime = getCurrentDateTime();
    std::string payload = "{\"SECRET_KEY\":\"" + hexEncryptedKey + "\", \"CLIENT_INFO\": {\"datetime\": \"" + dateTime + "\", \"ip_info\": " + ipInfo + "}}";
    std::stringstream request;
    request << "POST /api/validate HTTP/1.1\r\n"
        << "Host: " << SERVER_HOST << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << payload.length() << "\r\n"
        << "\r\n"
        << payload;

    std::cout << "Validating Secret Key ...." << std::endl;
    std::string response = sendRequest(SERVER_HOST, SERVER_PORT, request.str());

    if (response.empty()) {
        std::cout << "Failed to get response from server." << std::endl;
        return false;
    }

    if (response.find("true") != std::string::npos) {
        std::cout << "Secret Key successfully validated. continue" << std::endl;
        detail::get_initialized() = true;
        return true;
    }
    else {
        std::cout << "Invalid Secret Key. Program will terminate." << std::endl;
        return false;
    }
}

LIBSCYHV_API auto ScyHV::get_proc_base(std::uint32_t pid) -> uint32_t
{
    ScyHV::check_initialization();
    if (!pid)
        return 0;

    auto peproc = ScyVDM::vdm.get_peprocess(pid);

    if (!peproc)
        return 0;

    using PsGetProcessSectionBaseAddress = PVOID(__fastcall*)(PEPROCESS);
    uint32_t Base = (uint32_t)ScyVDM::vdm.syscall<PsGetProcessSectionBaseAddress>((void*)ProcBaseProt, peproc);

    return Base;
}

LIBSCYHV_API auto ScyHV::get_proc_dtb(std::uint32_t pid) -> std::uintptr_t {
    const auto peproc = ScyVDM::vdm.get_peprocess(pid);

    if (!peproc)
        return {};

    return ScyVDM::vdm.rkm<cr3>(reinterpret_cast<std::uintptr_t>(peproc) + 0x28).pml4_pfn << 12;

}

LIBSCYHV_API auto ScyHV::get_eac_dtb(std::uint32_t pid) -> uintptr_t {
    if (!driver::initialize_handle()) {
        printf("Failed to initialize driver handle");
    }
    printf("Walking Pagetables...\n");
    Sleep(100);
    if (!driver::update(pid)) {
        printf("Failed to attach to process\n");
    }

    uintptr_t local_image_base = driver::get_image_base(0);
    if (local_image_base == 0) {
        printf("Failed to get image base\n");
    }

    uintptr_t local_directory_base = driver::get_dtb(pid);
    if (local_directory_base == 0) {
        printf("Failed to get directory base\n");
    }

    driver::image_base = local_image_base;
    driver::directory_base = local_directory_base;

    return local_directory_base;
}

LIBSCYHV_API auto ScyHV::translate(guest_virt_t virt_addr) -> guest_phys_t
{
    command_t command;
    command.translate_virt.virt_src = virt_addr;

    const auto result = hypercall(VMEXIT_KEY, vmexit_command_t::translate, &command);

    if (result != SCY_SUCCESS)
        return {};

    return command.translate_virt.phys_addr;
}

LIBSCYHV_API auto ScyHV::read_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> vmxroot_error_t
{
    command_t command;
    command.copy_phys = { phys_addr, buffer, size };
    return hypercall(VMEXIT_KEY, vmexit_command_t::read_guest_phys, &command);
}

LIBSCYHV_API void ScyHV::read_km(void* UmDst, void* KrnlSrc, std::size_t size)
{
    static const auto ntoskrnl_memcpy =
        util::get_kmodule_export("ntoskrnl.exe", "memcpy");

    ScyVDM::vdm.syscall<decltype(&memcpy)>(ntoskrnl_memcpy, UmDst, KrnlSrc, size);
}

LIBSCYHV_API auto ScyHV::write_phys(guest_phys_t phys_addr, guest_virt_t buffer, u64 size) -> vmxroot_error_t
{
   
    command_t command;
    command.copy_phys = { phys_addr, buffer, size };
    return hypercall(VMEXIT_KEY, vmexit_command_t::write_guest_phys, &command);
}

LIBSCYHV_API void ScyHV::write_km(void* KrnlDst, void* UmSrc, size_t size)
{
    static const auto ntoskrnl_memcpy =
        util::get_kmodule_export("ntoskrnl.exe", "memcpy");

    ScyVDM::vdm.syscall<decltype(&memcpy)>(ntoskrnl_memcpy, KrnlDst, UmSrc, size);
}

LIBSCYHV_API auto ScyHV::copy_virt(guest_phys_t dirbase_src, guest_virt_t virt_src, guest_phys_t dirbase_dest, guest_virt_t virt_dest, u64 size) -> vmxroot_error_t
{
    command_t command;
    command.copy_virt = { dirbase_src, virt_src, dirbase_dest, virt_dest, size };
    return hypercall(VMEXIT_KEY, vmexit_command_t::copy_guest_virt, &command);
}

LIBSCYHV_API auto ScyHV::get_kmodule_address() -> bool {
    ScyVDM::ntoskrnl = reinterpret_cast<uint8_t*>(util::get_kmodule_base("ntoskrnl.exe"));
    if (!ScyVDM::ntoskrnl) {
        printf("Failed to get ntoskrnl.exe base address\n");
        return false;
    }
    printf("\n[+] ntoskrnl.exe Base address: 0x%x", ScyVDM::ntoskrnl);

    const auto ntdll_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("ntdll.dll"));
    if (!ntdll_base) {
        printf("Failed to get ntdll.dll base address\n");
        return false;
    }
    printf("\n[+] ntdll.dll Base address: 0x%x", ntdll_base);

    ScyHV::NtShutdownSystemVa = (ULONG64)util::get_kmodule_export("ntoskrnl.exe", ScyVDM::syscall_hook.first);
    if (!ScyHV::NtShutdownSystemVa) {
        printf("Failed to get NtShutdownSystemVa address\n");
        return false;
    }
    //printf("\n[+] NtShutdownSystemVa: %p\n", ScyHV::NtShutdownSystemVa);

    ScyHV::MemCopy = (ULONG64)util::get_kmodule_export("ntoskrnl.exe", "memcpy");
    if (!ScyHV::MemCopy) {
        printf("Failed to get MemCopy address\n");
        return false;
    }
    printf("[+] MemCopy: %p\n", ScyHV::MemCopy);

    ScyHV::PsLookupPeproc = (ULONG64)util::get_kmodule_export("ntoskrnl.exe", "PsLookupProcessByProcessId");
    if (!ScyHV::PsLookupPeproc) {
        printf("Failed to get PsLookupPeproc address\n");
        return false;
    }
    printf("[+] PsLookupPeproc: %p\n", ScyHV::PsLookupPeproc);

    ScyHV::ObDereferenceObject = (ULONG64)util::get_kmodule_export("ntoskrnl.exe", "ObfDereferenceObject");
    if (!ScyHV::ObDereferenceObject) {
        printf("Failed to get ObDereferenceObject address\n");
        return false;
    }
    printf("[+] ObDereferenceObject: %p\n", ScyHV::ObDereferenceObject);

    ScyHV::ProcBaseProt = (ULONG64)util::get_kmodule_export("ntoskrnl.exe", "PsGetProcessSectionBaseAddress");
    if (!ScyHV::ProcBaseProt) {
        printf("Failed to get ProcBaseProt address\n");
        return false;
    }
    printf("[+] ProcBaseProt: %p\n", ScyHV::ProcBaseProt);

    ScyHV::ProcPebProt = (ULONG64)util::get_kmodule_export("ntoskrnl.exe", "PsGetProcessPeb");
    if (!ScyHV::ProcPebProt) {
        printf("Failed to get ProcPebProt address\n");
        return false;
    }
    printf("[+] ProcPebProt: %p\n", ScyHV::ProcPebProt);

    return true;
}

namespace ScyVDM
{
    LIBSCYHV_API std::atomic<void*> ScyVDM::syscall_address;

    cVDM::cVDM(read_phys_t& read_func, write_phys_t& write_func)
        : read_phys(read_func), write_phys(write_func)
    {
        // std::cout << "cVDM constructor called" << std::endl;
        // std::cout << "read_phys address: " << &read_phys << std::endl;
        // std::cout << "write_phys address: " << &write_phys << std::endl;

        if (!read_phys || !write_phys) {
            throw std::runtime_error("read_phys or write_phys is null in constructor");
        }
        if (ScyVDM::syscall_address.load())
            return;

        ScyVDM::ntoskrnl = reinterpret_cast<std::uint8_t*>(
            LoadLibraryExA("ntoskrnl.exe", NULL,
                DONT_RESOLVE_DLL_REFERENCES));

        nt_rva = reinterpret_cast<std::uint32_t>(
            util::get_kmodule_export(
                "ntoskrnl.exe",
                syscall_hook.first,
                true
            ));

        ScyVDM::nt_page_offset = nt_rva % PAGE_4KB;
        std::vector<std::thread> search_threads;

        for (auto ranges : util::pmem_ranges)
            search_threads.emplace_back(std::thread(
                &cVDM::locate_syscall,
                this,
                ranges.first,
                ranges.second
            ));

        for (std::thread& search_thread : search_threads)
            search_thread.join();
    }

    void cVDM::set_read(read_phys_t& read_func)
    {
        this->read_phys = read_func;
    }

    void cVDM::set_write(write_phys_t& write_func)
    {
        this->write_phys = write_func;
    }

    void cVDM::locate_syscall(std::uintptr_t address, std::uintptr_t length) const
    {
        // std::cout << "Entering locate_syscall. Address: " << std::hex << address << ", Length: " << length << std::endl;

        if (!read_phys || !write_phys) {
            throw std::runtime_error("read_phys or write_phys is null");
        }

        if (!ntoskrnl || nt_rva == 0) {
            throw std::runtime_error("ntoskrnl is null or nt_rva is 0");
        }

        try {
            const auto page_data = reinterpret_cast<std::uint8_t*>(
                VirtualAlloc(nullptr, PAGE_4KB, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

            if (!page_data) {
                throw std::runtime_error("Failed to allocate memory for page_data");
            }

            std::atomic<bool> syscall_found{ false };

            // accesses the page in order to make PTE...
            memset(page_data, NULL, PAGE_4KB);
            for (auto page = 0u; page < length; page += PAGE_4KB)
            {
                if (syscall_found.load(std::memory_order_relaxed))
                    break;

                size_t read_size = (page + PAGE_4KB > length) ? (length - page) : PAGE_4KB;
                if (!read_phys(reinterpret_cast<void*>(address + page), page_data, read_size))
                {
                    // std::cout << "read_phys failed at address: " << std::hex << (address + page) << std::endl;
                    continue;
                }

                // check the first 32 bytes of the syscall, if its the same, test that its the correct
                // occurrence of these bytes (since dxgkrnl is loaded into physical memory at least 2 times now)...
                if (!memcmp(page_data + nt_page_offset, ntoskrnl + nt_rva, 32))
                {
                    if (valid_syscall(reinterpret_cast<void*>(address + page + nt_page_offset)))
                    {
                        void* expected = nullptr;
                        if (syscall_address.compare_exchange_strong(expected, reinterpret_cast<void*>(address + page + nt_page_offset)))
                        {
                            syscall_found.store(true, std::memory_order_release);
                            // std::cout << "Syscall address found: " << std::hex << (address + page + nt_page_offset) << std::endl;
                        }
                    }
                }
            }
            VirtualFree(page_data, 0, MEM_RELEASE);
        }
        catch (const std::exception& e) {
             std::cerr << "Exception in locate_syscall: " << e.what() << std::endl;
        }
        catch (...) {
             std::cerr << "Unknown exception in locate_syscall" << std::endl;
        }
    }

    bool cVDM::valid_syscall(void* syscall_addr) const
    {
        static std::mutex syscall_mutex;
        std::lock_guard<std::mutex> lock(syscall_mutex);

        static const auto proc =
            GetProcAddress(
                LoadLibraryA(syscall_hook.second),
                syscall_hook.first
            );

        // 0:  48 31 c0    xor rax, rax
        // 3 : c3          ret
        std::uint8_t shellcode[] = { 0x48, 0x31, 0xC0, 0xC3 };
        std::uint8_t orig_bytes[sizeof shellcode];

        // save original bytes and install shellcode...
        read_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
        write_phys(syscall_addr, shellcode, sizeof shellcode);

        auto result = reinterpret_cast<NTSTATUS(__fastcall*)(void)>(proc)();
        write_phys(syscall_addr, orig_bytes, sizeof orig_bytes);
        return result == STATUS_SUCCESS;
    }
}

