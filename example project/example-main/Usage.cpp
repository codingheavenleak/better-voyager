#include <iostream>
#include <iomanip>
#include <thread>
#include "ScyVisor.h"



int main()
{

	// Initialize the hyper-v communication, if it doesnt is called you will get instant BSOD
    if (!ScyHV::init()) {
        std::cout << "Initialization failed. Exiting." << std::endl;
        return 1;
    }

    // Getting our own DirBase
    ScyHV::guest_phys_t MyCr3 = ScyHV::my_dtb();
    if (MyCr3 == 0) {
        std::cout << "Failed obtaining My DTB! press any key to close...\n";
        std::cin.get();
        ExitProcess(0);
    }
    std::cout << "[+] Retrieved My CR3: 0x" << std::hex << MyCr3 << std::endl;

    // Loading Kernel Module Addresses that are necessary for further steps
    bool kModuleInit = ScyHV::get_kmodule_address();
    if (!kModuleInit) {
        std::cout << "[-] Failed to load Kernel Module Addresses! press any key to close...";
        std::cin.get();
        ExitProcess(0);
    }
    std::cout << "[+] All necessary Kernel Module Addresses retrieved!" << std::endl;

    // Getting target process id
    std::uint32_t PID = ScyHV::get_pid(L"explorer.exe"); //add here the Process Name
    if (PID == 0) {
        std::cout << "Failed obtaining Process ID! press any key to close...\n";
        std::cin.get();
        ExitProcess(0);
    }
    std::cout << "\n[+] Retrieved Target Process ID: " << PID << std::endl;

    // Getting process module Base address
    std::uint32_t ImageBase = ScyHV::get_proc_base(PID);
    if (ImageBase == 0) {
        std::cout << "Failed to get Process Base Address! press any key to close...\n";
        std::cin.get();
        ExitProcess(0);
    }
    std::cout << "[+] Retrieved Target Base Address: 0x" << std::hex << ImageBase << std::endl;

	// Getting target process cr3 (no EAC CR3 Shuffling supported!)
    ScyHV::guest_phys_t ProcessCr3 = ScyHV::get_proc_dtb(PID); 
    if (ProcessCr3 == 0) {
        std::cout << "Failed to get Target CR3! press any key to close...\n";
        std::cin.get();
        ExitProcess(0);
    }
    std::cout << "[+] Retrieved Target Process CR3: 0x" << std::hex << ProcessCr3 << std::endl;

    // Include testing framework here
    // Currently it is NOT implemented in the hypervisor
    
    std::cout << "[!] press any key to close...\n";
    std::cin.get();

}


