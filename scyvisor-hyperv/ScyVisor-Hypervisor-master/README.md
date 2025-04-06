# ScyVisor - Hyper-V Hijack Framework (Private)

---

## Features

The framework is divided into the following modules, each offering key functionalities:

### **Core Features**
- **Initialization and Management**:
  - `init()` - Initializes the ScyVisor.
  - `initPTB()` - Initializes the page tables of the guest. (not really necessary to use, but needed in some cases)
- **Address Translation**:
  - `translate()` - Translates guest virtual addresses to guest physical addresses.
- **Memory Operations**:
  - Read and write access to guest physical memory (`read_phys`, `write_phys`).
  - Read and write access to kernel modules (`read_km`, `write_km`) (hooking capability - hiding kernelmode and usermode modules).
  - Copying data between virtual addresses in different address spaces (`copy_virt`).
- **Process Management**:
  - Retrieve process ID (PID) by process name (`get_pid`).
  - Retrieve the base address of a process in memory (`get_proc_base`).
  - Retrieve the Directory Table Base (DTB) of a process (`get_proc_dtb`).
  - **EAC-specific DTB detection**: Supports games protected by EAC's CR3 Shuffling - like Rust, Fortnite, and Apex Legends (`get_eac_dtb`).
- **Kernel Module Hooking**:
  - Retrieve the base address of a kernel module (`get_kmodule_base`).
  - Locate exported functions of a kernel module (`get_kmodule_export`).
- **Advanced Memory Management**:
  - Structure for physical memory resources (e.g., `PhysicalMemoryPage`).
  - Support for large memory resources (`cm_resource_memory_large_*`).
- **System Calls**:
  - Dynamic system calls by modifying kernel memory (`syscall`). (detection bypass via hyper-v)

### **Error Handling**
- **Defined error codes** for various functions (e.g., `SCY_SUCCESS`, `SCY_PML4E_NOT_PRESENT`).
- Support for detailed error analysis in address translation and memory operations.

---

## To-Do / Pending Implementation

### **ScyVisorUEFI**
- Use **Hyper-V Memory Allocation Manager** for payload memory allocation.
- Eliminate potential detection vectors:
  - Research alternatives to the current hook chain.
  - Investigate the possibility of a payload-free hooking approach.

### **ScyVisorLib**
- Implement **ShadowEPT** in the library.
- Encrypt **ScyVisorLib** for added security.
- Clean and optimize the codebase for better maintainability.
- Improve API structure inside the ScyVisor.h
- implementing global variables in scyvisor.h especially for processCr3 and myCr3.
- implement TrCrypt -> to give the capability to encrypt any string on compile time with AES 128 CBC.

### **ScyVisorUsage**
- Add **ShadowEPT examples** to the usage documentation.
- Provide detailed examples for advanced techniques, such as cross-address-space memory copying and hiding usermode/kernelmode modules effectively by hooking kernelmodules and/or by using shadowEPT.

### **ScyVisorInit**
- Encrypt **ScyVisorInit**
- Enhance initialization security by improving configuration encryption.

---

## Supported Platforms
- **Windows 10 22H2 & Windows 11 24H2 ** Intel Vt-x supported processors only.
- may work on Mobile systems (laptops) but officially not supported.
- EAC-protected games.
- BattleEye-protected games.
- Riccochet-protected games.
- Marvel Rivals
- Overwatch 2
- World of Warcraft
- etc. 

---

## Notes
Except the Usage Project everything else is PRIVATE and should never be seen by the public, the library will be an encrypted static library we can send our customers including the global headers (dependencies/includes).
