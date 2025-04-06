#pragma once

#include "WinLoad.h"

// Signatures and masks for different Windows versions
#if WINVER == 2302
    // Signature for ImgArchStartBootApplication in Windows 11 Build 24H2 -> located in Winload.efi -> mov   rax, rsp of ImgArchStartBootApplication
    // 48 8B C4 48 89 58 ? 44 89 40 ? 48 89 50 ? 48 89 48 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 68 ? 48 81 EC ? ? ? ? 0F 57 C0
#define START_BOOT_APPLICATION_SIG "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68\xA9"
#define START_BOOT_APPLICATION_MASK "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
#else
    // Signature for ImgArchStartBootApplication in Windows 10 Build 22H2  -> located in Winload.efi -> mov   rax, rsp of ImgArchStartBootApplication
#define START_BOOT_APPLICATION_SIG "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x68\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\xF9"
#define START_BOOT_APPLICATION_MASK "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx?xxx????xxx"
#endif

// Ensure signature and mask sizes match
static_assert(sizeof(START_BOOT_APPLICATION_SIG) == sizeof(START_BOOT_APPLICATION_MASK), "Signature and mask sizes don't match");

// File paths
#define WINDOWS_BOOTMGFW_PATH L"\\efi\\microsoft\\boot\\bootmgfw.efi"
#define WINDOWS_BOOTMGFW_BACKUP_PATH L"\\efi\\microsoft\\boot\\bootmgfw.efi.backup"

// External declarations
extern INLINE_HOOK BootMgfwShitHook;

// Function pointer type for ImgArchStartBootApplication
typedef EFI_STATUS(EFIAPI* IMG_ARCH_START_BOOT_APPLICATION)(VOID*, VOID*, UINT32, UINT8, VOID*);

// Function prototypes
EFI_STATUS EFIAPI RestoreBootMgfw(VOID);
EFI_STATUS EFIAPI GetBootMgfwPath(EFI_DEVICE_PATH** BootMgfwDevicePath);
EFI_STATUS EFIAPI InstallBootMgfwHooks(EFI_HANDLE BootMgfwPath);
/**
 * @brief Hook function for ArchStartBootApplication
 *
 * This function is called when winload is loaded into memory.
 * All hooks related to winload will be installed here.
 *
 * @param AppEntry Pointer to the application entry point
 * @param ImageBase Base address of winload in memory
 * @param ImageSize Size of winload in memory (not on disk)
 * @param BootOption Boot option flags
 * @param ReturnArgs Pointer to return arguments structure
 * @return EFI_STATUS Original function's return value
 */
EFI_STATUS EFIAPI ArchStartBootApplicationHook(VOID* AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, VOID* ReturnArgs);