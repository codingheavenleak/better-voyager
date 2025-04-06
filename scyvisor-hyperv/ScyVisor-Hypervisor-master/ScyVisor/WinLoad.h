#pragma once
#pragma warning(disable : 4022)

#include "HvLoader.h"
#include "PayLoad.h"


extern INLINE_HOOK WinLoadImageShitHook;
extern INLINE_HOOK WinLoadAllocateImageHook;

// Version-specific definitions and signatures
#if WINVER == 2302
	// Signature for BlImgAllocateImageBuffer in Windows 24H2 -> winload.efi
    
#define ALLOCATE_IMAGE_BUFFER_SIG "\x41\xB8\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0\x78\x00\x21\x7C\x24"
#define ALLOCATE_IMAGE_BUFFER_MASK "xx????x????xxxxx?xxx"
//#define ALLOCATE_IMAGE_BUFFER_SIG "\x41\x8B\xD6\x41\xB8\x00\x00\x00\x00\xE8"
//#define ALLOCATE_IMAGE_BUFFER_MASK "xxxxx????x"

typedef UINT64(EFIAPI* ALLOCATE_IMAGE_BUFFER)(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType,
    UINT32 attributes, VOID* unused, UINT32 Value);

typedef EFI_STATUS(EFIAPI* LDR_LOAD_IMAGE)(VOID* a1, VOID* a2, CHAR16* ImagePath, UINT64* ImageBasePtr, UINT32* ImageSize,
    VOID* a6, VOID* a7, VOID* a8, VOID* a9, VOID* a10, VOID* a11, VOID* a12, VOID* a13, VOID* a14, VOID* a15, VOID* a16, VOID* a17);


#else


    // Signature for BlImgAllocateImageBuffer in Windows 2004-1511
#define ALLOCATE_IMAGE_BUFFER_SIG "\x41\xB8\x0A\x00\x00\xD0\x00\x00\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0"
#define ALLOCATE_IMAGE_BUFFER_MASK "xxxxxx??x????xxxx"

// Signature for BlImgLoadPEImageEx in Windows 1703-1511
#define LOAD_PE_IMG_SIG "\x48\x89\x44\x24\x00\xE8\x00\x00\x00\x00\x44\x8B\xF0\x85\xC0\x79\x11"
#define LOAD_PE_IMG_MASK "xxxx?x????xxxxxxx"

typedef UINT64(EFIAPI* ALLOCATE_IMAGE_BUFFER)(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType,
    UINT32 attributes, VOID* unused, UINT32 Value);

typedef EFI_STATUS(EFIAPI* LDR_LOAD_IMAGE)(VOID* a1, VOID* a2, CHAR16* ImagePath, UINT64* ImageBasePtr, UINT32* ImageSize,
    VOID* a6, VOID* a7, VOID* a8, VOID* a9, VOID* a10, VOID* a11, VOID* a12, VOID* a13, VOID* a14, VOID* a15, VOID* a16);
#endif


static_assert(sizeof(ALLOCATE_IMAGE_BUFFER_SIG) == sizeof(ALLOCATE_IMAGE_BUFFER_MASK), "Signature and mask sizes do not match!");

// Function prototypes

/*
 * @brief Hooks BlImgLoadPEImageEx to intercept image loading (for Windows 1703-1507)
 *
 * This function is used to install hooks inside hvloader.efi. It hooks winload.BlImgLoadPEImageEx
 * to detect when hvloader.efi is loaded into memory.
 *
 * @param a1 Unknown parameter
 * @param a2 Unknown parameter
 * @param ImagePath Unicode string path to the image being loaded
 * @param ImageBasePtr Pointer to store the base address of the loaded module
 * @param ImageSize Pointer to store the size of the loaded image
 * @param a6-a14 Unknown parameters
 * @return EFI_STATUS Status of the image loading operation
 */
EFI_STATUS EFIAPI BlImgLoadPEImageEx(
    VOID* a1, VOID* a2, CHAR16* ImagePath, UINT64* ImageBasePtr, UINT32* ImageSize,
    VOID* a6, VOID* a7, VOID* a8, VOID* a9, VOID* a10, VOID* a11, VOID* a12, VOID* a13, VOID* a14);

/**
 * @brief Hooks BlImgAllocateImageBuffer to extend allocation size and set RWX permissions (for Windows 2004-1709)
 *
 * This function hooks BlImgAllocateImageBuffer, which is called by BlLdrLoadImage to allocate memory
 * for the Hyper-V module. It extends the allocation size and sets the entire allocation as RWX.
 *
 * @param imageBuffer Pointer to store the base address of the allocation
 * @param imageSize Size of the allocation
 * @param memoryType Type of memory to allocate
 * @param attributes Memory attributes
 * @param unused Unused parameter
 * @param Value Additional flags
 * @return EFI_STATUS Status of the memory allocation operation
 */
EFI_STATUS EFIAPI BlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID* unused, UINT32 Value);

/**
 * @brief Hooks BlLdrLoadImage to intercept Hyper-V loading (for Windows 2004-1709)
 *
 * This function hooks BlLdrLoadImage, which is exported from winload. It's used to install
 * hooks and extend Hyper-V's allocation when Hyper-V is being loaded.
 *
 * @param Arg1-Arg17 Various parameters, some unknown
 * @param ModulePath Path to the module being loaded
 * @param ModuleName Name of the module being loaded
 * @param lplpTableEntry Pointer to the LDR_DATA_TABLE_ENTRY structure
 * @return EFI_STATUS Status of the module loading operation
 */
#if WINVER == 2302
EFI_STATUS EFIAPI BlLdrLoadImage(
    int Arg1, int Arg2, CHAR16* ImagePath, CHAR16* ModuleName, UINT64 ImageSize,
    int Arg6, int Arg7, PPLDR_DATA_TABLE_ENTRY lplpTableEntry, UINT64 Arg9,
    UINT64 Arg10, int Arg11, int Arg12, int Arg13, int Arg14, int Arg15,
    UINT64 Arg16, UINT64 Arg17
);
#else
EFI_STATUS EFIAPI BlLdrLoadImage(
    VOID* Arg1, CHAR16* ImagePath, CHAR16* ModuleName, UINT64 ImageSize, VOID* Arg5,
    VOID* Arg6, VOID* Arg7, PPLDR_DATA_TABLE_ENTRY lplpTableEntry, VOID* Arg9,
    VOID* Arg10, VOID* Arg11, VOID* Arg12, VOID* Arg13, VOID* Arg14, VOID* Arg15,
    VOID* Arg16
);
#endif