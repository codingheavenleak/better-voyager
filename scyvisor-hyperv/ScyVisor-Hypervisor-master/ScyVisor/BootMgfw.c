#pragma warning(disable : 4047)
#pragma warning(disable : 4024)
#include "BootMgfw.h"

INLINE_HOOK BootMgfwShitHook;
PSCYVISOR_T ScyvisorData;

EFI_STATUS EFIAPI RestoreBootMgfw(VOID)
{
    UINTN HandleCount = NULL;
    EFI_STATUS Result;
    EFI_HANDLE* Handles = NULL;
    EFI_FILE_HANDLE VolumeHandle;
    EFI_FILE_HANDLE BootMgfwHandle;
    EFI_FILE_IO_INTERFACE* FileSystem = NULL;

    // Locate all file system handles
    if (EFI_ERROR((Result = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles))))
    {
        Print(L"Error getting file system handles -> 0x%p\n", Result);
        return Result;
    }

    // Iterate through all file system handles
    for (UINT32 Idx = 0u; Idx < HandleCount; ++Idx)
    {
        // Open the file system protocol
        if (EFI_ERROR((Result = gBS->OpenProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL))))
        {
            Print(L"Error opening protocol -> 0x%p\n", Result);
            return Result;
        }

        // Open the volume
        if (EFI_ERROR((Result = FileSystem->OpenVolume(FileSystem, &VolumeHandle))))
        {
            Print(L"Error opening file system -> 0x%p\n", Result);
            return Result;
        }

        // Try to open the bootmgfw.efi file
        if (!EFI_ERROR((Result = VolumeHandle->Open(VolumeHandle, &BootMgfwHandle, WINDOWS_BOOTMGFW_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY))))
        {
            VolumeHandle->Close(VolumeHandle);
            EFI_FILE_PROTOCOL* BootMgfwFile = NULL;
            EFI_DEVICE_PATH* BootMgfwPathProtocol = FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_PATH);

            // Open bootmgfw.efi as read/write then delete it
            if (EFI_ERROR((Result = EfiOpenFileByDevicePath(&BootMgfwPathProtocol, &BootMgfwFile, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, NULL))))
            {
                Print(L"Error opening bootmgfw... reason -> %r\n", Result);
                return Result;
            }

            if (EFI_ERROR((Result = BootMgfwFile->Delete(BootMgfwFile))))
            {
                Print(L"Error deleting bootmgfw... reason -> %r\n", Result);
                return Result;
            }

            // Open bootmgfw.efi.backup
            BootMgfwPathProtocol = FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_BACKUP_PATH);
            if (EFI_ERROR((Result = EfiOpenFileByDevicePath(&BootMgfwPathProtocol, &BootMgfwFile, EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, NULL))))
            {
                Print(L"Failed to open backup file... reason -> %r\n", Result);
                return Result;
            }

            // Get the size of bootmgfw.efi.backup
            EFI_FILE_INFO* FileInfoPtr = NULL;
            UINTN FileInfoSize = NULL;
            if (EFI_ERROR((Result = BootMgfwFile->GetInfo(BootMgfwFile, &gEfiFileInfoGuid, &FileInfoSize, NULL))))
            {
                if (Result == EFI_BUFFER_TOO_SMALL)
                {
                    gBS->AllocatePool(EfiBootServicesData, FileInfoSize, &FileInfoPtr);
                    if (EFI_ERROR(Result = BootMgfwFile->GetInfo(BootMgfwFile, &gEfiFileInfoGuid, &FileInfoSize, FileInfoPtr)))
                    {
                        Print(L"Get backup file information failed... reason -> %r\n", Result);
                        return Result;
                    }
                }
                else
                {
                    Print(L"Failed to get file information... reason -> %r\n", Result);
                    return Result;
                }
            }

            // Read the backup file into an allocated pool
            VOID* BootMgfwBuffer = NULL;
            UINTN BootMgfwSize = FileInfoPtr->FileSize;
            gBS->AllocatePool(EfiBootServicesData, FileInfoPtr->FileSize, &BootMgfwBuffer);

            if (EFI_ERROR((Result = BootMgfwFile->Read(BootMgfwFile, &BootMgfwSize, BootMgfwBuffer))))
            {
                Print(L"Failed to read backup file into buffer... reason -> %r\n", Result);
                return Result;
            }

            // Delete the backup file
            if (EFI_ERROR((Result = BootMgfwFile->Delete(BootMgfwFile))))
            {
                Print(L"Unable to delete backup file... reason -> %r\n", Result);
                return Result;
            }

            // Create a new bootmgfw file
            BootMgfwPathProtocol = FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_PATH);
            if (EFI_ERROR((Result = EfiOpenFileByDevicePath(&BootMgfwPathProtocol, &BootMgfwFile, EFI_FILE_MODE_CREATE | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_READ, EFI_FILE_SYSTEM))))
            {
                Print(L"Unable to create new bootmgfw on disk... reason -> %r\n", Result);
                return Result;
            }

            // Write the data from the backup file to the new bootmgfw file
            BootMgfwSize = FileInfoPtr->FileSize;
            if (EFI_ERROR((Result = BootMgfwFile->Write(BootMgfwFile, &BootMgfwSize, BootMgfwBuffer))))
            {
                Print(L"Unable to write to newly created bootmgfw.efi... reason -> %r\n", Result);
                return Result;
            }

            BootMgfwFile->Close(BootMgfwFile);
            gBS->FreePool(FileInfoPtr);
            gBS->FreePool(BootMgfwBuffer);
            return EFI_SUCCESS;
        }

        // Close the protocol if bootmgfw.efi was not found
        if (EFI_ERROR((Result = gBS->CloseProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL))))
        {
            Print(L"Error closing protocol -> 0x%p\n", Result);
            return Result;
        }
    }

    gBS->FreePool(Handles);
    return EFI_ABORTED;
}

EFI_STATUS EFIAPI GetBootMgfwPath(EFI_DEVICE_PATH** BootMgfwDevicePath)
{
	UINTN HandleCount = NULL;
	EFI_STATUS Result;
	EFI_HANDLE* Handles = NULL;
	EFI_FILE_HANDLE VolumeHandle;
	EFI_FILE_HANDLE BootMgfwHandle;
	EFI_FILE_IO_INTERFACE* FileSystem = NULL;

	if (EFI_ERROR((Result = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles))))
	{
		Print(L"error getting file system handles -> 0x%p\n", Result);
		return Result;
	}

	for (UINT32 Idx = 0u; Idx < HandleCount; ++Idx)
	{
		if (EFI_ERROR((Result = gBS->OpenProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL))))
		{
			Print(L"error opening protocol -> 0x%p\n", Result);
			return Result;
		}

		if (EFI_ERROR((Result = FileSystem->OpenVolume(FileSystem, &VolumeHandle))))
		{
			Print(L"error opening file system -> 0x%p\n", Result);
			return Result;
		}

		if (!EFI_ERROR(VolumeHandle->Open(VolumeHandle, &BootMgfwHandle, WINDOWS_BOOTMGFW_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY)))
		{
			VolumeHandle->Close(BootMgfwHandle);
			*BootMgfwDevicePath = FileDevicePath(Handles[Idx], WINDOWS_BOOTMGFW_PATH);
			return EFI_SUCCESS;
		}

		if (EFI_ERROR((Result = gBS->CloseProtocol(Handles[Idx], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL))))
		{
			Print(L"error closing protocol -> 0x%p\n", Result);
			return Result;
		}
	}
	return EFI_NOT_FOUND;
}

EFI_STATUS EFIAPI InstallBootMgfwHooks(EFI_HANDLE ImageHandle)
{
	EFI_STATUS Result = EFI_SUCCESS;
	EFI_LOADED_IMAGE* BootMgfw = NULL;

	Print(L"[!] Preparing bypass...\n");

	if (EFI_ERROR(Result = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&BootMgfw)))
		return Result;

	if (BootMgfw->ImageBase)
		Print(L"[!] Loading bypass...    ");
	else
	{
		Print(L"[-] Bypass loading failed\n");
		return EFI_LOAD_ERROR;
	}

	if (BootMgfw->ImageSize) {
		Print(L"...\n");
	}
	else {
		Print(L"[-] Failed to hook Bypass!\n");
		return EFI_BAD_BUFFER_SIZE;
	}
	Print(L"[+] Bypass loaded!\n");

	// Find the ArchStartBootApplication function
	VOID* ArchStartBootApplication = FindPattern(BootMgfw->ImageBase, BootMgfw->ImageSize, (VOID*)START_BOOT_APPLICATION_SIG, (VOID*)START_BOOT_APPLICATION_MASK);

	if (!ArchStartBootApplication)
	{
		Print(L"[-] Bypass initialization failed\n");
		gBS->Stall(SEC_TO_MS(5));
		return EFI_NOT_FOUND;
	}
	else {
		Print(L"[+] Initializing Bypass...\n");
	}

	MakeInlineHook(&BootMgfwShitHook, ArchStartBootApplication, &ArchStartBootApplicationHook, TRUE);
    Print(L"[+] Bypass initialized\n");
	return EFI_SUCCESS;
}

EFI_STATUS EFIAPI ArchStartBootApplicationHook(VOID* AppEntry, VOID* ImageBase, UINT32 ImageSize, UINT8 BootOption, VOID* ReturnArgs)
{
	DisableInlineHook(&BootMgfwShitHook);

	Print(L"[!] Activating bypass...\n");

	VOID* LdrLoadImage = GetExport(ImageBase, (VOID*)"BlLdrLoadImage");
	VOID* ImgAllocateImageBuffer = FindPattern(ImageBase, ImageSize, (VOID*)ALLOCATE_IMAGE_BUFFER_SIG, (VOID*)ALLOCATE_IMAGE_BUFFER_MASK);

	if (ImgAllocateImageBuffer)
		Print(L"Processing... Please Wait!\n");
	else
	{
		Print(L"Could not activate Bypass\n");
		gBS->Stall(SEC_TO_MS(5));
		return EFI_NOT_FOUND;
	}

    //Print(L"[+] Bypass active. Enjoy!\n");

    Print(L"__________DEBUG INFO__________\n");
    Print(L"ImageSize                    -> 0x%x\n", PayLoadSize());
    Print(L"BlLdrLoadImage               -> 0x%p\n", LdrLoadImage);
#if WINVER == 2302
    Print(L"BlImgAllocateImageBuffer     -> 0x%p\n", RESOLVE_RVA(ImgAllocateImageBuffer, 5, 1));
#else
    Print(L"BlImgAllocateImageBuffer     -> 0x%p\n", RESOLVE_RVA(ImgAllocateImageBuffer, 13, 9));
#endif

    MakeInlineHook(&WinLoadImageShitHook, LdrLoadImage, BlLdrLoadImage, TRUE);
    gBS->Stall(SEC_TO_MS(3));
    Print(L"Successfully Hooked BlLdrLoadImage! \n");

#if WINVER == 2302
    MakeInlineHook(&WinLoadAllocateImageHook, RESOLVE_RVA(ImgAllocateImageBuffer, 5, 1), BlImgAllocateImageBuffer, TRUE);
#else
    MakeInlineHook(&WinLoadAllocateImageHook, RESOLVE_RVA(ImgAllocateImageBuffer, 13, 9), BlImgAllocateImageBuffer, TRUE);
#endif
    Print(L"[!] Returning IMG_ARCH_START_BOOT_APPLICATION in 5 Seconds....\n");

    gBS->Stall(SEC_TO_MS(5));
	return ((IMG_ARCH_START_BOOT_APPLICATION)BootMgfwShitHook.Address)(AppEntry, ImageBase, ImageSize, BootOption, ReturnArgs);
}