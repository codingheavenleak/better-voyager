#include "BootMgfw.h"
#include "PayloadBytes.h"

CHAR8* gEfiCallerBaseName = "iBzSjmVpJyJP";
const UINT32 _gUefiDriverRevision = 0x1375;
PSCYVISOR_T ScyvisorData;



EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE ImageHandle)
{
    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)
{
    EFI_STATUS Result;
    EFI_HANDLE BootMgfwHandle;
    EFI_DEVICE_PATH* BootMgfwPath = NULL;

    gST->ConOut->ClearScreen(gST->ConOut);
    Print(L"┌───────────────────────────────────────────────┐\n");
    Print(L"│                   ScyVisor                    │\n");
    Print(L"│                                               │\n");
    Print(L"│                  Version 1.0.0.0              │\n");
    Print(L"└───────────────────────────────────────────────┘\n\n");

    // since we replaced bootmgfw on disk, we are going to need to restore the image back
    // this is simply just moving bootmgfw.efi.backup to bootmgfw.efi...
    if (EFI_ERROR((Result = RestoreBootMgfw())))
    {
        Print(L"unable to restore bootmgfw... reason -> %r\n", Result);
        gBS->Stall(SEC_TO_MS(5));
        return Result;
    }

    // get the device path to bootmgfw...
    if (EFI_ERROR((Result = GetBootMgfwPath(&BootMgfwPath))))
    {
        Print(L"getting bootmgfw device path failed... reason -> %r\n", Result);
        gBS->Stall(SEC_TO_MS(5));
        return Result;
    }

    // load bootmgfw into memory...
    if (EFI_ERROR((Result = gBS->LoadImage(TRUE, ImageHandle, BootMgfwPath, NULL, NULL, &BootMgfwHandle))))
    {
        Print(L"failed to load bootmgfw.efi... reason -> %r\n", Result);
        gBS->Stall(SEC_TO_MS(5));
        return EFI_ABORTED;
    }

    UINT32 CupType = GetCPUVendor();

    if (CupType == 1)
    {

        PayLoad = (UINT8*)IntelPayload;
    }
    else if (CupType == 2)
    {

        PayLoad = (UINT8*)AmdPayload;
    }
    else
    {
        Print(L"Unknown CPU!\n");
        gBS->Stall(SEC_TO_MS(5));
        return EFI_ABORTED;
    }

    // install hooks on bootmgfw...
    if (EFI_ERROR((Result = InstallBootMgfwHooks(BootMgfwHandle))))
    {
        Print(L"Failed to install bootmgfw hooks... reason -> %r\n", Result);
        gBS->Stall(SEC_TO_MS(5));
        return Result;
    }

    Print(L"Finalizing ScyVisor initialization. Please wait...\n");

    // wait 5 seconds then call the entry point of bootmgfw...
    gBS->Stall(SEC_TO_MS(5));
    if (EFI_ERROR((Result = gBS->StartImage(BootMgfwHandle, NULL, NULL))))
    {
        Print(L"Failed to start bootmgfw.efi... reason -> %r\n", Result);
        gBS->Stall(SEC_TO_MS(5));
        return EFI_ABORTED;
    }

    return EFI_SUCCESS;
}