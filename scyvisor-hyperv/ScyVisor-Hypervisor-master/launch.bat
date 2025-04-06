@echo off
net session >nul 2>&1
if %errorLevel% == 0 (
    :: mount the efi partition to X: drive...
    mountvol X: /S
    
    :: bootmgfw is a system file so we are going to strip those attributes away...
    attrib -s -h X:\EFI\Microsoft\Boot\bootmgfw.efi
    
    :: backup bootmgfw.efi (this is needed for ScyVisor to work since ScyVisor restores bootmgfw.efi)
    move X:\EFI\Microsoft\Boot\bootmgfw.efi X:\EFI\Microsoft\Boot\bootmgfw.efi.backup
    
    :: copy bootmgfw.efi to EFI partition...
    xcopy E:\\scyvisorHV\bootmgfw.efi X:\EFI\Microsoft\Boot\


    echo press enter to reboot...
    pause
    
    :: enable hyper-v and reboot now...
    ::BCDEDIT /Set {current} hypervisorlaunchtype auto
    shutdown /r /t 0
) else (
    echo Failure: Please run as admin.
    pause
)