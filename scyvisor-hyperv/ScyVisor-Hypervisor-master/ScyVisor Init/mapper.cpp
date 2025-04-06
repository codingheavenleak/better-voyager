#include "mapper.h"
#include <windows.h>
#include <iostream>
#include "xorstr.h"

namespace Mapper {
    bool Map(const std::wstring& kdmPath, const std::wstring& driverPath) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        ZeroMemory(&pi, sizeof(pi));

        std::wstring commandLine = kdmPath + L" " + driverPath;

        if (!CreateProcessW(
            NULL,
            const_cast<LPWSTR>(commandLine.c_str()),
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            std::cerr << adsq("[ERROR] Failed to execute kdm.exe: ") << GetLastError() << std::endl;
            return false;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode;
        if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == 0) {
            std::cout << adsq("Success") << std::endl;
        }
        else {
            std::cerr << adsq("[ERROR] kdm.exe execution failed with exit code: ") << exitCode << std::endl;
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return exitCode == 0;
    }
}