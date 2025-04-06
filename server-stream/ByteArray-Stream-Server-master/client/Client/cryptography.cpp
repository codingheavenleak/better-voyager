#include "cryptography.h"
#include <iostream>
#include <sstream>
#include <iomanip>

const std::string SECRET_KEY = "X9f2kP7qLm3nR8tUvWxYzA5bCdEgHjKl";

std::vector<unsigned char> deriveKey(const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(32);
    PKCS5_PBKDF2_HMAC(SECRET_KEY.c_str(), SECRET_KEY.length(), salt.data(), salt.size(), 100000, EVP_sha256(), 32, key.data());
    return key;
}

std::string decrypt(const std::string& encryptedData) {
    std::vector<unsigned char> iv(16), salt(16);
    std::string encryptedPayload;

    for (int i = 0; i < 64; i += 2) {
        unsigned char byte = std::stoul(encryptedData.substr(i, 2), nullptr, 16);
        if (i < 32) iv[i / 2] = byte;
        else salt[(i - 32) / 2] = byte;
    }
    encryptedPayload = encryptedData.substr(64);

    auto key = deriveKey(salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());

    std::vector<unsigned char> decodedPayload(encryptedPayload.length() / 2);
    for (size_t i = 0; i < encryptedPayload.length(); i += 2) {
        decodedPayload[i / 2] = std::stoul(encryptedPayload.substr(i, 2), nullptr, 16);
    }

    std::vector<unsigned char> decryptedData(decodedPayload.size() + AES_BLOCK_SIZE);
    int len = 0, plaintext_len = 0;

    EVP_DecryptUpdate(ctx, decryptedData.data(), &len, decodedPayload.data(), decodedPayload.size());
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(decryptedData.begin(), decryptedData.begin() + plaintext_len);
}

std::vector<unsigned char> parseByteArray(const std::string& data) {
    std::vector<unsigned char> result;

    size_t start = data.find("unsigned char rawData[");
    if (start == std::string::npos) {
        std::cerr << "[ERROR] Start of byte array not found\n";
        return result;
    }

    start = data.find("{", start);
    if (start == std::string::npos) {
        std::cerr << "[ERROR] Opening brace of byte array not found\n";
        return result;
    }
    start++;

    size_t end = data.find("};", start);
    if (end == std::string::npos) {
        std::cerr << "[ERROR] Closing brace of byte array not found\n";
        return result;
    }

    std::string arrayContent = data.substr(start, end - start);

    std::istringstream iss(arrayContent);
    std::string byteStr;
    while (iss >> byteStr) {
        if (byteStr.back() == ',') byteStr.pop_back();
        if (byteStr.substr(0, 2) == "0x") byteStr = byteStr.substr(2);
        if (!byteStr.empty()) {
            result.push_back(static_cast<unsigned char>(std::stoul(byteStr, nullptr, 16)));
        }
    }

    return result;
}