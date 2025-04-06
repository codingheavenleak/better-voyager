#pragma once

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>

extern const std::string SECRET_KEY;

std::vector<unsigned char> deriveKey(const std::vector<unsigned char>& salt);
std::string decrypt(const std::string& encryptedData);
std::vector<unsigned char> parseByteArray(const std::string& data);