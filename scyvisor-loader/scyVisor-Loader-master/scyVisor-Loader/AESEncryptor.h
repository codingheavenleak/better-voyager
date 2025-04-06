#pragma once

#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

class AESEncryptor {
private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    void initializeKeyAndIV();

public:
    AESEncryptor();
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext);
};