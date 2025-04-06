#include "request.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "xorstr.h"

#pragma comment(lib, "Ws2_32.lib")

std::string getWindowsDisplayVersion() {
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        return "Unknown";
    }

    WCHAR value[256];
    DWORD valueSize = sizeof(value);
    DWORD type;
    result = RegQueryValueExW(hKey, L"DisplayVersion", NULL, &type, (LPBYTE)value, &valueSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || type != REG_SZ) {
        return "Unknown";
    }

    std::wstring wideStr(value);
    return std::string(wideStr.begin(), wideStr.end());
}

std::string sendRequestWithWinsock(const std::string& host, const std::string& port, const std::string& endpoint) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    std::string response;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << adsq("[ERROR] WSAStartup failed.\n");
        return "";
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0) {
        std::cerr << adsq("[ERROR] getaddrinfo failed.\n");
        WSACleanup();
        return "";
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << adsq("[ERROR] Socket creation failed.\n");
            WSACleanup();
            return "";
        }

        if (connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(result);
    if (ConnectSocket == INVALID_SOCKET) {
        std::cerr << adsq("[ERROR] Unable to connect to server.\n");
        WSACleanup();
        return "";
    }

    std::string windowsVersion = getWindowsDisplayVersion();
    std::string request = "GET " + endpoint + "?version=" + windowsVersion + " HTTP/1.1\r\n" +
        "Host: " + host + ":" + port + "\r\n" +
        "Connection: close\r\n\r\n";

    if (send(ConnectSocket, request.c_str(), (int)request.size(), 0) == SOCKET_ERROR) {
        std::cerr << adsq("[ERROR] Send request failed.\n");
        closesocket(ConnectSocket);
        WSACleanup();
        return "";
    }
    char buffer[1024];
    int bytesReceived;
    while ((bytesReceived = recv(ConnectSocket, buffer, sizeof(buffer), 0)) > 0) {
        response.append(buffer, bytesReceived);
    }
    if (bytesReceived < 0) {
        std::cerr << adsq("[ERROR] Receive failed.\n");
    }
    closesocket(ConnectSocket);
    WSACleanup();

    size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart != std::string::npos) {
        response = response.substr(bodyStart + 4);
    }
    else {
        std::cerr << adsq("[ERROR] Invalid HTTP response format.\n");
        return "";
    }

    return response;
}