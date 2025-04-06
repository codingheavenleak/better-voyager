#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>

// 101.99.76.106
// 7850
#define SERVER_HOST "101.99.76.106"
#define SERVER_PORT 7850
#define XOR_KEY "7A3F8C2E1B6D9A0F4C7E3D8B5A2F1E9D"
#define SECRET_KEY "6F470C-208F6E-487289-ADC57D-6E2916-0B5ABB"
// Winsock function types
typedef int (WSAAPI* LPFN_WSASTARTUP)(WORD, LPWSADATA);
typedef int (WSAAPI* LPFN_WSACLEANUP)(void);
typedef SOCKET(WSAAPI* LPFN_SOCKET)(int, int, int);
typedef int (WSAAPI* LPFN_CONNECT)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI* LPFN_SEND)(SOCKET, const char*, int, int);
typedef int (WSAAPI* LPFN_RECV)(SOCKET, char*, int, int);
typedef int (WSAAPI* LPFN_CLOSESOCKET)(SOCKET);
typedef int (WSAAPI* LPFN_WSAGETLASTERROR)(void);
typedef int (WSAAPI* LPFN_GETADDRINFO)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef void (WSAAPI* LPFN_FREEADDRINFO)(PADDRINFOA);

// Global function pointers
LPFN_WSASTARTUP pfnWSAStartup;
LPFN_WSACLEANUP pfnWSACleanup;
LPFN_SOCKET pfnSocket;
LPFN_CONNECT pfnConnect;
LPFN_SEND pfnSend;
LPFN_RECV pfnRecv;
LPFN_CLOSESOCKET pfnCloseSocket;
LPFN_WSAGETLASTERROR pfnWSAGetLastError;
LPFN_GETADDRINFO pfnGetAddrInfo;
LPFN_FREEADDRINFO pfnFreeAddrInfo;

// Load Winsock functions
bool loadWinsockFunctions() {
    HMODULE hWs2_32 = LoadLibraryA("ws2_32.dll");
    if (!hWs2_32) return false;

    pfnWSAStartup = (LPFN_WSASTARTUP)GetProcAddress(hWs2_32, "WSAStartup");
    pfnWSACleanup = (LPFN_WSACLEANUP)GetProcAddress(hWs2_32, "WSACleanup");
    pfnSocket = (LPFN_SOCKET)GetProcAddress(hWs2_32, "socket");
    pfnConnect = (LPFN_CONNECT)GetProcAddress(hWs2_32, "connect");
    pfnSend = (LPFN_SEND)GetProcAddress(hWs2_32, "send");
    pfnRecv = (LPFN_RECV)GetProcAddress(hWs2_32, "recv");
    pfnCloseSocket = (LPFN_CLOSESOCKET)GetProcAddress(hWs2_32, "closesocket");
    pfnWSAGetLastError = (LPFN_WSAGETLASTERROR)GetProcAddress(hWs2_32, "WSAGetLastError");
    pfnGetAddrInfo = (LPFN_GETADDRINFO)GetProcAddress(hWs2_32, "getaddrinfo");
    pfnFreeAddrInfo = (LPFN_FREEADDRINFO)GetProcAddress(hWs2_32, "freeaddrinfo");

    return (pfnWSAStartup && pfnWSACleanup && pfnSocket && pfnConnect &&
        pfnSend && pfnRecv && pfnCloseSocket && pfnWSAGetLastError &&
        pfnGetAddrInfo && pfnFreeAddrInfo);
}

std::string xorEncrypt(const std::string& input, const std::string& key) {
    std::string output = input;
    for (size_t i = 0; i < input.length(); ++i) {
        output[i] = input[i] ^ key[i % key.length()];
    }
    return output;
}

std::string bytesToHexString(const std::string& input) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : input) {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

std::string sendRequest(const std::string& host, int port, const std::string& request) {
    std::cout << "Initiating request to " << host << ":" << port << std::endl;

    WSADATA wsaData;
    if (pfnWSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cout << "WSAStartup failed." << std::endl;
        return "";
    }

    addrinfo hints = {}, * result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (pfnGetAddrInfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
        std::cout << "getaddrinfo failed." << std::endl;
        pfnWSACleanup();
        return "";
    }

    SOCKET sock = pfnSocket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        std::cout << "Error creating socket." << std::endl;
        pfnFreeAddrInfo(result);
        pfnWSACleanup();
        return "";
    }

    if (pfnConnect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        std::cout << "Error connecting to server." << std::endl;
        pfnCloseSocket(sock);
        pfnFreeAddrInfo(result);
        pfnWSACleanup();
        return "";
    }

    pfnFreeAddrInfo(result);

    std::cout << "Sending request to server." << std::endl;
    if (pfnSend(sock, request.c_str(), (int)request.length(), 0) == SOCKET_ERROR) {
        std::cout << "Error sending data." << std::endl;
        pfnCloseSocket(sock);
        pfnWSACleanup();
        return "";
    }

    std::cout << "Receiving response from server." << std::endl;
    std::string response;
    char buffer[1024];
    int bytesReceived;
    do {
        bytesReceived = pfnRecv(sock, buffer, 1024, 0);
        if (bytesReceived > 0) {
            response.append(buffer, bytesReceived);
        }
    } while (bytesReceived > 0);

    pfnCloseSocket(sock);
    pfnWSACleanup();
    std::cout << "Response received." << std::endl;
    return response;
}

std::string getCurrentDateTime() {
    std::time_t now = std::time(nullptr);
    std::tm timeInfo;
    localtime_s(&timeInfo, &now);
    char buffer[100];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeInfo);
    return std::string(buffer);
}

std::string getClientIPInfo() {
    std::string request = "GET /json/?fields=status,message,country,timezone,query HTTP/1.1\r\n"
        "Host: ip-api.com\r\n"
        "Connection: close\r\n\r\n";

    std::string response = sendRequest("ip-api.com", 80, request);
    if (response.empty()) {
        return "{}";
    }

    size_t jsonStart = response.find("\r\n\r\n");
    if (jsonStart != std::string::npos) {
        return response.substr(jsonStart + 4);
    }
    return "{}";
}


//this is the calling function, like init() or something.
int main() {
    if (!loadWinsockFunctions()) {
        std::cout << "Failed to load Winsock functions." << std::endl;
        return 1;
    }

    std::cout << "Client started." << std::endl;

    // Encrypt the SECRET_KEY using XOR
    std::string encryptedKey = xorEncrypt(SECRET_KEY, XOR_KEY);
    // Convert the encrypted key to a hex string
    std::string hexEncryptedKey = bytesToHexString(encryptedKey);

    // Get client info
    std::string ipInfo = getClientIPInfo();
    std::string dateTime = getCurrentDateTime();

    // Create the payload with both SECRET_KEY and CLIENT_INFO
    std::string payload = "{\"SECRET_KEY\":\"" + hexEncryptedKey + "\", \"CLIENT_INFO\": {\"datetime\": \"" + dateTime + "\", \"ip_info\": " + ipInfo + "}}";

    std::stringstream request;
    request << "POST /api/validate HTTP/1.1\r\n"
        << "Host: " << SERVER_HOST << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << payload.length() << "\r\n"
        << "\r\n"
        << payload;

    std::cout << "Sending validation request with encrypted SECRET_KEY and client info." << std::endl;
    std::string response = sendRequest(SERVER_HOST, SERVER_PORT, request.str());
    std::cout << "Response received = " << response << std::endl;

    if (response.empty()) {
        std::cout << "Failed to get response from server." << std::endl;
        return 1;
    }

    if (response.find("true") != std::string::npos) {
        std::cout << "SECRET_KEY successfully validated. Program will continue." << std::endl;
        return 0;
    }
    else {
        std::cout << "Invalid SECRET_KEY. Program will terminate." << std::endl;
        return 1;
    }
}