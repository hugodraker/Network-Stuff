/* ============================================================================
 * CalDAV Server & HTTP Web Server - C Implementation with Win32 GUI
 *
 * COMPILATION INSTRUCTIONS:
 *
 * With GCC (MinGW-w64):
 *   gcc -Os -s -Wl,--subsystem,windows -mwindows -o caldavd.exe caldavd.c -lgdi32 -lole32 -limm32 -lcomdlg32 -lcomctl32 -lws2_32 -ladvapi32
 * 
 * 2026 HUGO
 * 
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "imm32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#define SERVER_NAME "CaldAV-D"
#define SERVER_VERSION "1.6"
#define DEFAULT_PORT 8080
#define DEFAULT_HTTP_PORT 80
#define DEFAULT_TIMEOUT_MS 2000
#define MAX_CONNECTIONS 10
#define BUFFER_SIZE 4096
#define CONFIG_FILE "caldavd.ini"
#define DATA_DIR "./calendars"
#define WEB_DIR "./"
#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_ICON 1
#define ID_MENU_START 2
#define ID_MENU_STOP 3
#define ID_MENU_SETTINGS 4
#define ID_MENU_EXIT 5
#define ID_BTN_START 6
#define ID_BTN_STOP 7
#define ID_EDIT_PORT 8
#define ID_BTN_SAVE 9
#define ID_EDIT_TIMEOUT 10
#define ID_CHK_ANON 11
#define ID_EDIT_HTTP_PORT 12
#define ID_MENU_IMPORT 13
#define ID_MENU_EXPORT 14
#define WM_UPDATE_PORT (WM_USER + 2)
#define PORT_UPDATE_DELAY_MS 1000
static HINSTANCE g_hInstance = NULL;
static HWND g_hMainWnd = NULL;
static HWND g_hSettingsWnd = NULL;
static NOTIFYICONDATA g_nid = { sizeof(NOTIFYICONDATA) };
static BOOL g_bRunning = FALSE;
static SOCKET g_ListenSocket = INVALID_SOCKET;
static SOCKET g_HttpListenSocket = INVALID_SOCKET;
static int g_Port = DEFAULT_PORT;
static int g_HttpPort = DEFAULT_HTTP_PORT;
static int g_TimeoutMs = DEFAULT_TIMEOUT_MS;
static BOOL g_bAnonymous = TRUE;
static UINT g_TaskbarCreatedMsg = 0;

typedef struct {
    SOCKET socket;
    int port;
} ClientThreadCtx;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SettingsWndProc(HWND, UINT, WPARAM, LPARAM);
VOID CALLBACK UpdateTimerCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime);
unsigned __stdcall ServerThread(void* pParam);
unsigned __stdcall ClientHandler(void* pParam);
unsigned __stdcall HttpServerThread(void* pParam);
unsigned __stdcall HttpClientHandler(void* pParam);
INT_PTR CreateSettingsWindow(void);
VOID CreateTrayIcon(HWND hWnd);
VOID RemoveTrayIcon(void);
VOID ShowContextMenu(HWND hWnd);
VOID HandleCommandLine(SOCKET clientSocket, char* buffer, char* response);
VOID SendHTTPResponse(SOCKET client, const char* status, const char* contentType, const char* body, SIZE_T bodyLen, const char* extraHeaders);
VOID SendHTTPFileResponse(SOCKET client, const char* filePath);
BOOL SaveConfig(void);
BOOL LoadConfig(void);
BOOL StartServer(int port);
VOID StopServer(VOID);
BOOL StartHttpServer(int port);
VOID StopHttpServer(VOID);
VOID SeedDefaultUser(VOID);
char* GetHTTPMethod(char* buffer);
char* GetRequestPath(char* buffer);
BOOL AuthenticateRequest(char* buffer);
VOID GenerateSaltedHash(const char* password, const char* salt, char* outHex);
VOID Base64Decode(const char* input, char* output, int maxLen);
VOID HandleExportData(HWND hWnd);
VOID HandleImportData(HWND hWnd);

VOID GenerateSaltedHash(const char* password, const char* salt, char* outHex) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    outHex[0] = '\0';
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (const BYTE*)password, (DWORD)strlen(password), 0);
            CryptHashData(hHash, (const BYTE*)salt, (DWORD)strlen(salt), 0);
            BYTE hashBytes[32];
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
                for (DWORD i = 0; i < hashLen; i++) {
                    snprintf(outHex + (i * 2), 3, "%02x", hashBytes[i]);
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

VOID Base64Decode(const char* input, char* output, int maxLen) {
    int decoding_table[256];
    const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 256; i++) decoding_table[i] = -1;
    for (int i = 0; i < 64; i++) decoding_table[(unsigned char)b64chars[i]] = i;
    int out_idx = 0;
    int val = 0, valb = -8;
    for (const char* c = input; *c; c++) {
        if (decoding_table[(unsigned char)*c] == -1) break;
        val = (val << 6) + decoding_table[(unsigned char)*c];
        valb += 6;
        if (valb >= 0) {
            if (out_idx < maxLen - 1) output[out_idx++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    output[out_idx] = '\0';
}

BOOL AuthenticateRequest(char* buffer) {
    if (g_bAnonymous) return TRUE;
    char* authHeader = strstr(buffer, "Authorization: Basic ");
    if (!authHeader) return FALSE;
    authHeader += 21;
    char b64[256] = {0};
    int i = 0;
    while (authHeader[i] && authHeader[i] != '\r' && authHeader[i] != '\n' && authHeader[i] != ' ' && i < 255) {
        b64[i] = authHeader[i];
        i++;
    }
    b64[i] = '\0';
    char decoded[256] = {0};
    Base64Decode(b64, decoded, 256);
    char* colon = strchr(decoded, ':');
    if (!colon) return FALSE;
    *colon = '\0';
    char* username = decoded;
    char* password = colon + 1;
    char userEntry[256];
    GetPrivateProfileString("users", username, "", userEntry, sizeof(userEntry), CONFIG_FILE);
    if (strlen(userEntry) == 0) return FALSE;
    char* comma = strchr(userEntry, ',');
    if (!comma) return FALSE;
    *comma = '\0';
    char* salt = userEntry;
    char* expectedHash = comma + 1;
    char actualHash[65] = {0};
    GenerateSaltedHash(password, salt, actualHash);
    return (strcmp(expectedHash, actualHash) == 0);
}

VOID SeedDefaultUser(VOID) {
    char buf[2];
    if (GetPrivateProfileString("users", "admin", "", buf, sizeof(buf), CONFIG_FILE) == 0) {
        char hash[65];
        GenerateSaltedHash("admin", "salt2026", hash);
        char entry[128];
        snprintf(entry, sizeof(entry), "salt2026,%s", hash);
        WritePrivateProfileString("users", "admin", entry, CONFIG_FILE);
    }
}

BOOL LoadConfig(void) {
    char buffer[64];
    if (GetPrivateProfileString("server", "port", "8080", buffer, sizeof(buffer), CONFIG_FILE)) {
        g_Port = atoi(buffer);
        if (g_Port < 1 || g_Port > 65535) g_Port = DEFAULT_PORT;
    }
    if (GetPrivateProfileString("server", "http_port", "80", buffer, sizeof(buffer), CONFIG_FILE)) {
        g_HttpPort = atoi(buffer);
        if (g_HttpPort < 1 || g_HttpPort > 65535) g_HttpPort = DEFAULT_HTTP_PORT;
    }
    if (GetPrivateProfileString("server", "timeout_ms", "2000", buffer, sizeof(buffer), CONFIG_FILE)) {
        g_TimeoutMs = atoi(buffer);
        if (g_TimeoutMs < 1) g_TimeoutMs = DEFAULT_TIMEOUT_MS;
    }
    if (GetPrivateProfileString("server", "anonymous", "1", buffer, sizeof(buffer), CONFIG_FILE)) {
        g_bAnonymous = (atoi(buffer) != 0);
    }
    return TRUE;
}

BOOL SaveConfig(void) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", g_Port);
    WritePrivateProfileString("server", "port", buffer, CONFIG_FILE);
    snprintf(buffer, sizeof(buffer), "%d", g_HttpPort);
    WritePrivateProfileString("server", "http_port", buffer, CONFIG_FILE);
    snprintf(buffer, sizeof(buffer), "%d", g_TimeoutMs);
    WritePrivateProfileString("server", "timeout_ms", buffer, CONFIG_FILE);
    snprintf(buffer, sizeof(buffer), "%d", g_bAnonymous ? 1 : 0);
    WritePrivateProfileString("server", "anonymous", buffer, CONFIG_FILE);
    return TRUE;
}

BOOL StartHttpServer(int port) {
    SOCKADDR_IN addr;
    g_HttpListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_HttpListenSocket == INVALID_SOCKET) return FALSE;
    
    char optval = 1;
    setsockopt(g_HttpListenSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(g_HttpListenSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR || listen(g_HttpListenSocket, MAX_CONNECTIONS) == SOCKET_ERROR) {
        closesocket(g_HttpListenSocket);
        g_HttpListenSocket = INVALID_SOCKET;
        return FALSE;
    }
    return TRUE;
}

VOID StopHttpServer(VOID) {
    if (g_HttpListenSocket != INVALID_SOCKET) {
        closesocket(g_HttpListenSocket);
        g_HttpListenSocket = INVALID_SOCKET;
    }
}

unsigned __stdcall HttpServerThread(void* pParam) {
    (void)pParam;
    while (g_bRunning && g_HttpListenSocket != INVALID_SOCKET) {
        SOCKADDR_IN clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(g_HttpListenSocket, (SOCKADDR*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) continue;
        ClientThreadCtx* ctx = malloc(sizeof(ClientThreadCtx));
        if (ctx) {
            ctx->socket = clientSocket;
            ctx->port = g_HttpPort;
            HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, HttpClientHandler, ctx, 0, NULL);
            if (hThread) CloseHandle(hThread);
            else { free(ctx); closesocket(clientSocket); }
        } else closesocket(clientSocket);
    }
    return 0;
}

unsigned __stdcall HttpClientHandler(void* pParam) {
    ClientThreadCtx* ctx = (ClientThreadCtx*)pParam;
    SOCKET clientSocket = ctx->socket;
    char buffer[BUFFER_SIZE];
    DWORD timeout = (DWORD)g_TimeoutMs;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    memset(buffer, 0, sizeof(buffer));
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        char* method = GetHTTPMethod(buffer);
        char* path = GetRequestPath(buffer);
        if (strcmp(method, "GET") == 0) {
            if (strcmp(path, "/") == 0) path = "/calendar.html";
            char fullPath[MAX_PATH];
            snprintf(fullPath, sizeof(fullPath), "%s%s", WEB_DIR, path);
            if (strstr(path, "..") == NULL) SendHTTPFileResponse(clientSocket, fullPath);
            else SendHTTPResponse(clientSocket, "403 Forbidden", "text/plain", "Forbidden", 9, NULL);
        } else {
            SendHTTPResponse(clientSocket, "405 Method Not Allowed", "text/plain", "Method Not Allowed", 18, NULL);
        }
    }
    shutdown(clientSocket, SD_BOTH);
    closesocket(clientSocket);
    free(ctx);
    return 0;
}

VOID SendHTTPFileResponse(SOCKET client, const char* filePath) {
    FILE* fp = fopen(filePath, "rb");
    if (!fp) {
        SendHTTPResponse(client, "404 Not Found", "text/plain", "File Not Found", 14, NULL);
        return;
    }
    fseek(fp, 0, SEEK_END);
    long fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    const char* contentType = "application/octet-stream";
    if (strstr(filePath, ".html")) contentType = "text/html";
    else if (strstr(filePath, ".class") || strstr(filePath, ".jar")) contentType = "application/java-archive";
    else if (strstr(filePath, ".js")) contentType = "application/javascript";
    else if (strstr(filePath, ".css")) contentType = "text/css";
    else if (strstr(filePath, ".json")) contentType = "application/json";
    
    char header[512];
    int headerLen = snprintf(header, sizeof(header), 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
        "Pragma: no-cache\r\n"
        "Expires: 0\r\n"
        "\r\n", contentType, fileSize);
    send(client, header, headerLen, 0);
    char fileBuf[4096];
    size_t bytesRead;
    while ((bytesRead = fread(fileBuf, 1, sizeof(fileBuf), fp)) > 0) {
        send(client, fileBuf, (int)bytesRead, 0);
    }
    fclose(fp);
}

BOOL StartServer(int port) {
    WSADATA wsaData;
    SOCKADDR_IN addr;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return FALSE;
    g_ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_ListenSocket == INVALID_SOCKET) { WSACleanup(); return FALSE; }
    
    char optval = 1;
    setsockopt(g_ListenSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(g_ListenSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR || listen(g_ListenSocket, MAX_CONNECTIONS) == SOCKET_ERROR) {
        closesocket(g_ListenSocket);
        WSACleanup();
        return FALSE;
    }
    return TRUE;
}

void StopServer(VOID) {
    if (g_ListenSocket != INVALID_SOCKET) {
        closesocket(g_ListenSocket);
        g_ListenSocket = INVALID_SOCKET;
    }
    StopHttpServer();
    WSACleanup();
}

unsigned __stdcall ServerThread(void* pParam) {
    (void)pParam;
    while (g_bRunning && g_ListenSocket != INVALID_SOCKET) {
        SOCKADDR_IN clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(g_ListenSocket, (SOCKADDR*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) continue;
        ClientThreadCtx* ctx = malloc(sizeof(ClientThreadCtx));
        if (ctx) {
            ctx->socket = clientSocket;
            ctx->port = g_Port;
            HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ClientHandler, ctx, 0, NULL);
            if (hThread) CloseHandle(hThread);
            else { free(ctx); closesocket(clientSocket); }
        } else closesocket(clientSocket);
    }
    return 0;
}

char* GetHTTPMethod(char* buffer) {
    static __thread char method[16];
    char* space = strchr(buffer, ' ');
    if (!space) return "";
    int len = (int)(space - buffer);
    if (len >= (int)sizeof(method)) len = sizeof(method) - 1;
    strncpy_s(method, sizeof(method), buffer, len);
    method[len] = '\0';
    return method;
}

char* GetRequestPath(char* buffer) {
    static __thread char path[MAX_PATH];
    char* space1 = strchr(buffer, ' ');
    if (!space1) return "/";
    space1++;
    char* space2 = strchr(space1, ' ');
    int len = space2 ? (int)(space2 - space1) : (int)strlen(space1);
    if (len >= (int)sizeof(path)) len = sizeof(path) - 1;
    strncpy(path, space1, len);
    path[len] = '\0';
    
    /* Strip URL query parameters so local file lookups succeed */
    char* query = strchr(path, '?');
    if (query) *query = '\0';
    
    return path;
}
VOID SendHTTPResponse(SOCKET client, const char* status, const char* contentType, const char* body, SIZE_T bodyLen, const char* extraHeaders) {
    char header[1024];
    int headerLen = snprintf(header, sizeof(header), 
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s; charset=utf-8\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n"
        "Pragma: no-cache\r\n"
        "Expires: 0\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, REPORT\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Server: %s/%s\r\n"
        "%s"
        "\r\n",
        status, contentType, (unsigned long)bodyLen, SERVER_NAME, SERVER_VERSION,
        extraHeaders ? extraHeaders : "");
    send(client, header, headerLen, 0);
    if (bodyLen > 0 && body) send(client, body, (int)bodyLen, 0);
}

unsigned __stdcall ClientHandler(void* pParam) {
    ClientThreadCtx* ctx = (ClientThreadCtx*)pParam;
    SOCKET clientSocket = ctx->socket;
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE * 2];
    DWORD timeout = (DWORD)g_TimeoutMs;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    memset(buffer, 0, sizeof(buffer));
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived > 0) {
        char* method = GetHTTPMethod(buffer);
        if (strcmp(method, "OPTIONS") == 0 || AuthenticateRequest(buffer)) {
            HandleCommandLine(clientSocket, buffer, response);
        } else {
            SendHTTPResponse(clientSocket, "401 Unauthorized", "text/plain", "Unauthorized", 12, "WWW-Authenticate: Basic realm=\"CalDAV Server\"\r\n");
        }
    }
    shutdown(clientSocket, SD_BOTH);
    closesocket(clientSocket);
    free(ctx);
    return 0;
}

VOID HandleCommandLine(SOCKET clientSocket, char* buffer, char* response) {
    char* method = GetHTTPMethod(buffer);
    char* path = GetRequestPath(buffer);
    memset(response, 0, BUFFER_SIZE * 2);
    
    if (strstr(path, "..")) {
        SendHTTPResponse(clientSocket, "403 Forbidden", "text/plain", "Forbidden", 9, NULL);
        return;
    }
    
    char* body = strstr(buffer, "\r\n\r\n");
    if (body) body += 4;
    
    int contentLen = 0;
    char* clPtr = strstr(buffer, "Content-Length:");
    if (!clPtr) clPtr = strstr(buffer, "Content-length:");
    if (clPtr) contentLen = atoi(clPtr + 15);

    if (strcmp(method, "OPTIONS") == 0) {
        SendHTTPResponse(clientSocket, "200 OK", "text/plain", "", 0, NULL);
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/config/remote") == 0) {
        if (body) {
            char* url = strstr(body, "\"url\":\"");
            char* port = strstr(body, "\"port\":\"");
            char* user = strstr(body, "\"user\":\"");
            char* pass = strstr(body, "\"pass\":\"");
            if (url) { url += 7; char* end = strchr(url, '\"'); if (end) *end = '\0'; WritePrivateProfileString("RemoteServer", "URL", url, CONFIG_FILE); }
            if (port) { port += 8; char* end = strchr(port, '\"'); if (end) *end = '\0'; WritePrivateProfileString("RemoteServer", "Port", port, CONFIG_FILE); }
            if (user) { user += 8; char* end = strchr(user, '\"'); if (end) *end = '\0'; WritePrivateProfileString("RemoteServer", "User", user, CONFIG_FILE); }
            if (pass) { pass += 8; char* end = strchr(pass, '\"'); if (end) *end = '\0'; WritePrivateProfileString("RemoteServer", "Pass", pass, CONFIG_FILE); }
            SendHTTPResponse(clientSocket, "200 OK", "text/plain", "Saved", 5, NULL);
        } else {
            SendHTTPResponse(clientSocket, "400 Bad Request", "text/plain", "Missing body", 12, NULL);
        }
    }
    else if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/calendar/all") == 0) {
            char* responseBody = (char*)malloc(1024 * 1024);
            if (responseBody) {
                strcpy(responseBody, "[");
                WIN32_FIND_DATA fd;
                char searchPath[MAX_PATH];
                snprintf(searchPath, sizeof(searchPath), "%s\\*.json", DATA_DIR);
                HANDLE hFind = FindFirstFile(searchPath, &fd);
                int first = 1;
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (strcmp(fd.cFileName, "people.json") == 0) continue;
                        char filepath[MAX_PATH];
                        snprintf(filepath, sizeof(filepath), "%s/%s", DATA_DIR, fd.cFileName);
                        FILE* fp = fopen(filepath, "rb");
                        if (fp) {
                            fseek(fp, 0, SEEK_END);
                            long size = ftell(fp);
                            fseek(fp, 0, SEEK_SET);
                            if (size > 0 && strlen(responseBody) + size + 2 < 1024 * 1024) {
                                if (!first) strcat(responseBody, ",");
                                int curLen = strlen(responseBody);
                                fread(responseBody + curLen, 1, size, fp);
                                responseBody[curLen + size] = '\0';
                                first = 0;
                            }
                            fclose(fp);
                        }
                    } while (FindNextFile(hFind, &fd));
                    FindClose(hFind);
                }
                strcat(responseBody, "]");
                SendHTTPResponse(clientSocket, "200 OK", "application/json", responseBody, strlen(responseBody), NULL);
                free(responseBody);
            } else { SendHTTPResponse(clientSocket, "500 Internal Error", "text/plain", "Memory Error", 12, NULL); }
        }
        else if (strncmp(path, "/calendar/", 10) == 0) {
            char filepath[MAX_PATH];
            snprintf(filepath, sizeof(filepath), "%s/%s", DATA_DIR, path + 10);
            FILE* fp = fopen(filepath, "rb");
            if (fp) {
                fseek(fp, 0, SEEK_END);
                long size = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                char* fileBuf = malloc(size + 1);
                if (fileBuf) {
                    fread(fileBuf, 1, size, fp);
                    fileBuf[size] = '\0';
                    SendHTTPResponse(clientSocket, "200 OK", "application/json", fileBuf, size, NULL);
                    free(fileBuf);
                }
                fclose(fp);
            } else { SendHTTPResponse(clientSocket, "404 Not Found", "text/plain", "Not Found", 9, NULL); }
        }
        else { SendHTTPResponse(clientSocket, "404 Not Found", "text/plain", "Endpoint not found", 18, NULL); }
    }
    else if (strcmp(method, "PUT") == 0 && strncmp(path, "/calendar/", 10) == 0) {
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", DATA_DIR, path + 10);
        if (body) {
            FILE* fp = fopen(filepath, "wb");
            if (fp) {
                int writeLen = contentLen > 0 ? contentLen : (int)strlen(body);
                fwrite(body, 1, writeLen, fp);
                fclose(fp);
                SendHTTPResponse(clientSocket, "201 Created", "text/plain", "Created", 7, NULL);
            } else { SendHTTPResponse(clientSocket, "500 Internal Error", "text/plain", "I/O Error", 9, NULL); }
        } else { SendHTTPResponse(clientSocket, "400 Bad Request", "text/plain", "No Body", 7, NULL); }
    }
    else if (strcmp(method, "DELETE") == 0 && strncmp(path, "/calendar/", 10) == 0) {
        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s/%s", DATA_DIR, path + 10);
        remove(filepath);
        SendHTTPResponse(clientSocket, "204 No Content", "text/plain", "", 0, NULL);
    }
    else {
        SendHTTPResponse(clientSocket, "404 Not Found", "text/plain", "Endpoint not found", 18, NULL);
    }
}

VOID HandleExportData(HWND hWnd) {
    OPENFILENAME ofn = {0};
    char szFile[MAX_PATH] = "caldav_backup.bak";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = "Backup Files (*.bak)\0*.bak\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    
    if (GetSaveFileName(&ofn)) {
        FILE* out = fopen(szFile, "wb");
        if (out) {
            WIN32_FIND_DATA fd;
            char searchPath[MAX_PATH];
            snprintf(searchPath, sizeof(searchPath), "%s\\*.*", DATA_DIR);
            HANDLE hFind = FindFirstFile(searchPath, &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
                        char filepath[MAX_PATH];
                        snprintf(filepath, sizeof(filepath), "%s/%s", DATA_DIR, fd.cFileName);
                        FILE* in = fopen(filepath, "rb");
                        if (in) {
                            fseek(in, 0, SEEK_END);
                            long size = ftell(in);
                            fseek(in, 0, SEEK_SET);
                            
                            char paddedName[64] = {0};
                            strncpy(paddedName, fd.cFileName, 63);
                            fwrite(paddedName, 1, 64, out);
                            fwrite(&size, sizeof(long), 1, out);
                            
                            char* buf = malloc(size);
                            if (buf) {
                                fread(buf, 1, size, in);
                                fwrite(buf, 1, size, out);
                                free(buf);
                            }
                            fclose(in);
                        }
                    }
                } while (FindNextFile(hFind, &fd));
                FindClose(hFind);
            }
            fclose(out);
            MessageBox(hWnd, "Export Successful!", SERVER_NAME, MB_ICONINFORMATION);
        }
    }
}

VOID HandleImportData(HWND hWnd) {
    OPENFILENAME ofn = {0};
    char szFile[MAX_PATH] = "";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = "Backup Files (*.bak)\0*.bak\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST;
    
    if (GetOpenFileName(&ofn)) {
        FILE* in = fopen(szFile, "rb");
        if (in) {
            char fname[64];
            long size;
            while (fread(fname, 1, 64, in) == 64) {
                if (fread(&size, sizeof(long), 1, in) != 1) break;
                char filepath[MAX_PATH];
                snprintf(filepath, sizeof(filepath), "%s/%s", DATA_DIR, fname);
                FILE* out = fopen(filepath, "wb");
                char* buf = malloc(size);
                if (buf) {
                    fread(buf, 1, size, in);
                    if (out) {
                        fwrite(buf, 1, size, out);
                        fclose(out);
                    }
                    free(buf);
                }
            }
            fclose(in);
            MessageBox(hWnd, "Import Successful!", SERVER_NAME, MB_ICONINFORMATION);
        }
    }
}

VOID CreateTrayIcon(HWND hWnd) {
    g_nid.hWnd = hWnd;
    g_nid.uID = ID_TRAY_ICON;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s - %s", SERVER_NAME, g_bRunning ? "Running" : "Stopped");
    Shell_NotifyIcon(NIM_ADD, &g_nid);
}

VOID RemoveTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &g_nid);
}

VOID ShowContextMenu(HWND hWnd) {
    POINT pt;
    HMENU hMenu = CreatePopupMenu();
    GetCursorPos(&pt);
    AppendMenu(hMenu, MF_STRING | (g_bRunning ? MF_CHECKED : MF_UNCHECKED), ID_MENU_START, "Start Server\tCtrl+S");
    AppendMenu(hMenu, MF_STRING | (!g_bRunning ? MF_CHECKED : MF_UNCHECKED), ID_MENU_STOP, "Stop Server\tCtrl+T");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, ID_MENU_IMPORT, "Import Data (.bak)...");
    AppendMenu(hMenu, MF_STRING, ID_MENU_EXPORT, "Export Data (.bak)...");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, ID_MENU_SETTINGS, "Settings...\tCtrl+P");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, ID_MENU_EXIT, "Exit\tAlt+F4");
    SetForegroundWindow(hWnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hWnd, NULL);
    DestroyMenu(hMenu);
}

INT_PTR CreateSettingsWindow(void) {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = SettingsWndProc;
    wc.hInstance = g_hInstance;
    wc.lpszClassName = "CaldAVDSettingsClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassEx(&wc);
    g_hSettingsWnd = CreateWindowEx(0, "CaldAVDSettingsClass", "CaldAV Server Settings", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 320, 230, NULL, NULL, g_hInstance, NULL);
    if (g_hSettingsWnd) ShowWindow(g_hSettingsWnd, SW_SHOWNORMAL);
    return (INT_PTR)g_hSettingsWnd;
}

LRESULT CALLBACK SettingsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindow("STATIC", "CalDAV Port:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 20, 20, 80, 20, hWnd, NULL, g_hInstance, NULL);
            HWND hEditPort = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | ES_NUMBER | WS_BORDER, 110, 17, 100, 25, hWnd, (HMENU)ID_EDIT_PORT, g_hInstance, NULL);
            CreateWindow("STATIC", "HTTP Port:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 20, 50, 80, 20, hWnd, NULL, g_hInstance, NULL);
            HWND hEditHttpPort = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | ES_NUMBER | WS_BORDER, 110, 47, 100, 25, hWnd, (HMENU)ID_EDIT_HTTP_PORT, g_hInstance, NULL);
            CreateWindow("STATIC", "Timeout (ms):", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 20, 80, 80, 20, hWnd, NULL, g_hInstance, NULL);
            HWND hEditTimeout = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | ES_NUMBER | WS_BORDER, 110, 77, 100, 25, hWnd, (HMENU)ID_EDIT_TIMEOUT, g_hInstance, NULL);
            HWND hChkAnon = CreateWindow("BUTTON", "Anonymous Access", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 112, 150, 20, hWnd, (HMENU)ID_CHK_ANON, g_hInstance, NULL);
            CreateWindow("BUTTON", "Start", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 220, 16, 70, 27, hWnd, (HMENU)ID_BTN_START, g_hInstance, NULL);
            CreateWindow("BUTTON", "Stop", WS_CHILD | WS_VISIBLE, 220, 46, 70, 27, hWnd, (HMENU)ID_BTN_STOP, g_hInstance, NULL);
            
            char valStr[16];
            snprintf(valStr, sizeof(valStr), "%d", g_Port);
            SetWindowText(hEditPort, valStr);
            snprintf(valStr, sizeof(valStr), "%d", g_HttpPort);
            SetWindowText(hEditHttpPort, valStr);
            snprintf(valStr, sizeof(valStr), "%d", g_TimeoutMs);
            SetWindowText(hEditTimeout, valStr);
            SendMessage(hChkAnon, BM_SETCHECK, g_bAnonymous ? BST_CHECKED : BST_UNCHECKED, 0);
            
            EnableWindow(GetDlgItem(hWnd, ID_BTN_START), !g_bRunning);
            EnableWindow(GetDlgItem(hWnd, ID_BTN_STOP), g_bRunning);
            if (g_bRunning) SendMessage(GetDlgItem(hWnd, ID_BTN_STOP), BM_SETSTYLE, BS_PUSHBUTTON, TRUE);
            
            SetProp(hWnd, "EditPort", (HANDLE)hEditPort);
            SetProp(hWnd, "EditHttpPort", (HANDLE)hEditHttpPort);
            SetProp(hWnd, "EditTimeout", (HANDLE)hEditTimeout);
            return 0;
        }
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT: {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, RGB(0, 0, 0));
            SetBkColor(hdcStatic, RGB(255, 255, 255));
            return (LRESULT)GetStockObject(WHITE_BRUSH);
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_EDIT_PORT:
                case ID_EDIT_HTTP_PORT:
                case ID_EDIT_TIMEOUT:
                    if (HIWORD(wParam) == EN_CHANGE) {
                        KillTimer(hWnd, 1);
                        SetTimer(hWnd, 1, PORT_UPDATE_DELAY_MS, UpdateTimerCallback);
                    }
                    return 0;
                case ID_CHK_ANON:
                    g_bAnonymous = (SendMessage((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    SaveConfig();
                    return 0;
                case ID_BTN_START:
                    if (!g_bRunning) {
                        HWND hEdit = GetProp(hWnd, "EditPort");
                        HWND hEditHttp = GetProp(hWnd, "EditHttpPort");
                        if (hEdit && hEditHttp) {
                            char portStr[16];
                            GetWindowText((HWND)hEdit, portStr, sizeof(portStr));
                            int newPort = atoi(portStr);
                            GetWindowText((HWND)hEditHttp, portStr, sizeof(portStr));
                            int newHttpPort = atoi(portStr);
                            
                            if (newPort >= 1 && newPort <= 65535 && newHttpPort >= 1 && newHttpPort <= 65535) {
                                g_Port = newPort;
                                g_HttpPort = newHttpPort;
                                if (StartServer(g_Port)) {
                                    g_bRunning = TRUE;
                                    HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ServerThread, NULL, 0, NULL);
                                    if (hThread) CloseHandle(hThread);
                                    if (StartHttpServer(g_HttpPort)) {
                                        HANDLE hHttpThread = (HANDLE)_beginthreadex(NULL, 0, HttpServerThread, NULL, 0, NULL);
                                        if (hHttpThread) CloseHandle(hHttpThread);
                                    }
                                    SetWindowText(GetDlgItem(hWnd, ID_BTN_STOP), "Stop Running");
                                    SendMessage(GetDlgItem(hWnd, ID_BTN_STOP), BM_SETSTYLE, BS_PUSHBUTTON | BS_OWNERDRAW, TRUE);
                                    HDC hdcBtn = GetDC(GetDlgItem(hWnd, ID_BTN_STOP));
                                    RECT rc; GetClientRect(GetDlgItem(hWnd, ID_BTN_STOP), &rc);
                                    HBRUSH hBrush = CreateSolidBrush(RGB(0, 200, 0));
                                    FillRect(hdcBtn, &rc, hBrush);
                                    DeleteObject(hBrush); ReleaseDC(GetDlgItem(hWnd, ID_BTN_STOP), hdcBtn);
                                    snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s - Running (CalDAV:%d, HTTP:%d)", SERVER_NAME, g_Port, g_HttpPort);
                                    Shell_NotifyIcon(NIM_MODIFY, &g_nid);
                                    MessageBox(hWnd, "Servers started successfully!", SERVER_NAME, MB_ICONINFORMATION);
                                } else { MessageBox(hWnd, "Failed to start server. Ports may be in use.", SERVER_NAME, MB_ICONERROR); }
                            }
                        }
                    }
                    return 0;
                case ID_BTN_STOP:
                    if (g_bRunning) {
                        StopServer();
                        g_bRunning = FALSE;
                        SetWindowText(GetDlgItem(hWnd, ID_BTN_STOP), "Stop");
                        SendMessage(GetDlgItem(hWnd, ID_BTN_STOP), BM_SETSTYLE, BS_PUSHBUTTON, TRUE);
                        snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s - Stopped", SERVER_NAME);
                        Shell_NotifyIcon(NIM_MODIFY, &g_nid);
                        MessageBox(hWnd, "Servers stopped.", SERVER_NAME, MB_ICONINFORMATION);
                    }
                    return 0;
            }
            return DefWindowProc(hWnd, msg, wParam, lParam);
        }
        case WM_CLOSE: ShowWindow(hWnd, SW_HIDE); return 0;
        case WM_DESTROY:
            RemoveProp(hWnd, "EditPort");
            RemoveProp(hWnd, "EditHttpPort");
            RemoveProp(hWnd, "EditTimeout");
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

VOID CALLBACK UpdateTimerCallback(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    (void)uMsg; (void)idEvent; (void)dwTime;
    KillTimer(hwnd, idEvent);
    if (g_hSettingsWnd) {
        HWND hEditPort = GetProp(g_hSettingsWnd, "EditPort");
        if (hEditPort) {
            char portStr[16]; GetWindowText(hEditPort, portStr, sizeof(portStr));
            int newPort = atoi(portStr);
            if (newPort >= 1 && newPort <= 65535 && newPort != g_Port) g_Port = newPort;
        }
        HWND hEditHttpPort = GetProp(g_hSettingsWnd, "EditHttpPort");
        if (hEditHttpPort) {
            char portStr[16]; GetWindowText(hEditHttpPort, portStr, sizeof(portStr));
            int newHttpPort = atoi(portStr);
            if (newHttpPort >= 1 && newHttpPort <= 65535 && newHttpPort != g_HttpPort) g_HttpPort = newHttpPort;
        }
        HWND hEditTimeout = GetProp(g_hSettingsWnd, "EditTimeout");
        if (hEditTimeout) {
            char timeoutStr[16]; GetWindowText(hEditTimeout, timeoutStr, sizeof(timeoutStr));
            int newTimeout = atoi(timeoutStr);
            if (newTimeout > 0 && newTimeout != g_TimeoutMs) g_TimeoutMs = newTimeout;
        }
        SaveConfig();
    }
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: g_TaskbarCreatedMsg = RegisterWindowMessage("TaskbarCreated"); break;
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP) ShowContextMenu(hWnd);
            break;
        case WM_COMMAND:
            switch (wParam) {
                case ID_MENU_START:
                    if (!g_bRunning && LoadConfig() && StartServer(g_Port)) {
                        g_bRunning = TRUE;
                        g_hMainWnd = hWnd;
                        HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ServerThread, NULL, 0, NULL);
                        if (hThread) CloseHandle(hThread);
                        if (StartHttpServer(g_HttpPort)) {
                            HANDLE hHttpThread = (HANDLE)_beginthreadex(NULL, 0, HttpServerThread, NULL, 0, NULL);
                            if (hHttpThread) CloseHandle(hHttpThread);
                        }
                        snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s - Running (CalDAV:%d, HTTP:%d)", SERVER_NAME, g_Port, g_HttpPort);
                        Shell_NotifyIcon(NIM_MODIFY, &g_nid);
                    }
                    break;
                case ID_MENU_STOP:
                    if (g_bRunning) {
                        StopServer();
                        g_bRunning = FALSE;
                        snprintf(g_nid.szTip, sizeof(g_nid.szTip), "%s - Stopped", SERVER_NAME);
                        Shell_NotifyIcon(NIM_MODIFY, &g_nid);
                    }
                    break;
                case ID_MENU_IMPORT: HandleImportData(hWnd); break;
                case ID_MENU_EXPORT: HandleExportData(hWnd); break;
                case ID_MENU_SETTINGS: CreateSettingsWindow(); break;
                case ID_MENU_EXIT: DestroyWindow(hWnd); break;
            }
            break;
        case WM_CLOSE:
            if (g_bRunning) StopServer();
            DestroyWindow(hWnd);
            break;
        case WM_DESTROY: RemoveTrayIcon(); PostQuitMessage(0); break;
        default:
            if (msg == g_TaskbarCreatedMsg && g_TaskbarCreatedMsg != 0) { CreateTrayIcon(hWnd); return 0; }
            break;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR cmdLine, int cmdShow) {
    (void)hPrevInst; (void)cmdLine; (void)cmdShow;
    g_hInstance = hInst;
    INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);
    LoadConfig(); SeedDefaultUser();
    CreateDirectory(DATA_DIR, NULL); CreateDirectory(WEB_DIR, NULL);
    
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_hInstance;
    wc.lpszClassName = "CaldAVDMainClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassEx(&wc);
    
    g_hMainWnd = CreateWindowEx(0, "CaldAVDMainClass", SERVER_NAME, WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, g_hInstance, NULL);
    if (!g_hMainWnd) { MessageBox(NULL, "Failed to create main window.", SERVER_NAME, MB_ICONERROR); return 1; }
    
    if (StartServer(g_Port)) {
        g_bRunning = TRUE;
        HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ServerThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
        if (StartHttpServer(g_HttpPort)) {
            HANDLE hHttpThread = (HANDLE)_beginthreadex(NULL, 0, HttpServerThread, NULL, 0, NULL);
            if (hHttpThread) CloseHandle(hHttpThread);
        }
    }

    CreateTrayIcon(g_hMainWnd);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessage(&msg); }
    if (g_bRunning) StopServer();
    return (int)msg.wParam;
}
