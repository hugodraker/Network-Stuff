/* ============================================================================
 * smtpd - Win32 SMTP Proxy to IMAP Append Server
 * 
 * COMPILATION:
 *   gcc -Os -s smtpd.c -o smtpd.exe -lws2_32 -mwindows -lcomctl32 -ladvapi32 -lcrypt32
 *
 * FEATURES:
 *  - High-Speed Win32 SMTP Proxy (Up to 25MB Payloads)
 *  - Subdomain routing & Local IMAP Appending
 *  - Granular Authentication Control
 *  - Inline Host Editing
 *  - Comprehensive Event Logging
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "crypt32.lib")
#define WM_TRAYICON (WM_USER + 1)
#define MAX_HOSTS 100
#define INI_SMTPD ".\\smtpd.ini"
#define INI_IMAPD ".\\imapd.ini"
#define LOG_FILE ".\\smtpd.log"
#define MAX_EMAIL_SIZE (1024 * 1024 * 25) // Increased to 25 MB for large image attachments

#define ID_TIMER_PORT 1
#define ID_TRAY_EXIT 1001
#define ID_TRAY_SETTINGS 1002
#define ID_TRAY_TOGGLE 1003
#define ID_EDIT_PORT 2001
#define ID_LIST_HOSTS 2002
#define ID_BTN_ADD 2003
#define ID_BTN_DEL 2004
#define ID_BTN_CLOSE 2005
#define ID_CHK_GLOBAL_PASS 2006
#define ID_CHK_LOGGING 2007
typedef struct {
    int is_active;
    int pass_req;
    char hostname[256];
    char ips[6][256];
    int imap_port;
    char username[256];
    char password[256];
} HostEntry;

typedef struct {
    int smtp_port;
    int global_pass_req;
    int enable_logging;
    HostEntry hosts[MAX_HOSTS];
    int host_count;
} ServerConfig;

// Globals
ServerConfig g_config = {0};
SOCKET g_listen_sock = INVALID_SOCKET;
HWND g_hwndMain = NULL, g_hwndSettings = NULL;
HWND hEditPort, hListHosts, hStaticStatus, hCheckGlobalPass, hCheckLogging;
HWND hAddHost, hAddIP, hAddPort, hAddPassReq, hAddUser, hAddPass;
HANDLE g_hThreadSmtp = NULL;
BOOL g_app_running = TRUE;
BOOL g_server_active = FALSE;
NOTIFYICONDATA g_nid = {0};
HBRUSH g_hBrushGreen = NULL;
HBRUSH g_hBrushRed = NULL;
HBRUSH g_hBrushGray = NULL;

HWND g_hwndEdit = NULL;
int g_editRow = -1, g_editCol = -1;
WNDPROC g_oldEditProc = NULL;

DWORD WINAPI SmtpListenerThread(LPVOID lpParam);
void SaveHostsToIni();
void RefreshListView();

// --- Logging ---
void LogEvent(const char* format, ...) {
    if (!g_config.enable_logging) return;
    FILE* f = fopen(LOG_FILE, "a");
    if (!f) return;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    va_list args;
    va_start(args, format);
    vfprintf(f, format, args);
    va_end(args);
    
    fprintf(f, "\n");
    fclose(f);
}

// --- Hashing & Crypto ---
BOOL ComputeSHA256(const char* input, char* output_hex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)input, strlen(input), 0)) {
                BYTE hashVal[32];
                DWORD hashLen = 32;
                if (CryptGetHashParam(hHash, HP_HASHVAL, hashVal, &hashLen, 0)) {
                    for (DWORD i = 0; i < hashLen; i++) {
                        sprintf(&output_hex[i * 2], "%02x", hashVal[i]);
                    }
                    result = TRUE;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

static const int b64index[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,63,62,62,63,52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
    0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
    0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51
};

void DecodeBase64(const char* data, char* out, size_t out_size) {
    int pad = 0; size_t len = strlen(data);
    while (len > 0 && (data[len - 1] == '=' || data[len - 1] == '\r' || data[len - 1] == '\n')) len--;
    size_t j = 0;
    for (size_t i = 0; i < len && j < out_size - 3; i += 4) {
        int n = b64index[(unsigned char)data[i]] << 18 | b64index[(unsigned char)data[i + 1]] << 12 | 
                (i + 2 < len ? b64index[(unsigned char)data[i + 2]] << 6 : 0) | 
                (i + 3 < len ? b64index[(unsigned char)data[i + 3]] : 0);
        out[j++] = (n >> 16) & 0xFF;
        if (i + 2 < len) out[j++] = (n >> 8) & 0xFF;
        if (i + 3 < len) out[j++] = n & 0xFF;
    }
    out[j] = '\0';
}

// --- Config Management ---
char* ParseToken(char** ctx) {
    if (!*ctx) return NULL;
    char* start = *ctx;
    char* end = strchr(start, '|');
    if (end) { *end = '\0'; *ctx = end + 1; } 
    else { *ctx = NULL; }
    return start;
}

void SaveHostsToIni() {
    WritePrivateProfileString("Hosts", NULL, NULL, INI_SMTPD);
    for (int i = 0; i < g_config.host_count; i++) {
        char key[32], val[4096];
        sprintf(key, "Host%d", i);
        HostEntry* h = &g_config.hosts[i];
        sprintf(val, "%d|%d|%s|%s|%s|%s|%s|%s|%s|%d|%s|%s",
            h->is_active, h->pass_req, h->hostname, h->ips[0], h->ips[1], h->ips[2], h->ips[3], h->ips[4], h->ips[5],
            h->imap_port, h->username, h->password);
        WritePrivateProfileString("Hosts", key, val, INI_SMTPD);
    }
}

void LoadConfig() {
    char buffer[4096];
    g_config.smtp_port = GetPrivateProfileInt("Settings", "SmtpPort", 2525, INI_SMTPD);
    g_config.global_pass_req = GetPrivateProfileInt("Settings", "GlobalPassReq", 1, INI_SMTPD);
    g_config.enable_logging = GetPrivateProfileInt("Settings", "EnableLogging", 0, INI_SMTPD);
    g_config.host_count = 0;

    for (int i = 0; i < MAX_HOSTS; i++) {
        char key[32]; sprintf(key, "Host%d", i);
        GetPrivateProfileString("Hosts", key, "", buffer, sizeof(buffer), INI_SMTPD);
        if (buffer[0] == '\0') break;
        
        char* ctx = buffer;
        HostEntry* h = &g_config.hosts[g_config.host_count];
        char* t = ParseToken(&ctx); if (t) h->is_active = atoi(t);
        t = ParseToken(&ctx); if (t) h->pass_req = atoi(t);
        t = ParseToken(&ctx); if (t) strncpy(h->hostname, t, 255);
        for(int j=0; j<6; j++) { t = ParseToken(&ctx); if (t) strncpy(h->ips[j], t, 255); }
        t = ParseToken(&ctx); if (t) h->imap_port = atoi(t);
        t = ParseToken(&ctx); if (t) strncpy(h->username, t, 255);
        t = ParseToken(&ctx); if (t) strncpy(h->password, t, 255);
        g_config.host_count++;
    }
}

void RefreshListView() {
    ListView_DeleteAllItems(hListHosts);
    for (int i = 0; i < g_config.host_count; i++) {
        HostEntry* h = &g_config.hosts[i];
        LVITEM lvi = {0};
        lvi.mask = LVIF_TEXT; lvi.iItem = i; lvi.pszText = "";
        ListView_InsertItem(hListHosts, &lvi);
        
        ListView_SetCheckState(hListHosts, i, h->is_active);
        ListView_SetItemText(hListHosts, i, 1, h->hostname);
        ListView_SetItemText(hListHosts, i, 2, h->ips[0]);
        ListView_SetItemText(hListHosts, i, 3, h->ips[1]);
        ListView_SetItemText(hListHosts, i, 4, h->ips[2]);
        ListView_SetItemText(hListHosts, i, 5, h->ips[3]);
        ListView_SetItemText(hListHosts, i, 6, h->ips[4]);
        ListView_SetItemText(hListHosts, i, 7, h->ips[5]);
        
        char portBuf[16]; sprintf(portBuf, "%d", h->imap_port);
        ListView_SetItemText(hListHosts, i, 8, portBuf);
        ListView_SetItemText(hListHosts, i, 9, h->pass_req ? "1" : "0");
        ListView_SetItemText(hListHosts, i, 10, h->username);
        ListView_SetItemText(hListHosts, i, 11, h->password);
    }
}

// --- Server Management ---
void StopServer() {
    if (g_server_active) {
        LogEvent("Server stopping on port %d...", g_config.smtp_port);
        g_server_active = FALSE;
        closesocket(g_listen_sock);
        WaitForSingleObject(g_hThreadSmtp, 3000);
        LogEvent("Server successfully stopped.");
    }
    if (hStaticStatus) {
        SetWindowText(hStaticStatus, "SERVER STOPPED");
        InvalidateRect(hStaticStatus, NULL, TRUE);
    }
}

void StartServer() {
    if (!g_server_active) {
        g_server_active = TRUE;
        g_hThreadSmtp = CreateThread(NULL, 0, SmtpListenerThread, NULL, 0, NULL);
        LogEvent("Server started listening on port %d.", g_config.smtp_port);
    }
    if (hStaticStatus) {
        SetWindowText(hStaticStatus, "SERVER RUNNING");
        InvalidateRect(hStaticStatus, NULL, TRUE);
    }
}

// --- Host Identification & Routing ---
HostEntry* FindHostForDomain(const char* domain) {
    for (int i = 0; i < g_config.host_count; i++) {
        if (!g_config.hosts[i].is_active) continue;
        const char* host = g_config.hosts[i].hostname;
        int h_len = strlen(host);
        int d_len = strlen(domain);
        
        if (d_len == h_len && _stricmp(domain, host) == 0) {
            return &g_config.hosts[i];
        }
        if (d_len > h_len && domain[d_len - h_len - 1] == '.' && _stricmp(domain + d_len - h_len, host) == 0) {
            return &g_config.hosts[i];
        }
    }
    return NULL;
}

// --- Network Stream Helper ---
BOOL SafeIMAPRecv(SOCKET sock, const char* expected, char* out_buf, int out_size) {
    int total = 0;
    out_buf[0] = '\0';
    while (total < out_size - 1) {
        int n = recv(sock, out_buf + total, out_size - total - 1, 0);
        if (n <= 0) return FALSE;
        total += n;
        out_buf[total] = '\0';
        
        if (strstr(out_buf, expected) != NULL) return TRUE;
        
        if (expected[0] == '+' && (strstr(out_buf, "A02 NO") || strstr(out_buf, "A02 BAD"))) return FALSE;
        
        if (total >= out_size - 256) {
            memmove(out_buf, out_buf + total - 128, 128);
            total = 128;
            out_buf[total] = '\0';
        }
    }
    return FALSE;
}

BOOL AppendToImap(const char* domain, const char* auth_user, const char* client_ip, const char* mail_from, const char* rcpt_to, const char* raw_email_data, size_t raw_email_len) {
    HostEntry* target = FindHostForDomain(domain);
    
    char headers[2048];
    SYSTEMTIME st; GetLocalTime(&st);
    char date_str[64];
    const char* days[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    sprintf(date_str, "%s, %02d %s %04d %02d:%02d:%02d +0000", 
            days[st.wDayOfWeek], st.wDay, months[st.wMonth-1], st.wYear, st.wHour, st.wMinute, st.wSecond);

    sprintf(headers, 
        "Return-Path: <%s>\r\n"
        "Delivered-To: %s\r\n"
        "Received: from [%s] by localhost with SMTP; %s\r\n"
        "X-Original-User: %s\r\n"
        "X-Source-IP: %s\r\n", 
        mail_from, rcpt_to, client_ip, date_str, auth_user, client_ip);

    size_t email_size = strlen(headers) + raw_email_len;

// --- EXTERNAL MTA FORWARDING ---
    if (!target) {
        char mta_cmd[1024];
        GetPrivateProfileString("ExternalMTA", "Command", "", mta_cmd, sizeof(mta_cmd), INI_SMTPD);
        if (mta_cmd[0] != '\0') {
            BOOL use_file = (strstr(mta_cmd, "{file}") != NULL);
            BOOL use_cli_payload = (strstr(mta_cmd, "{payload}") != NULL);
            char temp_path[MAX_PATH], temp_file[MAX_PATH] = {0};
            
            if (use_file) {
                GetTempPath(MAX_PATH, temp_path);
                GetTempFileName(temp_path, "EML", 0, temp_file);
                FILE* f = fopen(temp_file, "wb");
                if (f) {
                    fwrite(headers, 1, strlen(headers), f);
                    fwrite(raw_email_data, 1, raw_email_len, f);
                    fclose(f);
                }
            }
            
            char final_cmd[32768] = {0}; // Win32 Max Command Line Length
            char* p = mta_cmd;
            char* d = final_cmd;
            
            while (*p && (d - final_cmd) < 32000) {
                if (strncmp(p, "{from}", 6) == 0) { strcpy(d, mail_from); d += strlen(mail_from); p += 6; }
                else if (strncmp(p, "{to}", 4) == 0) { strcpy(d, rcpt_to); d += strlen(rcpt_to); p += 4; }
                else if (strncmp(p, "{file}", 6) == 0) { strcpy(d, temp_file); d += strlen(temp_file); p += 6; }
                else if (strncmp(p, "{payload}", 9) == 0) {
                    size_t avail = 32000 - (d - final_cmd);
                    size_t h_len = strlen(headers);
                    if (h_len < avail) { strcpy(d, headers); d += h_len; avail -= h_len; }
                    size_t to_copy = raw_email_len < avail ? raw_email_len : avail;
                    memcpy(d, raw_email_data, to_copy); d += to_copy;
                    p += 9;
                }
                else { *d++ = *p++; }
            }
            *d = '\0';
            
            LogEvent("Routing external mail to %s via MTA: %s", rcpt_to, final_cmd);
            
            STARTUPINFO si = { sizeof(STARTUPINFO) };
            PROCESS_INFORMATION pi = {0};
            HANDLE hReadPipe = NULL, hWritePipe = NULL;
            
            // If neither {file} nor {payload} are specified, pipe it securely via STDIN
            if (!use_file && !use_cli_payload) {
                SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
                if (CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
                    SetHandleInformation(hWritePipe, HANDLE_FLAG_INHERIT, 0); // Secure write end
                    si.hStdInput = hReadPipe;
                    si.dwFlags |= STARTF_USESTDHANDLES;
                }
            }
            
            // CreateProcess with bInheritHandles = TRUE for pipes to work
            if (CreateProcess(NULL, final_cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                if (hReadPipe) CloseHandle(hReadPipe); // Parent doesn't read
                
                if (hWritePipe) {
                    DWORD written;
                    WriteFile(hWritePipe, headers, (DWORD)strlen(headers), &written, NULL);
                    WriteFile(hWritePipe, raw_email_data, (DWORD)raw_email_len, &written, NULL);
                    CloseHandle(hWritePipe); // Sending EOF to the child process
                }
                
                WaitForSingleObject(pi.hProcess, 60000); // 60s timeout
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                LogEvent("Failed to execute external MTA. Error: %d", GetLastError());
                if (hReadPipe) CloseHandle(hReadPipe);
                if (hWritePipe) CloseHandle(hWritePipe);
            }
            
            if (use_file) DeleteFile(temp_file);
            return TRUE;

        }
    }
/*
To configure it, add this block to your smtpd.ini file. If Command is left empty or missing, smtpd.exe falls back to attempting a direct DNS resolution delivery as it does currently.
[ExternalMTA]
Command=C:\MTA\send.exe --sender {from} --recipient {to} --payload {file}

By leaving out {file} or {payload}, the proxy automatically streams the payload seamlessly via Standard Input without touching the disk.
Command=C:\MTA\send.exe --sender {from} --recipient {to}

Note that any email exceeding ~32KB will be forcefully truncated to prevent the buffer from crashing Win32.
Command=C:\MTA\send.exe --sender {from} --recipient {to} --payload "{payload}"

*/

    // --- STANDARD IMAP DELIVERY ---
    char resolved_ip[256] = {0};
    int imap_port = 143;

    if (target) {
        strncpy(resolved_ip, target->ips[0], 255); 
        imap_port = target->imap_port;
        LogEvent("Routed %s to matched host: %s (%s:%d)", domain, target->hostname, resolved_ip, imap_port);
    } else {
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(domain, NULL, &hints, &res) == 0) {
            inet_ntop(AF_INET, &(((struct sockaddr_in*)res->ai_addr)->sin_addr), resolved_ip, 256);
            freeaddrinfo(res);
            LogEvent("Resolved fallback DNS for %s -> %s", domain, resolved_ip);
        } else {
            LogEvent("Failed DNS resolution for target domain: %s", domain);
            return FALSE;
        }
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(imap_port);
    inet_pton(AF_INET, resolved_ip, &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        LogEvent("IMAP connection failed to %s:%d", resolved_ip, imap_port);
        closesocket(sock);
        return FALSE;
    }

    char buffer[4096];
    SafeIMAPRecv(sock, "\r\n", buffer, sizeof(buffer)); 
    
    if (target && target->password[0]) {
        char cmd[1024];
        sprintf(cmd, "A01 LOGIN \"%s\" \"%s\"\r\n", rcpt_to, target->password);
        send(sock, cmd, strlen(cmd), 0);
        SafeIMAPRecv(sock, "A01 ", buffer, sizeof(buffer)); 
        if (strstr(buffer, "A01 OK") == NULL) {
            LogEvent("IMAP LOGIN failed for impersonated user %s: %s", rcpt_to, buffer);
            closesocket(sock);
            return FALSE;
        }
    }

    char cmd[512];
    sprintf(cmd, "A02 APPEND INBOX {%zu}\r\n", email_size);
    send(sock, cmd, strlen(cmd), 0);
    
    if (SafeIMAPRecv(sock, "+", buffer, sizeof(buffer))) {
        send(sock, headers, strlen(headers), 0);
        send(sock, raw_email_data, raw_email_len, 0); 
        send(sock, "\r\n", 2, 0);
        
        SafeIMAPRecv(sock, "A02 ", buffer, sizeof(buffer));
        if (strstr(buffer, "A02 OK") != NULL) {
            LogEvent("Message successfully appended to IMAP.");
        } else {
            LogEvent("IMAP APPEND rejected after data: %s", buffer);
        }
    } else {
        LogEvent("IMAP server rejected APPEND command literal: %s", buffer);
    }

    send(sock, "A03 LOGOUT\r\n", 12, 0);
    closesocket(sock);
    return TRUE;
}
DWORD WINAPI SmtpClientHandler(LPVOID lpParam) {
    SOCKET client_sock = (SOCKET)lpParam;
    struct sockaddr_in peer; int peer_len = sizeof(peer);
    getpeername(client_sock, (struct sockaddr*)&peer, &peer_len);
    char client_ip[256];
    inet_ntop(AF_INET, &peer.sin_addr, client_ip, sizeof(client_ip));
    
    LogEvent("New inbound SMTP connection from %s", client_ip);

    char recv_buf[1024];
    // Dynamic high-capacity allocation for heavy media payloads
    char* raw_email = (char*)malloc(MAX_EMAIL_SIZE); 
    char auth_user[256] = {0};
    char rcpt_domain[256] = {0};
    char mail_from[256] = {0};
    char rcpt_to[256] = {0};
    BOOL authenticated = FALSE;
    
    if (!raw_email) { closesocket(client_sock); return 0; }
    raw_email[0] = '\0';

    send(client_sock, "220 SmtpToImap Proxy Ready\r\n", 28, 0);

    int n;
    while (g_server_active && (n = recv(client_sock, recv_buf, sizeof(recv_buf)-1, 0)) > 0) {
        recv_buf[n] = '\0';
        
        if (_strnicmp(recv_buf, "EHLO", 4) == 0 || _strnicmp(recv_buf, "HELO", 4) == 0) {
            const char* ehlo_reply = "250-localhost Hello\r\n250 AUTH LOGIN\r\n";
            send(client_sock, ehlo_reply, strlen(ehlo_reply), 0);
        }
        else if (_strnicmp(recv_buf, "AUTH LOGIN", 10) == 0) {
            send(client_sock, "334 VXNlcm5hbWU6\r\n", 18, 0);
            
            n = recv(client_sock, recv_buf, sizeof(recv_buf)-1, 0); 
            if (n > 0) recv_buf[n] = '\0';
            DecodeBase64(recv_buf, auth_user, sizeof(auth_user));

            send(client_sock, "334 UGFzc3dvcmQ6\r\n", 18, 0);
            
            n = recv(client_sock, recv_buf, sizeof(recv_buf)-1, 0);
            if (n > 0) recv_buf[n] = '\0';
            char decoded_pass[256] = {0};
            DecodeBase64(recv_buf, decoded_pass, sizeof(decoded_pass));
            
            char imapd_user[256], imapd_salt[256], imapd_hash[128];
            GetPrivateProfileString("Auth", "Username", "", imapd_user, sizeof(imapd_user), INI_IMAPD);
            GetPrivateProfileString("Auth", "Salt", "", imapd_salt, sizeof(imapd_salt), INI_IMAPD);
            GetPrivateProfileString("Auth", "Hash", "", imapd_hash, sizeof(imapd_hash), INI_IMAPD);

            char concat[1024], computed_hash[65] = {0};
            sprintf(concat, "%s%s", imapd_salt, decoded_pass);
            ComputeSHA256(concat, computed_hash);

            if (strcmp(imapd_user, auth_user) == 0 && _stricmp(computed_hash, imapd_hash) == 0) {
                authenticated = TRUE;
                LogEvent("Authentication successful for user: %s", auth_user);
                send(client_sock, "235 Authentication successful\r\n", 31, 0);
            } else {
                LogEvent("Authentication failed for attempted user: %s", auth_user);
                send(client_sock, "535 Authentication failed\r\n", 27, 0);
            }
        }
        else if (_strnicmp(recv_buf, "MAIL FROM:", 10) == 0) {
            char* start = strchr(recv_buf, '<');
            char* end = strchr(recv_buf, '>');
            if (start && end && end > start) {
                size_t len = end - (start + 1);
                strncpy(mail_from, start + 1, len < 255 ? len : 255);
                mail_from[len] = '\0';
            }
            send(client_sock, "250 OK\r\n", 8, 0);
        }
        else if (_strnicmp(recv_buf, "RCPT TO:", 8) == 0) {
            char* start = strchr(recv_buf, '<');
            char* end = strchr(recv_buf, '>');
            if (start && end && end > start) {
                size_t len = end - (start + 1);
                strncpy(rcpt_to, start + 1, len < 255 ? len : 255);
                rcpt_to[len] = '\0';
                
                char* at = strchr(rcpt_to, '@');
                if (at) strncpy(rcpt_domain, at + 1, 255);
            }

            HostEntry* target = FindHostForDomain(rcpt_domain);
            BOOL host_pass_req = target ? target->pass_req : 1;

            if (g_config.global_pass_req && host_pass_req && !authenticated) {
                LogEvent("Rejected RCPT TO %s: Auth Required.", rcpt_to);
                send(client_sock, "530 Auth required\r\n", 19, 0);
            } else {
                LogEvent("Accepted RCPT TO %s", rcpt_to);
                send(client_sock, "250 OK\r\n", 8, 0);
            }
        }
        else if (_strnicmp(recv_buf, "DATA", 4) == 0) {
            HostEntry* target = FindHostForDomain(rcpt_domain);
            BOOL host_pass_req = target ? target->pass_req : 1;

            if (g_config.global_pass_req && host_pass_req && !authenticated) {
                send(client_sock, "530 Not authenticated\r\n", 23, 0);
                continue;
            }

            send(client_sock, "354 End data with <CR><LF>.<CR><LF>\r\n", 37, 0);
            LogEvent("Receiving DATA stream...");
            
            // High-Performance Stream Aggregation
            size_t email_len = 0;
            while (email_len < MAX_EMAIL_SIZE - 1) {
                n = recv(client_sock, raw_email + email_len, MAX_EMAIL_SIZE - email_len - 1, 0);
                if (n <= 0) break;
                
                email_len += n;
                raw_email[email_len] = '\0';
                
                // Only scan the newly added bytes to prevent massive O(N^2) CPU slowdowns
                size_t search_start = (email_len > (size_t)n + 4) ? (email_len - n - 4) : 0;
                char* dot_pos = strstr(raw_email + search_start, "\r\n.\r\n");
                
                if (dot_pos) {
                    dot_pos[2] = '\0'; // Preserve the \r\n of the final line
                    email_len = dot_pos + 2 - raw_email;
                    break;
                }
            }

            if (!authenticated) strcpy(auth_user, "Anonymous");
            
          LogEvent("Dispatching Email: Mail From: <%s>, Rcpt To: <%s>, Payload Size: %zu Bytes", mail_from, rcpt_to, email_len);
            
            if (AppendToImap(rcpt_domain[0] ? rcpt_domain : "localhost", auth_user, client_ip, mail_from, rcpt_to, raw_email, email_len)) {
                send(client_sock, "250 OK: Message appended to IMAP\r\n", 34, 0);
            } else {
                LogEvent("Delivery failed. Initiating Return to Sender bounce to <%s>", mail_from);
                
                // Prevent infinite bounce loops if the postmaster's own mail fails
                if (mail_from[0] != '\0' && _stricmp(mail_from, "postmaster@localhost") != 0) {
                    char* bounce_payload = (char*)malloc(email_len + 2048);
                    if (bounce_payload) {
                        char bounce_headers[1024];
                        SYSTEMTIME st; GetLocalTime(&st);
                        const char* days[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
                        const char* months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
                        char date_str[64];
                        sprintf(date_str, "%s, %02d %s %04d %02d:%02d:%02d +0000", 
                                days[st.wDayOfWeek], st.wDay, months[st.wMonth-1], st.wYear, st.wHour, st.wMinute, st.wSecond);
                        
                        sprintf(bounce_headers, 
                            "From: Mail Delivery Subsystem <postmaster@localhost>\r\n"
                            "To: <%s>\r\n"
                            "Subject: Undelivered Mail Returned to Sender\r\n"
                            "Date: %s\r\n"
                            "Content-Type: text/plain\r\n"
                            "\r\n"
                            "This is the mail system at localhost.\r\n\r\n"
                            "I'm sorry to have to inform you that your message could not be delivered.\r\n"
                            "The mailbox for <%s> does not exist or is unavailable.\r\n\r\n"
                            "   ----- Original message follows -----\r\n\r\n",
                            mail_from, date_str, rcpt_to);
                        
                        strcpy(bounce_payload, bounce_headers);
                        size_t bounce_hdr_len = strlen(bounce_headers);
                        
                        // Append the original email payload below the bounce explanation
                        memcpy(bounce_payload + bounce_hdr_len, raw_email, email_len);
                        bounce_payload[bounce_hdr_len + email_len] = '\0';
                        
                        char sender_domain[256] = "localhost";
                        char* at = strchr(mail_from, '@');
                        if (at) strncpy(sender_domain, at + 1, 255);
                        
                        AppendToImap(sender_domain, "System", "127.0.0.1", "postmaster@localhost", mail_from, bounce_payload, bounce_hdr_len + email_len);
                        free(bounce_payload);
                    }
                }
                
                // Return 250 OK so the email client moves the draft to Sent instead of throwing a popup error
                send(client_sock, "250 OK: Message bounced back to sender\r\n", 40, 0);
            }
        }
        else if (_strnicmp(recv_buf, "QUIT", 4) == 0) {
            send(client_sock, "221 Bye\r\n", 9, 0);
            break;
        }
        else {
            char safe_log[128];
            size_t copy_len = (n < 127) ? n : 127;
            for (size_t i = 0; i < copy_len; i++) {
                safe_log[i] = (recv_buf[i] >= 32 && recv_buf[i] <= 126) ? recv_buf[i] : '.';
            }
            safe_log[copy_len] = '\0';
            
            LogEvent("Unrecognized command: %s", safe_log);
            send(client_sock, "500 Unrecognized command\r\n", 26, 0);
        }
    }
    
    LogEvent("Closing SMTP connection for %s", client_ip);
    free(raw_email);
    closesocket(client_sock);
    return 0;
}
DWORD WINAPI SmtpListenerThread(LPVOID lpParam) {
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(g_config.smtp_port);

    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    bind(g_listen_sock, (struct sockaddr*)&server, sizeof(server));
    listen(g_listen_sock, SOMAXCONN);

    while (g_server_active) {
        struct sockaddr_in client_addr; int client_len = sizeof(client_addr);
        SOCKET client_sock = accept(g_listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock != INVALID_SOCKET) {
            CreateThread(NULL, 0, SmtpClientHandler, (LPVOID)client_sock, 0, NULL);
        }
    }
    return 0;
}

// --- UI Logic & Inline Editing ---
void UpdateHostFromEdit(int row, int col, const char* text) {
    HostEntry* h = &g_config.hosts[row];
    switch (col) {
        case 1: strncpy(h->hostname, text, 255); break;
        case 2: strncpy(h->ips[0], text, 255); break;
        case 3: strncpy(h->ips[1], text, 255); break;
        case 4: strncpy(h->ips[2], text, 255); break;
        case 5: strncpy(h->ips[3], text, 255); break;
        case 6: strncpy(h->ips[4], text, 255); break;
        case 7: strncpy(h->ips[5], text, 255); break;
        case 8: h->imap_port = atoi(text); break;
        case 9: h->pass_req = atoi(text) ? 1 : 0; break;
        case 10: strncpy(h->username, text, 255); break;
        case 11: strncpy(h->password, text, 255); break;
    }
    SaveHostsToIni();
    RefreshListView();
}

LRESULT CALLBACK SubItemEditProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        char buf[512]; GetWindowText(hwnd, buf, sizeof(buf));
        UpdateHostFromEdit(g_editRow, g_editCol, buf);
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_KILLFOCUS) {
        char buf[512]; GetWindowText(hwnd, buf, sizeof(buf));
        UpdateHostFromEdit(g_editRow, g_editCol, buf);
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_DESTROY) {
        g_hwndEdit = NULL;
        g_editRow = -1; g_editCol = -1;
    }
    return CallWindowProc(g_oldEditProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            CreateWindow("STATIC", "SMTP Port:", WS_VISIBLE | WS_CHILD, 10, 15, 80, 20, hwnd, NULL, NULL, NULL);
            char pBuf[16]; sprintf(pBuf, "%d", g_config.smtp_port);
            hEditPort = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", pBuf, WS_VISIBLE | WS_CHILD | ES_NUMBER, 90, 13, 50, 22, hwnd, (HMENU)ID_EDIT_PORT, NULL, NULL);
            
            hCheckGlobalPass = CreateWindow("BUTTON", "Global Pass Required", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 160, 15, 160, 20, hwnd, (HMENU)ID_CHK_GLOBAL_PASS, NULL, NULL);
            SendMessage(hCheckGlobalPass, BM_SETCHECK, g_config.global_pass_req ? BST_CHECKED : BST_UNCHECKED, 0);

            hCheckLogging = CreateWindow("BUTTON", "Enable Logging", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 330, 15, 120, 20, hwnd, (HMENU)ID_CHK_LOGGING, NULL, NULL);
            SendMessage(hCheckLogging, BM_SETCHECK, g_config.enable_logging ? BST_CHECKED : BST_UNCHECKED, 0);

            hStaticStatus = CreateWindow("STATIC", g_server_active ? "SERVER RUNNING" : "SERVER STOPPED", WS_VISIBLE | WS_CHILD | SS_CENTER | SS_CENTERIMAGE | SS_NOTIFY, 600, 13, 150, 25, hwnd, (HMENU)ID_TRAY_TOGGLE, NULL, NULL);

            hListHosts = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL, 10, 50, 760, 250, hwnd, (HMENU)ID_LIST_HOSTS, NULL, NULL);
            ListView_SetExtendedListViewStyle(hListHosts, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

            char* cols[] = {"Active", "Host", "IP1", "IP2", "IP3", "IP4", "IP5", "IP6", "Port", "Pass Req", "User", "Pass"};
            int widths[] = {45, 100, 75, 50, 50, 50, 50, 50, 45, 65, 80, 80};
            for (int i = 0; i < 12; i++) {
                LVCOLUMN lvc = {0}; lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
                lvc.cx = widths[i]; lvc.pszText = cols[i];
                ListView_InsertColumn(hListHosts, i, &lvc);
            }
            RefreshListView();

            CreateWindow("STATIC", "Host:", WS_VISIBLE|WS_CHILD, 10, 312, 35, 20, hwnd, NULL, NULL, NULL);
            hAddHost = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE|WS_CHILD, 45, 310, 90, 22, hwnd, NULL, NULL, NULL);
            CreateWindow("STATIC", "IP:", WS_VISIBLE|WS_CHILD, 140, 312, 20, 20, hwnd, NULL, NULL, NULL);
            hAddIP = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE|WS_CHILD, 165, 310, 70, 22, hwnd, NULL, NULL, NULL);
            CreateWindow("STATIC", "Port:", WS_VISIBLE|WS_CHILD, 240, 312, 35, 20, hwnd, NULL, NULL, NULL);
            hAddPort = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "143", WS_VISIBLE|WS_CHILD, 275, 310, 40, 22, hwnd, NULL, NULL, NULL);
            hAddPassReq = CreateWindow("BUTTON", "Pass Req", WS_VISIBLE|WS_CHILD|BS_AUTOCHECKBOX, 320, 312, 75, 20, hwnd, NULL, NULL, NULL);
            SendMessage(hAddPassReq, BM_SETCHECK, BST_CHECKED, 0);
            CreateWindow("STATIC", "User:", WS_VISIBLE|WS_CHILD, 400, 312, 35, 20, hwnd, NULL, NULL, NULL);
            hAddUser = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE|WS_CHILD, 435, 310, 70, 22, hwnd, NULL, NULL, NULL);
            CreateWindow("STATIC", "Pass:", WS_VISIBLE|WS_CHILD, 510, 312, 35, 20, hwnd, NULL, NULL, NULL);
            hAddPass = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE|WS_CHILD|ES_PASSWORD, 545, 310, 70, 22, hwnd, NULL, NULL, NULL);
            
            CreateWindow("BUTTON", "Add Host", WS_VISIBLE|WS_CHILD, 625, 310, 80, 24, hwnd, (HMENU)ID_BTN_ADD, NULL, NULL);
            CreateWindow("BUTTON", "Delete Selected", WS_VISIBLE|WS_CHILD, 10, 350, 120, 30, hwnd, (HMENU)ID_BTN_DEL, NULL, NULL);
            CreateWindow("BUTTON", "Close", WS_VISIBLE|WS_CHILD, 650, 350, 120, 30, hwnd, (HMENU)ID_BTN_CLOSE, NULL, NULL);
            break;

        case WM_CTLCOLORSTATIC:
            if ((HWND)lParam == hStaticStatus) {
                SetTextColor((HDC)wParam, g_server_active ? RGB(0,0,0) : RGB(255,255,255));
                SetBkColor((HDC)wParam, g_server_active ? RGB(0,255,0) : RGB(150,150,150));
                return (LRESULT)(g_server_active ? g_hBrushGreen : g_hBrushGray);
            }
            break;

        case WM_NOTIFY:
            if (((LPNMHDR)lParam)->idFrom == ID_LIST_HOSTS) {
                if (((LPNMHDR)lParam)->code == NM_DBLCLK) {
                    LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
                    if (lpnmitem->iItem != -1 && lpnmitem->iSubItem > 0) {
                        RECT rc;
                        ListView_GetSubItemRect(hListHosts, lpnmitem->iItem, lpnmitem->iSubItem, LVIR_BOUNDS, &rc);
                        char buf[512];
                        ListView_GetItemText(hListHosts, lpnmitem->iItem, lpnmitem->iSubItem, buf, sizeof(buf));
                        
                        g_editRow = lpnmitem->iItem;
                        g_editCol = lpnmitem->iSubItem;
                        g_hwndEdit = CreateWindow("EDIT", buf, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                                  rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                                                  hListHosts, NULL, GetModuleHandle(NULL), NULL);
                        SetFocus(g_hwndEdit);
                        g_oldEditProc = (WNDPROC)SetWindowLongPtr(g_hwndEdit, GWLP_WNDPROC, (LONG_PTR)SubItemEditProc);
                    }
                }
                
                LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
                if (pnmv->hdr.code == LVN_ITEMCHANGED && (pnmv->uChanged & LVIF_STATE)) {
                    BOOL wasChecked = (pnmv->uOldState & LVIS_STATEIMAGEMASK) == INDEXTOSTATEIMAGEMASK(2);
                    BOOL isChecked = (pnmv->uNewState & LVIS_STATEIMAGEMASK) == INDEXTOSTATEIMAGEMASK(2);
                    if (!wasChecked && isChecked) {
                        g_config.hosts[pnmv->iItem].is_active = 1;
                        for (int i = 0; i < g_config.host_count; i++) {
                            if (i != pnmv->iItem && _stricmp(g_config.hosts[i].hostname, g_config.hosts[pnmv->iItem].hostname) == 0) {
                                g_config.hosts[i].is_active = 0;
                                ListView_SetCheckState(hListHosts, i, 0);
                            }
                        }
                        SaveHostsToIni();
                    } else if (wasChecked && !isChecked) {
                        g_config.hosts[pnmv->iItem].is_active = 0;
                        SaveHostsToIni();
                    }
                }
            }
            break;

        case WM_COMMAND:
            if (HIWORD(wParam) == EN_CHANGE && LOWORD(wParam) == ID_EDIT_PORT) {
                SetTimer(hwnd, ID_TIMER_PORT, 1000, NULL);
            }
            else if (LOWORD(wParam) == ID_CHK_GLOBAL_PASS) {
                g_config.global_pass_req = SendMessage(hCheckGlobalPass, BM_GETCHECK, 0, 0) == BST_CHECKED;
                char buf[16]; sprintf(buf, "%d", g_config.global_pass_req);
                WritePrivateProfileString("Settings", "GlobalPassReq", buf, INI_SMTPD);
            }
            else if (LOWORD(wParam) == ID_CHK_LOGGING) {
                g_config.enable_logging = SendMessage(hCheckLogging, BM_GETCHECK, 0, 0) == BST_CHECKED;
                char buf[16]; sprintf(buf, "%d", g_config.enable_logging);
                WritePrivateProfileString("Settings", "EnableLogging", buf, INI_SMTPD);
            }
            else if (LOWORD(wParam) == ID_BTN_ADD) {
                if (g_config.host_count >= MAX_HOSTS) break;
                HostEntry* h = &g_config.hosts[g_config.host_count];
                h->is_active = 0;
                h->pass_req = SendMessage(hAddPassReq, BM_GETCHECK, 0, 0) == BST_CHECKED;
                GetWindowText(hAddHost, h->hostname, 255);
                GetWindowText(hAddIP, h->ips[0], 255);
                char ptBuf[16]; GetWindowText(hAddPort, ptBuf, 15); h->imap_port = atoi(ptBuf);
                GetWindowText(hAddUser, h->username, 255);
                GetWindowText(hAddPass, h->password, 255);
                g_config.host_count++;
                SaveHostsToIni();
                RefreshListView();
            }
            else if (LOWORD(wParam) == ID_BTN_DEL) {
                int sel = ListView_GetNextItem(hListHosts, -1, LVNI_SELECTED);
                if (sel != -1) {
                    for (int i = sel; i < g_config.host_count - 1; i++) {
                        g_config.hosts[i] = g_config.hosts[i+1];
                    }
                    g_config.host_count--;
                    SaveHostsToIni();
                    RefreshListView();
                }
            }
            else if (LOWORD(wParam) == ID_BTN_CLOSE) {
                ShowWindow(hwnd, SW_HIDE);
            }
            else if (LOWORD(wParam) == ID_TRAY_TOGGLE) {
                if (g_server_active) StopServer(); else StartServer();
            }
            break;

        case WM_TIMER:
            if (wParam == ID_TIMER_PORT) {
                KillTimer(hwnd, ID_TIMER_PORT);
                char buf[32]; GetWindowText(hEditPort, buf, sizeof(buf));
                int new_port = atoi(buf);
                if (new_port != g_config.smtp_port && new_port > 0) {
                    g_config.smtp_port = new_port;
                    WritePrivateProfileString("Settings", "SmtpPort", buf, INI_SMTPD);
                    StopServer(); StartServer();
                }
            }
            break;

        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP) {
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING | (g_server_active ? MF_CHECKED : MF_UNCHECKED), ID_TRAY_TOGGLE, g_server_active ? "Server Running" : "Server Stopped");
                AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenu(hMenu, MF_STRING, ID_TRAY_SETTINGS, "Settings");
                AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit");
                
                POINT pt; GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == ID_TRAY_EXIT) {
                PostQuitMessage(0);
            } 
            else if (LOWORD(wParam) == ID_TRAY_SETTINGS) {
                ShowWindow(g_hwndSettings, SW_SHOW);
                SetForegroundWindow(g_hwndSettings);
            }
            else if (LOWORD(wParam) == ID_TRAY_TOGGLE) {
                if (g_server_active) StopServer(); else StartServer();
            }
            break;

        case WM_DESTROY:
            Shell_NotifyIcon(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    InitCommonControls();

    g_hBrushGreen = CreateSolidBrush(RGB(0, 255, 0));
    g_hBrushRed = CreateSolidBrush(RGB(200, 0, 0));
    g_hBrushGray = CreateSolidBrush(RGB(150, 150, 150));

    LoadConfig();

    WNDCLASS wc = {0}; wc.lpfnWndProc = MainWndProc; wc.hInstance = hInstance; wc.lpszClassName = "SmtpProxyMainClass"; RegisterClass(&wc);
    WNDCLASS wcSet = {0}; wcSet.lpfnWndProc = SettingsWndProc; wcSet.hInstance = hInstance; wcSet.hbrBackground = (HBRUSH)(COLOR_WINDOW); wcSet.lpszClassName = "SmtpProxySettingsClass"; RegisterClass(&wcSet);

    g_hwndMain = CreateWindow("SmtpProxyMainClass", "SMTP Proxy", 0, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);
    g_hwndSettings = CreateWindow("SmtpProxySettingsClass", "SMTP/IMAP Proxy Settings", WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT, 800, 430, NULL, NULL, hInstance, NULL);

    g_nid.cbSize = sizeof(NOTIFYICONDATA); g_nid.hWnd = g_hwndMain; g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    strcpy(g_nid.szTip, "SMTP/IMAP Proxy Server");
    Shell_NotifyIcon(NIM_ADD, &g_nid);

    StartServer(); 

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }

    StopServer();
    DeleteObject(g_hBrushGreen); DeleteObject(g_hBrushRed); DeleteObject(g_hBrushGray);
    WSACleanup();
    return 0;
}