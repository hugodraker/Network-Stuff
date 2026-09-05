/*
 * Standalone SMB1 Server Stub & Tray App (With Configurable Shares)
 * 
 * COMPILATION:
 *   gcc -Os -s -o smb1server.exe smb1server.c -lws2_32 -luser32 -lgdi32 -ladvapi32 -lshell32 -lcomctl32 -mwindows
 *
 * ============================================================================
 * PUBLIC DOMAIN DEDICATION:
 *
 * This software is released into the public domain. It is not fit for any 
 * purpose. Use entirely at your own risk.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ============================================================================
 */

#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")

#define WM_TRAYICON         (WM_USER + 1)
#define ID_TRAY_SETTINGS    1001
#define ID_TRAY_TOGGLE      1002
#define ID_TRAY_EXIT        1003

#define IDE_PORT            2001
#define IDL_IPS             2002
#define IDE_LOG             2003
#define IDB_OK              2004
#define IDB_TOGGLE_SRV      2005
#define IDB_CANCEL          2006
#define IDC_CMB_SHARES      2007
#define IDE_SHAREPATH       2008
#define IDB_BROWSE          2009
#define IDB_DEL_SHARE       2010

#define TIMER_SAVE_SHARE    3001

#define MAX_SHARES          50

#pragma pack(push, 1)
typedef struct {
    uint8_t  protocol_id[4];
    uint8_t  cmd;
    uint32_t status;
    uint8_t  flags1;
    uint16_t flags2;
    uint16_t pid_high;
    uint8_t  signature[8];
    uint16_t reserved;
    uint16_t tid;
    uint16_t pid_low;
    uint16_t uid;
    uint16_t mid;
} SMB1Header;
#pragma pack(pop)

typedef struct {
    char name[64];
    char path[MAX_PATH];
} ServerShare;

typedef struct {
    uint16_t tid;
    char path[MAX_PATH];
} TidMap;

static ServerShare g_shares[MAX_SHARES];
static int g_share_count = 0;

static HWND g_hMain = NULL;
static HWND g_hSettings = NULL;
static HWND g_hLogEdit = NULL;
static HWND g_hCmbShares = NULL;
static HWND g_hSharePath = NULL;
static HINSTANCE g_hInst;
static NOTIFYICONDATA g_nid;
static char g_ini_path[MAX_PATH];

static volatile int g_server_running = 0;
static SOCKET g_listen_socket = INVALID_SOCKET;
static HANDLE g_server_thread = NULL;
static int g_port = 445;

static char g_log_buffer[16384] = "Server initialized.\r\n";

/* ==========================================================================
   CONFIG LOAD/SAVE
   ========================================================================== */
static void init_ini_path(void) {
    GetModuleFileNameA(NULL, g_ini_path, MAX_PATH);
    char *ext = strrchr(g_ini_path, '.');
    if (ext) strcpy(ext, ".ini"); else strcat(g_ini_path, ".ini");
}

static void load_config() {
    init_ini_path();
    g_port = GetPrivateProfileIntA("Config", "Port", 445, g_ini_path);
    
    char names[1024] = {0}, paths[4096] = {0};
    GetPrivateProfileStringA("Config", "sharename", "public", names, sizeof(names), g_ini_path);
    GetPrivateProfileStringA("Config", "sharepath", "C:\\", paths, sizeof(paths), g_ini_path);
    
    g_share_count = 0;
    char *n_tok = strtok(names, "|");
    char *p_tok = strtok(paths, "|");
    while (n_tok && p_tok && g_share_count < MAX_SHARES) {
        strcpy(g_shares[g_share_count].name, n_tok);
        strcpy(g_shares[g_share_count].path, p_tok);
        g_share_count++;
        n_tok = strtok(NULL, "|");
        p_tok = strtok(NULL, "|");
    }
    if (g_share_count == 0) {
        strcpy(g_shares[0].name, "public"); strcpy(g_shares[0].path, "C:\\"); g_share_count = 1;
    }
}

static void save_config() {
    char pStr[16]; snprintf(pStr, sizeof(pStr), "%d", g_port);
    WritePrivateProfileStringA("Config", "Port", pStr, g_ini_path);
    
    char names[1024] = {0}, paths[4096] = {0};
    for (int i = 0; i < g_share_count; i++) {
        if (i > 0) { strcat(names, "|"); strcat(paths, "|"); }
        strcat(names, g_shares[i].name);
        strcat(paths, g_shares[i].path);
    }
    WritePrivateProfileStringA("Config", "sharename", names, g_ini_path);
    WritePrivateProfileStringA("Config", "sharepath", paths, g_ini_path);
}

/* ==========================================================================
   UTILITY & LOGGING
   ========================================================================== */
static void normalize_local_path(char *path) {
    char temp[MAX_PATH];
    int t = 0;
    for (int k = 0; path[k]; k++) {
        char c = (path[k] == '/') ? '\\' : path[k];
        if (c == '\\' && t > 0 && temp[t-1] == '\\') {
            if (t == 1) { temp[t++] = c; } /* allow \\ at the very beginning for UNC paths */
            continue;
        }
        temp[t++] = c;
    }
    temp[t] = '\0';
    strcpy(path, temp);
}

static void server_log(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (strlen(g_log_buffer) + strlen(buf) + 4 >= sizeof(g_log_buffer)) {
        memmove(g_log_buffer, g_log_buffer + 2048, sizeof(g_log_buffer) - 2048);
        g_log_buffer[sizeof(g_log_buffer) - 1] = '\0';
    }
    strcat(g_log_buffer, buf);
    strcat(g_log_buffer, "\r\n");

    if (g_hLogEdit && IsWindow(g_hLogEdit)) {
        SendMessageA(g_hLogEdit, WM_SETTEXT, 0, (LPARAM)g_log_buffer);
        SendMessageA(g_hLogEdit, EM_LINESCROLL, 0, SendMessageA(g_hLogEdit, EM_GETLINECOUNT, 0, 0));
    }
}

static int send_packet(SOCKET sock, const uint8_t *data, size_t len) {
    uint8_t net_len[4];
    net_len[0] = 0x00;
    net_len[1] = (len >> 16) & 0xFF;
    net_len[2] = (len >> 8) & 0xFF;
    net_len[3] = len & 0xFF;
    if (send(sock, (char*)net_len, 4, 0) != 4) return 0;
    if (send(sock, (char*)data, (int)len, 0) != (int)len) return 0;
    return 1;
}

static void FreePidl(LPITEMIDLIST pidl) {
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (hOle32) {
        void (WINAPI *pCoTaskMemFree)(LPVOID) = (void*)GetProcAddress(hOle32, "CoTaskMemFree");
        if (pCoTaskMemFree) pCoTaskMemFree(pidl);
        FreeLibrary(hOle32);
    }
}

/* ==========================================================================
   SMB1 SERVER HANDLERS
   ========================================================================== */
static void handle_negotiate(SOCKET client, SMB1Header *req_hdr) {
    uint8_t resp[128]; memset(resp, 0, sizeof(resp));
    SMB1Header *hdr = (SMB1Header*)resp;
    memcpy(hdr, req_hdr, sizeof(SMB1Header));
    hdr->flags1 |= 0x80; hdr->status = 0;
    
    uint8_t *w = resp + sizeof(SMB1Header);
    *w++ = 17;                          
    *(uint16_t*)w = 5; w += 2;          
    *w++ = 0x03;                        
    *(uint16_t*)w = 50; w += 2;         
    *(uint16_t*)w = 1; w += 2;          
    *(uint32_t*)w = 65536; w += 4;      
    *(uint32_t*)w = 65536; w += 4;      
    *(uint32_t*)w = 1; w += 4;          
    *(uint32_t*)w = 0x00008004; w += 4; 
    *(uint64_t*)w = 0; w += 8;          
    *(uint16_t*)w = 0; w += 2;          
    *w++ = 8;                           
    
    uint16_t *bcc = (uint16_t*)w; w += 2;
    memset(w, 0, 8); w += 8;            
    strcpy((char*)w, "WORKGROUP"); w += 10;
    strcpy((char*)w, "SMB1SRV"); w += 8;
    
    *bcc = w - (uint8_t*)bcc - 2;
    send_packet(client, resp, w - resp);
    server_log("Handled: Negotiate Protocol");
}

static void handle_session_setup(SOCKET client, SMB1Header *req_hdr) {
    uint8_t resp[128]; memset(resp, 0, sizeof(resp));
    SMB1Header *hdr = (SMB1Header*)resp;
    memcpy(hdr, req_hdr, sizeof(SMB1Header));
    hdr->flags1 |= 0x80; hdr->uid = 100; 
    
    uint8_t *w = resp + sizeof(SMB1Header);
    *w++ = 3;                           
    *w++ = 0xFF; *w++ = 0;              
    *(uint16_t*)w = 0; w += 2;          
    *(uint16_t*)w = 1; w += 2;          
    *(uint16_t*)w = 0; w += 2;          
    
    send_packet(client, resp, w - resp);
}

static void handle_tree_connect(SOCKET client, SMB1Header *req_hdr, TidMap *maps, int *map_count) {
    uint8_t resp[128]; memset(resp, 0, sizeof(resp));
    SMB1Header *hdr = (SMB1Header*)resp;
    memcpy(hdr, req_hdr, sizeof(SMB1Header));
    hdr->flags1 |= 0x80; 
    
    uint16_t new_tid = (*map_count) + 1;
    hdr->tid = new_tid; 
    
    uint8_t *w = (uint8_t*)req_hdr + sizeof(SMB1Header);
    uint8_t wct = *w;
    uint16_t *vwv = (uint16_t*)(w + 1);
    uint8_t *data = w + 1 + wct*2 + 2;
    
    uint16_t pass_len = vwv[3];
    uint8_t *path_ptr = data + pass_len;
    
    char requested[MAX_PATH] = {0};
    if (req_hdr->flags2 & 0x8000) {
        if ((path_ptr - (uint8_t*)req_hdr) % 2 != 0) path_ptr++;
        uint16_t *u = (uint16_t*)path_ptr;
        for (int i = 0; u[i] && i < MAX_PATH - 1; i++) requested[i] = (char)u[i];
    } else {
        strcpy(requested, (char*)path_ptr);
    }
    
    char *share_name = strrchr(requested, '\\');
    if (share_name) share_name++; else share_name = requested;
    
    char mapped_path[MAX_PATH] = "C:\\"; 
    for (int i = 0; i < g_share_count; i++) {
        if (_stricmp(g_shares[i].name, share_name) == 0) {
            strcpy(mapped_path, g_shares[i].path);
            break;
        }
    }
    
    if (*map_count < 32) {
        maps[*map_count].tid = new_tid;
        strcpy(maps[*map_count].path, mapped_path);
        (*map_count)++;
    }
    
    server_log("Tree Connect: \\%s -> %s (TID %d)", share_name, mapped_path, new_tid);
    
    w = resp + sizeof(SMB1Header);
    *w++ = 3; 
    *w++ = 0xFF; *w++ = 0; 
    *(uint16_t*)w = 0; w += 2;          
    *(uint16_t*)w = 0x01; w += 2;       
    *(uint16_t*)w = 0; w += 2;          
    
    send_packet(client, resp, w - resp);
}

static void handle_trans(SOCKET client, SMB1Header *req_hdr, uint8_t *req, size_t req_len) {
    uint8_t wct = req[sizeof(SMB1Header)];
    if (wct < 14) return;
    uint16_t *vwv = (uint16_t*)(req + sizeof(SMB1Header) + 1);
    
    uint16_t param_off = vwv[10];
    uint16_t param_cnt = vwv[9];
    
    if (param_off + param_cnt > req_len || param_cnt < 2) return;
    uint8_t *params = req + param_off;
    uint16_t opcode = *(uint16_t*)params;
    
    if (opcode == 0x0000) { /* NetShareEnum over RAP */
        uint8_t resp[4096]; memset(resp, 0, sizeof(resp));
        SMB1Header *hdr = (SMB1Header*)resp;
        memcpy(hdr, req_hdr, sizeof(SMB1Header));
        hdr->flags1 |= 0x80;
        
        uint8_t *w = resp + sizeof(SMB1Header);
        *w++ = 10; 
        uint16_t *resp_vwv = (uint16_t*)w; w += 20;
        uint16_t *bcc_ptr = (uint16_t*)w; w += 2;
        uint8_t *data_start = w;
        *w++ = 0; 
        
        uint8_t *out_params = w; w += 8;
        *(uint16_t*)(out_params + 0) = 0; 
        *(uint16_t*)(out_params + 2) = 0; 
        *(uint16_t*)(out_params + 4) = g_share_count; 
        *(uint16_t*)(out_params + 6) = g_share_count; 
        
        int pad = (4 - ((w - resp) % 4)) % 4; w += pad;
        uint8_t *out_data = w;
        
        for (int i = 0; i < g_share_count; i++) {
            memset(w, 0, 20);
            strncpy((char*)w, g_shares[i].name, 13);
            *(uint16_t*)(w + 14) = 0; 
            *(uint32_t*)(w + 16) = 0; 
            w += 20;
        }
        
        uint16_t p_len = 8;
        uint16_t d_len = w - out_data;
        
        resp_vwv[0] = p_len; resp_vwv[1] = d_len; resp_vwv[2] = 0;
        resp_vwv[3] = p_len; resp_vwv[4] = out_params - resp; resp_vwv[5] = 0;
        resp_vwv[6] = d_len; resp_vwv[7] = out_data - resp;   resp_vwv[8] = 0;
        resp_vwv[9] = 0;
        
        *bcc_ptr = w - data_start;
        send_packet(client, resp, w - resp);
        server_log("Handled: NetShareEnum (Returned %d shares)", g_share_count);
    }
}

static void handle_trans2(SOCKET client, SMB1Header *req_hdr, uint8_t *req, size_t req_len, TidMap *maps, int map_count) {
    uint8_t wct = req[sizeof(SMB1Header)];
    if (wct < 14) return;
    
    uint16_t *vwv = (uint16_t*)(req + sizeof(SMB1Header) + 1);
    uint8_t setup_count = vwv[13] & 0xFF;
    if (setup_count == 0) return;
    
    uint16_t subcmd = vwv[14];
    
    if (subcmd == 0x0001) {
        uint16_t param_off = vwv[10];
        if (param_off + 12 > req_len) return;
        uint8_t *params = req + param_off;
        
        char search_pattern[MAX_PATH] = {0};
        
        if (req_hdr->flags2 & 0x8000) {
            uint16_t *uname = (uint16_t*)(params + 12);
            int i = 0;
            while (uname[i] && i < MAX_PATH - 1) { search_pattern[i] = (char)uname[i]; i++; }
        } else {
            strcpy(search_pattern, (char*)(params + 12));
        }
        
        char mapped_path[MAX_PATH] = "C:\\";
        for (int i = 0; i < map_count; i++) {
            if (maps[i].tid == req_hdr->tid) { strcpy(mapped_path, maps[i].path); break; }
        }
        
        char local_search[MAX_PATH];
        if (mapped_path[strlen(mapped_path)-1] == '\\' && search_pattern[0] == '\\') {
            snprintf(local_search, sizeof(local_search), "%s%s", mapped_path, search_pattern + 1);
        } else {
            snprintf(local_search, sizeof(local_search), "%s\\%s", mapped_path, search_pattern);
        }
        normalize_local_path(local_search);
        
        server_log("Handled: Directory List -> %s", local_search);
        
        uint8_t *resp = malloc(65536);
        memset(resp, 0, 65536);
        SMB1Header *hdr = (SMB1Header*)resp;
        memcpy(hdr, req_hdr, sizeof(SMB1Header));
        hdr->flags1 |= 0x80;
        
        uint8_t *w = resp + sizeof(SMB1Header);
        *w++ = 10; 
        uint16_t *resp_vwv = (uint16_t*)w; w += 20;
        uint16_t *bcc_ptr = (uint16_t*)w; w += 2;
        uint8_t *data_start = w;
        
        *w++ = 0; 
        uint8_t *param_ptr = w; w += 10;
        int pad = (4 - ((w - resp) % 4)) % 4; w += pad;
        uint8_t *entries_start = w;
        
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(local_search, &fd);
        int count = 0;
        uint8_t *last_entry = NULL;
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (w + 512 > resp + 65536) break;
                
                last_entry = w;
                uint32_t *next_off = (uint32_t*)w; w += 4;
                *(uint32_t*)w = 0; w += 4; 
                
                *(uint64_t*)w = ((uint64_t)fd.ftCreationTime.dwHighDateTime << 32) | fd.ftCreationTime.dwLowDateTime; w += 8;
                *(uint64_t*)w = ((uint64_t)fd.ftLastAccessTime.dwHighDateTime << 32) | fd.ftLastAccessTime.dwLowDateTime; w += 8;
                *(uint64_t*)w = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime; w += 8;
                *(uint64_t*)w = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime; w += 8;
                
                uint64_t fsize = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                *(uint64_t*)w = fsize; w += 8; 
                *(uint64_t*)w = fsize; w += 8; 
                *(uint32_t*)w = fd.dwFileAttributes; w += 4;
                
                uint32_t *name_len_ptr = (uint32_t*)w; w += 4;
                *(uint32_t*)w = 0; w += 4; 
                *w++ = 0; *w++ = 0;        
                memset(w, 0, 24); w += 24; 
                
                uint16_t *uname = (uint16_t*)w;
                int i = 0;
                while (fd.cFileName[i]) { uname[i] = (uint16_t)fd.cFileName[i]; i++; }
                *name_len_ptr = i * 2;
                w += i * 2;
                
                int epad = (4 - ((w - last_entry) % 4)) % 4; w += epad;
                *next_off = w - last_entry; 
                
                count++;
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
        
        if (last_entry) *(uint32_t*)last_entry = 0; 
        
        *(uint16_t*)(param_ptr + 0) = 1234;  
        *(uint16_t*)(param_ptr + 2) = count; 
        *(uint16_t*)(param_ptr + 4) = 1;     
        *(uint16_t*)(param_ptr + 6) = 0;     
        *(uint16_t*)(param_ptr + 8) = 0;     
        
        uint16_t param_len = 10;
        uint16_t data_len = w - entries_start;
        
        resp_vwv[0] = param_len; resp_vwv[1] = data_len; resp_vwv[2] = 0;
        resp_vwv[3] = param_len; resp_vwv[4] = param_ptr - resp; resp_vwv[5] = 0;
        resp_vwv[6] = data_len;  resp_vwv[7] = entries_start - resp; resp_vwv[8] = 0;
        resp_vwv[9] = 0; 
        
        *bcc_ptr = w - data_start;
        send_packet(client, resp, w - resp);
        free(resp);
    }
}

static DWORD WINAPI ClientThread(LPVOID param) {
    SOCKET client = (SOCKET)param;
    uint8_t header[4];
    TidMap maps[32];
    int map_count = 0;
    
    while (g_server_running) {
        int r = recv(client, (char*)header, 4, 0);
        if (r <= 0) break;

        size_t len = ((size_t)(header[1] & 0x01) << 16) | ((size_t)header[2] << 8) | header[3];
        if (header[0] == 0x85 || len == 0) continue; 
        
        uint8_t *payload = malloc(len);
        size_t received = 0;
        while (received < len) {
            r = recv(client, (char*)(payload + received), (int)(len - received), 0);
            if (r <= 0) break;
            received += r;
        }
        
        if (received == len && len >= sizeof(SMB1Header)) {
            SMB1Header *smb = (SMB1Header*)payload;
            if (memcmp(smb->protocol_id, "\xFFSMB", 4) == 0) {
                switch(smb->cmd) {
                    case 0x72: handle_negotiate(client, smb); break;
                    case 0x73: handle_session_setup(client, smb); break;
                    case 0x75: handle_tree_connect(client, smb, maps, &map_count); break;
                    case 0x25: handle_trans(client, smb, payload, len); break;
                    case 0x32: handle_trans2(client, smb, payload, len, maps, map_count); break;
                    default: {
                        uint8_t resp[128]; memset(resp, 0, sizeof(resp));
                        resp[0] = 0x00; resp[1] = 0; resp[2] = 0; resp[3] = sizeof(SMB1Header) + 3;
                        SMB1Header *hdr = (SMB1Header*)(resp + 4);
                        memcpy(hdr, smb, sizeof(SMB1Header));
                        hdr->flags1 |= 0x80; hdr->status = 0;
                        resp[4 + sizeof(SMB1Header)] = 0; 
                        *(uint16_t*)(resp + 4 + sizeof(SMB1Header) + 1) = 0; 
                        send(client, (char*)resp, 4 + sizeof(SMB1Header) + 3, 0);
                        break;
                    }
                }
            }
        }
        free(payload);
    }
    closesocket(client);
    server_log("Client disconnected.");
    return 0;
}

/* ==========================================================================
   SERVER INITIALIZATION & TRAY UI
   ========================================================================== */
static DWORD WINAPI ServerThread(LPVOID param) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    g_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(g_port);

    if (bind(g_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        server_log("Failed to bind to port %d. Error: %d", g_port, WSAGetLastError());
        g_server_running = 0;
        if (g_hSettings) InvalidateRect(g_hSettings, NULL, TRUE);
        return 1;
    }

    listen(g_listen_socket, SOMAXCONN);
    server_log("SMB1 Server listening on port %d...", g_port);

    while (g_server_running) {
        struct sockaddr_in client_addr; int addr_len = sizeof(client_addr);
        SOCKET client = accept(g_listen_socket, (struct sockaddr*)&client_addr, &addr_len);
        if (client == INVALID_SOCKET) break;

        server_log("Client connected from %s", inet_ntoa(client_addr.sin_addr));
        CreateThread(NULL, 0, ClientThread, (LPVOID)client, 0, NULL);
    }

    server_log("Server stopped.");
    if (g_listen_socket != INVALID_SOCKET) { closesocket(g_listen_socket); g_listen_socket = INVALID_SOCKET; }
    WSACleanup(); return 0;
}

static void ToggleServer() {
    if (g_server_running) {
        g_server_running = 0;
        if (g_listen_socket != INVALID_SOCKET) { closesocket(g_listen_socket); g_listen_socket = INVALID_SOCKET; }
        if (g_server_thread) { WaitForSingleObject(g_server_thread, 1000); CloseHandle(g_server_thread); g_server_thread = NULL; }
    } else {
        g_server_running = 1; g_server_thread = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    }
    if (g_hSettings && IsWindow(g_hSettings)) InvalidateRect(g_hSettings, NULL, TRUE);
}

BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    SendMessage(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE); return TRUE;
}

static void RefreshShareCombo(HWND hCmb) {
    SendMessageA(hCmb, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_share_count; i++) SendMessageA(hCmb, CB_ADDSTRING, 0, (LPARAM)g_shares[i].name);
    if (g_share_count > 0) SendMessageA(hCmb, CB_SETCURSEL, 0, 0);
}

static LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hPort, hIPs, hToggle, hBtnBrowse, hBtnDel;
    switch (msg) {
        case WM_CREATE: {
            int y = 10;
            CreateWindowA("STATIC", "Port Number:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_NUMBER, 110, y, 100, 20, hwnd, (HMENU)IDE_PORT, g_hInst, NULL);
            char pStr[16]; snprintf(pStr, sizeof(pStr), "%d", g_port); SetWindowTextA(hPort, pStr); y += 30;

            CreateWindowA("STATIC", "Shares:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            g_hCmbShares = CreateWindowExA(WS_EX_CLIENTEDGE, "COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWN, 110, y, 120, 100, hwnd, (HMENU)IDC_CMB_SHARES, g_hInst, NULL);
            g_hSharePath = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 235, y, 150, 20, hwnd, (HMENU)IDE_SHAREPATH, g_hInst, NULL);
            hBtnBrowse = CreateWindowA("BUTTON", "...", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 390, y, 30, 20, hwnd, (HMENU)IDB_BROWSE, g_hInst, NULL);
            hBtnDel = CreateWindowA("BUTTON", "-", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 425, y, 20, 20, hwnd, (HMENU)IDB_DEL_SHARE, g_hInst, NULL);
            
            RefreshShareCombo(g_hCmbShares);
            if (g_share_count > 0) SetWindowTextA(g_hSharePath, g_shares[0].path);
            y += 30;

            CreateWindowA("STATIC", "Bound IP Addresses:", WS_CHILD|WS_VISIBLE, 10, y, 150, 20, hwnd, NULL, g_hInst, NULL); y += 20;
            hIPs = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "", WS_CHILD|WS_VISIBLE|WS_VSCROLL, 10, y, 485, 60, hwnd, (HMENU)IDL_IPS, g_hInst, NULL); y += 70;

            char host[256]; WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
            if (gethostname(host, sizeof(host)) == 0) {
                struct hostent *he = gethostbyname(host);
                if (he) { for (int i = 0; he->h_addr_list[i]; i++) SendMessageA(hIPs, LB_ADDSTRING, 0, (LPARAM)inet_ntoa(*(struct in_addr*)he->h_addr_list[i])); }
            }

            CreateWindowA("STATIC", "Connection Log:", WS_CHILD|WS_VISIBLE, 10, y, 150, 20, hwnd, NULL, g_hInst, NULL); y += 20;
            g_hLogEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_log_buffer, WS_CHILD|WS_VISIBLE|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY, 10, y, 485, 120, hwnd, (HMENU)IDE_LOG, g_hInst, NULL); y += 130;
            SendMessageA(g_hLogEdit, EM_LINESCROLL, 0, SendMessageA(g_hLogEdit, EM_GETLINECOUNT, 0, 0));

            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 10, y, 80, 30, hwnd, (HMENU)IDB_OK, g_hInst, NULL);
            hToggle = CreateWindowA("BUTTON", "Start/Stop", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW, 100, y, 180, 30, hwnd, (HMENU)IDB_TOGGLE_SRV, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 415, y, 80, 30, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);

            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas"); EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF);
            return 0;
        }
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lp;
            if (dis->CtlID == IDB_TOGGLE_SRV) {
                HBRUSH hbr = CreateSolidBrush(g_server_running ? RGB(34, 177, 76) : RGB(220, 53, 69));
                FillRect(dis->hDC, &dis->rcItem, hbr); DeleteObject(hbr); SetBkMode(dis->hDC, TRANSPARENT); SetTextColor(dis->hDC, RGB(255, 255, 255));
                const char *btnText = g_server_running ? "Running - Click to Stop" : "Stopped - Click to Start";
                DrawTextA(dis->hDC, btnText, -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE); return TRUE;
            } break;
        }
        case WM_TIMER: {
            if (wp == TIMER_SAVE_SHARE) {
                KillTimer(hwnd, TIMER_SAVE_SHARE);
                char name[64], path[MAX_PATH];
                GetWindowTextA(g_hCmbShares, name, sizeof(name));
                GetWindowTextA(g_hSharePath, path, sizeof(path));
                
                if (name[0] && path[0]) {
                    char orig_path[MAX_PATH];
                    strcpy(orig_path, path);
                    normalize_local_path(path);
                    
                    if (strcmp(orig_path, path) != 0) {
                        DWORD sel = SendMessageA(g_hSharePath, EM_GETSEL, 0, 0);
                        SetWindowTextA(g_hSharePath, path);
                        SendMessageA(g_hSharePath, EM_SETSEL, LOWORD(sel), HIWORD(sel));
                    }
                    
                    int found = -1;
                    for (int i = 0; i < g_share_count; i++) {
                        if (_stricmp(g_shares[i].name, name) == 0) { found = i; break; }
                    }
                    
                    int added_new = 0;
                    if (found != -1) {
                        if (strcmp(g_shares[found].path, path) != 0) {
                            strcpy(g_shares[found].path, path);
                        }
                    } else if (g_share_count < MAX_SHARES) {
                        strcpy(g_shares[g_share_count].name, name);
                        strcpy(g_shares[g_share_count].path, path);
                        g_share_count++;
                        added_new = 1;
                    }
                    
                    if (added_new) SendMessageA(g_hCmbShares, CB_ADDSTRING, 0, (LPARAM)name);
                    save_config();
                }
            }
            return 0;
        }
        case DM_GETDEFID: return MAKELRESULT(IDB_OK, DC_HASDEFID);
        case WM_COMMAND: {
            int id = LOWORD(wp);
            int code = HIWORD(wp);
            
            if (id == IDC_CMB_SHARES && code == CBN_EDITCHANGE) {
                SetTimer(hwnd, TIMER_SAVE_SHARE, 1000, NULL);
            } else if (id == IDE_SHAREPATH && code == EN_CHANGE) {
                SetTimer(hwnd, TIMER_SAVE_SHARE, 1000, NULL);
            } else if (id == IDC_CMB_SHARES && code == CBN_SELCHANGE) {
                int idx = SendMessageA(g_hCmbShares, CB_GETCURSEL, 0, 0);
                if (idx >= 0 && idx < g_share_count) {
                    SetWindowTextA(g_hSharePath, g_shares[idx].path);
                }
            } else if (id == IDE_PORT && code == EN_CHANGE) {
                char pStr[16]; GetWindowTextA(hPort, pStr, sizeof(pStr)); 
                int new_port = atoi(pStr);
                if (new_port > 0 && new_port != g_port) {
                    g_port = new_port;
                    if (g_server_running) { ToggleServer(); ToggleServer(); }
                    save_config();
                }
            } else if (id == IDB_DEL_SHARE) {
                char name[64];
                GetWindowTextA(g_hCmbShares, name, sizeof(name));
                int found = -1;
                for (int i = 0; i < g_share_count; i++) {
                    if (_stricmp(g_shares[i].name, name) == 0) { found = i; break; }
                }
                if (found != -1 && g_share_count > 1) {
                    for (int i = found; i < g_share_count - 1; i++) g_shares[i] = g_shares[i+1];
                    g_share_count--;
                    RefreshShareCombo(g_hCmbShares);
                    SetWindowTextA(g_hSharePath, g_shares[0].path);
                    save_config();
                }
            } else if (id == IDB_BROWSE) {
                BROWSEINFOA bi = { 0 };
                bi.hwndOwner = hwnd;
                bi.lpszTitle = "Select a local folder to share:";
                bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
                LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
                if (pidl != 0) {
                    char path[MAX_PATH];
                    if (SHGetPathFromIDListA(pidl, path)) {
                        SetWindowTextA(g_hSharePath, path);
                        SetTimer(hwnd, TIMER_SAVE_SHARE, 100, NULL);
                    }
                    FreePidl(pidl);
                }
            } else if (id == IDB_TOGGLE_SRV) {
                char pStr[16]; GetWindowTextA(hPort, pStr, sizeof(pStr)); int new_port = atoi(pStr);
                if (new_port > 0 && new_port != g_port) { g_port = new_port; save_config(); }
                ToggleServer();
            } else if (id == IDB_OK || id == IDOK) {
                char pStr[16]; GetWindowTextA(hPort, pStr, sizeof(pStr)); int new_port = atoi(pStr);
                if (new_port > 0 && new_port != g_port) {
                    g_port = new_port;
                    if (g_server_running) { ToggleServer(); ToggleServer(); }
                }
                save_config();
                ShowWindow(hwnd, SW_HIDE);
            } else if (id == IDB_CANCEL || id == IDCANCEL) {
                ShowWindow(hwnd, SW_HIDE);
            }
            break;
        }
        case WM_CLOSE: ShowWindow(hwnd, SW_HIDE); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void ShowContextMenu(HWND hwnd) {
    POINT pt; GetCursorPos(&pt); HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING | (g_server_running ? MF_CHECKED : MF_UNCHECKED), ID_TRAY_TOGGLE, "Start/Stop Server");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_SETTINGS, "Server Settings...");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL); AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit");
    SetForegroundWindow(hwnd); TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL); DestroyMenu(hMenu);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            load_config();
            memset(&g_nid, 0, sizeof(g_nid)); g_nid.cbSize = sizeof(NOTIFYICONDATA); g_nid.hWnd = hwnd; g_nid.uID = 1;
            g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; g_nid.uCallbackMessage = WM_TRAYICON; g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
            strcpy(g_nid.szTip, "SMB1 Server Stub"); Shell_NotifyIcon(NIM_ADD, &g_nid);
            ToggleServer(); return 0;
        case WM_TRAYICON: if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP) ShowContextMenu(hwnd); return 0;
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_TRAY_TOGGLE: ToggleServer(); break;
                case ID_TRAY_SETTINGS:
                    if (!g_hSettings) {
                        WNDCLASSEXA wcx = {sizeof(WNDCLASSEXA), 0, SettingsWndProc, 0, 0, g_hInst, NULL, LoadCursor(NULL, IDC_ARROW), (HBRUSH)(COLOR_WINDOW+1), NULL, "SettingsClass", NULL};
                        RegisterClassExA(&wcx);
                        g_hSettings = CreateWindowExA(WS_EX_CONTROLPARENT, "SettingsClass", "SMB1 Server Settings", WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME, CW_USEDEFAULT, CW_USEDEFAULT, 520, 380, NULL, NULL, g_hInst, NULL);
                    }
                    ShowWindow(g_hSettings, SW_SHOW); SetForegroundWindow(g_hSettings); break;
                case ID_TRAY_EXIT: SendMessage(hwnd, WM_CLOSE, 0, 0); break;
            } return 0;
        case WM_DESTROY: if (g_server_running) ToggleServer(); Shell_NotifyIcon(NIM_DELETE, &g_nid); PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInst;
    WNDCLASSEXA wc = {sizeof(WNDCLASSEXA), 0, MainWndProc, 0, 0, hInst, NULL, NULL, NULL, NULL, "HiddenMainClass", NULL};
    RegisterClassExA(&wc);
    g_hMain = CreateWindowExA(0, "HiddenMainClass", "SMB1 Tray Server", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        HWND hActive = GetActiveWindow(); if (hActive && IsDialogMessage(hActive, &msg)) continue;
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}