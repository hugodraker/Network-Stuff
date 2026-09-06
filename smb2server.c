/*
 * Standalone SMB2 Server & Tray App (With Configurable Shares)
 * 
 * COMPILATION:
 *   gcc -Os -s -o smb2server.exe smb2server.c -lws2_32 -luser32 -lgdi32 -ladvapi32 -lshell32 -lcomctl32 -mwindows
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

/* SMB2 Constants */
#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_READ            0x0008
#define SMB2_QUERY_DIRECTORY 0x000E

#ifndef SMB2_WRITE
#define SMB2_WRITE 0x0009
#endif

/*
 * Standalone SMB2 Server & Tray App (With Directory Listing)
 * 
 * COMPILATION:
 *   gcc -Os -s -o smb2server.exe smb2server.c -lws2_32 -luser32 -lgdi32 -ladvapi32 -lshell32 -lcomctl32 -mwindows
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

typedef struct {
    uint8_t  protocol_id[4];
    uint16_t structure_size;
    uint16_t credit_charge;
    uint32_t status;
    uint16_t command;
    uint16_t credit_request;
    uint32_t flags;
    uint32_t next_command;
    uint64_t message_id;
    uint32_t process_id;
    uint32_t tree_id;
    uint64_t session_id;
    uint8_t  signature[16];
} SMB2Header;
#pragma pack(pop)

#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_READ            0x0008
#define SMB2_QUERY_DIRECTORY 0x000E

typedef struct {
    char name[64];
    char path[MAX_PATH];
} ServerShare;

typedef struct {
    uint32_t tid;
    char path[MAX_PATH];
} TidMap;

typedef struct {
    uint64_t fid;
    char path[MAX_PATH];
    int dcerpc_state;
    uint32_t dcerpc_call_id;
    uint16_t dcerpc_ctx_id;
} HandleMap;

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
   FORWARD DECLARATIONS & UTILITY LOGGING (Must precede handlers)
   ========================================================================== */
static void server_log(const char *fmt, ...);
static void normalize_local_path(char *path);
static int send_packet(SOCKET sock, const uint8_t *data, size_t len);
static void build_smb2_resp_header(SMB2Header *resp, SMB2Header *req, uint16_t cmd, uint32_t status);

/* ==========================================================================
   CONFIG LOAD/SAVE
   ========================================================================== */
static uint32_t handle_smb2_write(SMB2Header *req, uint8_t *resp_buf, HandleMap *handles, int handle_count) {
    uint8_t *req_data = (uint8_t*)req;
    uint16_t data_off = *(uint16_t*)(req_data + 64 + 2);
    uint32_t data_len = *(uint32_t*)(req_data + 64 + 4);
    uint64_t fid = *(uint64_t*)(req_data + 64 + 16);
    
    for(int i = 0; i < handle_count; i++) {
        if(handles[i].fid == fid && _stricmp(handles[i].path, "\\srvsvc") == 0) {
            if (data_off >= 64 && data_off + data_len <= 65536) {
                uint8_t *payload = req_data + data_off;
                if (data_len >= 16 && payload[0] == 0x05) { 
                    uint8_t ptype = payload[2]; uint32_t call_id = *(uint32_t*)(payload + 12); handles[i].dcerpc_call_id = call_id;
                    if (ptype == 0x0B) { handles[i].dcerpc_state = 1; } 
                    else if (ptype == 0x00 && data_len >= 24) { handles[i].dcerpc_ctx_id = *(uint16_t*)(payload + 20); uint16_t opnum = *(uint16_t*)(payload + 22); if (opnum == 15) handles[i].dcerpc_state = 2; else handles[i].dcerpc_state = 3; }
                }
            }
            break;
        }
    }
    
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, SMB2_WRITE, 0);
    uint8_t *w = resp_buf + 64; *(uint16_t*)w = 17; w += 2; *w++ = 0; *w++ = 0; *(uint32_t*)w = data_len; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4;
    return (uint32_t)(w - resp_buf);
}
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
    char temp[MAX_PATH]; int t = 0;
    for (int k = 0; path[k]; k++) {
        char c = (path[k] == '/') ? '\\' : path[k];
        if (c == '\\' && t > 0 && temp[t-1] == '\\') { if (t == 1) temp[t++] = c; continue; }
        temp[t++] = c;
    }
    temp[t] = '\0'; strcpy(path, temp);
}

static void server_log(const char *fmt, ...) {
    char buf[512]; va_list args;
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    if (strlen(g_log_buffer) + strlen(buf) + 4 >= sizeof(g_log_buffer)) {
        memmove(g_log_buffer, g_log_buffer + 2048, sizeof(g_log_buffer) - 2048);
        g_log_buffer[sizeof(g_log_buffer) - 1] = '\0';
    }
    strcat(g_log_buffer, buf); strcat(g_log_buffer, "\r\n");
    if (g_hLogEdit && IsWindow(g_hLogEdit)) {
        SendMessageA(g_hLogEdit, WM_SETTEXT, 0, (LPARAM)g_log_buffer);
        SendMessageA(g_hLogEdit, EM_LINESCROLL, 0, SendMessageA(g_hLogEdit, EM_GETLINECOUNT, 0, 0));
    }
}

static int send_packet(SOCKET sock, const uint8_t *data, size_t len) {
    uint8_t net_len[4] = {0, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF};
    if (send(sock, (char*)net_len, 4, 0) != 4) return 0;
    if (send(sock, (char*)data, (int)len, 0) != (int)len) return 0;
    return 1;
}

static void build_smb2_resp_header(SMB2Header *resp, SMB2Header *req, uint16_t cmd, uint32_t status) {
    memcpy(resp->protocol_id, "\xFE\x53\x4D\x42", 4);
    resp->structure_size = 64; resp->credit_charge = req->credit_charge;
    resp->status = status; resp->command = cmd;
    resp->credit_request = 1; resp->flags = 0x00000001; /* SERVER_TO_CLIENT */
    resp->next_command = 0; resp->message_id = req->message_id;
    resp->process_id = req->process_id; resp->tree_id = req->tree_id;
    resp->session_id = req->session_id; memset(resp->signature, 0, 16);
}

/* ==========================================================================
   SMB2 SERVER HANDLERS
   ========================================================================== */
static uint32_t handle_smb1_upgrade(uint8_t *resp_buf) {
    SMB2Header *hdr = (SMB2Header*)resp_buf;
    memcpy(hdr->protocol_id, "\xFE\x53\x4D\x42", 4);
    hdr->structure_size = 64; hdr->status = 0; hdr->command = SMB2_NEGOTIATE;
    hdr->credit_request = 1; hdr->flags = 1;
    
    uint8_t *w = resp_buf + 64;
    *(uint16_t*)w = 65; w += 2; *(uint16_t*)w = 1; w += 2; *(uint16_t*)w = 0x0210; w += 2; *(uint16_t*)w = 0; w += 2; 
    memset(w, 0xAA, 16); w += 16; 
    *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 1048576; w += 4; *(uint32_t*)w = 1048576; w += 4; *(uint32_t*)w = 1048576; w += 4; 
    *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; 
    *(uint16_t*)w = 128; w += 2; *(uint16_t*)w = 0; w += 2; *(uint32_t*)w = 0; w += 4; 
    server_log("Handled: SMB1-to-SMB2 Negotiate Upgrade");
    return (uint32_t)(w - resp_buf);
}

static uint32_t handle_smb2_negotiate(SMB2Header *req, uint8_t *resp_buf) {
    SMB2Header *hdr = (SMB2Header*)resp_buf;
    build_smb2_resp_header(hdr, req, SMB2_NEGOTIATE, 0);
    
    uint8_t spnego_neg[] = {
        0x60, 0x28, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x1e, 
        0x30, 0x1c, 0xa0, 0x1a, 0x30, 0x18, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 
        0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 
        0x01, 0x82, 0x37, 0x02, 0x02, 0x0e
    };

    uint8_t *w = resp_buf + 64;
    *(uint16_t*)w = 65; w += 2; *(uint16_t*)w = 1; w += 2; *(uint16_t*)w = 0x0210; w += 2; *(uint16_t*)w = 0; w += 2; 
    memset(w, 0xAA, 16); w += 16; 
    *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 1048576; w += 4; *(uint32_t*)w = 1048576; w += 4; *(uint32_t*)w = 1048576; w += 4; 
    *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; 
    *(uint16_t*)w = 128; w += 2; *(uint16_t*)w = sizeof(spnego_neg); w += 2; *(uint32_t*)w = 0; w += 4; 
    memcpy(w, spnego_neg, sizeof(spnego_neg)); w += sizeof(spnego_neg);
    server_log("Handled: SMB2 Negotiate Protocol");
    return (uint32_t)(w - resp_buf);
}

static uint32_t handle_smb2_session_setup(SMB2Header *req, uint8_t *resp_buf) {
    SMB2Header *hdr = (SMB2Header*)resp_buf;
    if (req->session_id == 0) {
        build_smb2_resp_header(hdr, req, SMB2_SESSION_SETUP, 0xC0000016); /* STATUS_MORE_PROCESSING_REQUIRED */
        hdr->session_id = 100;
        
        /* Valid SPNEGO Encapsulated NTLMSSP Challenge */
        uint8_t spnego_challenge[] = {
            0xa1, 0x49, 0x30, 0x47, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x0c, 0x06, 0x0a, 
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x32, 0x04, 0x30, 
            'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0', 
            0x02, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 
            0x01, 0x82, 0x00, 0x00, 
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00
        };
        
        uint8_t *w = resp_buf + 64;
        *(uint16_t*)w = 9; w += 2; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 72; w += 2; *(uint16_t*)w = sizeof(spnego_challenge); w += 2;
        memcpy(w, spnego_challenge, sizeof(spnego_challenge)); w += sizeof(spnego_challenge);
        server_log("Handled: SMB2 Session Setup (Challenge Sent)");
        return (uint32_t)(w - resp_buf);
    } else {
        build_smb2_resp_header(hdr, req, SMB2_SESSION_SETUP, 0);
        hdr->session_id = req->session_id;
        
        /* SPNEGO Accept-Completed */
        uint8_t spnego_accept[] = { 0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00 };
        uint8_t *w = resp_buf + 64;
        *(uint16_t*)w = 9; w += 2; *(uint16_t*)w = 1; w += 2; /* IS_GUEST Flag */ 
        *(uint16_t*)w = 72; w += 2; *(uint16_t*)w = sizeof(spnego_accept); w += 2;
        memcpy(w, spnego_accept, sizeof(spnego_accept)); w += sizeof(spnego_accept);
        server_log("Handled: SMB2 Session Setup (Guest Accept)");
        return (uint32_t)(w - resp_buf);
    }
}

static uint32_t handle_smb2_tree_connect(SMB2Header *req, uint8_t *resp_buf, TidMap *maps, int *map_count) {
    uint8_t *req_data = (uint8_t*)req;
    uint16_t path_off = *(uint16_t*)(req_data + 64 + 4);
    uint16_t path_len = *(uint16_t*)(req_data + 64 + 6);
    char requested[MAX_PATH] = {0};
    if (path_off >= 64 && path_off + path_len <= 65536) {
        uint16_t *uname = (uint16_t*)(req_data + path_off);
        int i = 0; while (i < path_len/2 && i < MAX_PATH - 1) { requested[i] = (char)uname[i]; i++; }
    }
    
    char *share_name = strrchr(requested, '\\');
    if (share_name) share_name++; else share_name = requested;
    char mapped_path[MAX_PATH] = "C:\\"; 
    int is_ipc = (_stricmp(share_name, "IPC$") == 0);
    
    if (is_ipc) strcpy(mapped_path, "\\IPC$");
    else { for (int i = 0; i < g_share_count; i++) { if (_stricmp(g_shares[i].name, share_name) == 0) { strcpy(mapped_path, g_shares[i].path); break; } } }
    
    uint32_t new_tid = (*map_count) + 1;
    if (*map_count < 32) { maps[*map_count].tid = new_tid; strcpy(maps[*map_count].path, mapped_path); (*map_count)++; }
    server_log("SMB2 Tree Connect: \\%s -> %s (TID %d)", share_name, mapped_path, new_tid);
    
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, SMB2_TREE_CONNECT, 0); hdr->tree_id = new_tid;
    uint8_t *w = resp_buf + 64;
    *(uint16_t*)w = 16; w += 2; *w++ = is_ipc ? 2 : 1; /* 2=PIPE, 1=DISK */ *w++ = 0; 
    *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0x001F01FF; w += 4;
    return (uint32_t)(w - resp_buf);
}

static uint32_t handle_smb2_create(SMB2Header *req, uint8_t *resp_buf, TidMap *maps, int map_count, HandleMap *handles, int *handle_count) {
    uint8_t *req_data = (uint8_t*)req;
    uint16_t name_off = *(uint16_t*)(req_data + 64 + 44);
    uint16_t name_len = *(uint16_t*)(req_data + 64 + 46);
    char file_path[MAX_PATH] = {0};
    if (name_off >= 64 && name_off + name_len <= 65536) {
        uint16_t *uname = (uint16_t*)(req_data + name_off); int i = 0; while (i < name_len/2 && i < MAX_PATH - 1) { file_path[i] = (char)uname[i]; i++; }
    }
    const char *clean_file_path = file_path; if (clean_file_path[0] == '\\') clean_file_path++;
    
    uint64_t new_fid = (*handle_count) + 1; uint32_t file_attr = 0x80;
    if (_stricmp(clean_file_path, "srvsvc") == 0) {
        if (*handle_count < 256) { handles[*handle_count].fid = new_fid; strcpy(handles[*handle_count].path, "\\srvsvc"); handles[*handle_count].dcerpc_state = 0; (*handle_count)++; }
    } else {
        char mapped_path[MAX_PATH] = "C:\\";
        for (int i = 0; i < map_count; i++) { if (maps[i].tid == req->tree_id) { strcpy(mapped_path, maps[i].path); break; } }
        char full_path[MAX_PATH];
        if (file_path[0]) { if (mapped_path[strlen(mapped_path)-1] == '\\' && file_path[0] == '\\') snprintf(full_path, sizeof(full_path), "%s%s", mapped_path, file_path + 1); else snprintf(full_path, sizeof(full_path), "%s\\%s", mapped_path, file_path); } else strcpy(full_path, mapped_path);
        normalize_local_path(full_path);
        if (*handle_count < 256) { handles[*handle_count].fid = new_fid; strcpy(handles[*handle_count].path, full_path); handles[*handle_count].dcerpc_state = 0; (*handle_count)++; }
        file_attr = GetFileAttributesA(full_path); if (file_attr == INVALID_FILE_ATTRIBUTES) file_attr = 0x80;
    }
    
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, SMB2_CREATE, 0);
    uint8_t *w = resp_buf + 64;
    *(uint16_t*)w = 89; w += 2; *w++ = 0; *w++ = 0; *(uint32_t*)w = 1; w += 4; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint32_t*)w = file_attr; w += 4; *(uint32_t*)w = 0; w += 4; *(uint64_t*)w = new_fid; w += 8; *(uint64_t*)w = new_fid; w += 8; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4; 
    return (uint32_t)(w - resp_buf);
}

static uint32_t handle_smb2_query_directory(SMB2Header *req, uint8_t *resp_buf, HandleMap *handles, int handle_count) {
    uint8_t *req_data = (uint8_t*)req;
    uint64_t req_fid = *(uint64_t*)(req_data + 64 + 16); 
    uint16_t name_off = *(uint16_t*)(req_data + 64 + 24);
    uint16_t name_len = *(uint16_t*)(req_data + 64 + 26);
    uint8_t info_class = *(req_data + 64 + 2);
    
    char search_pattern[MAX_PATH] = {0};
    if (name_off >= 64 && name_off + name_len <= 65536) {
        uint16_t *uname = (uint16_t*)(req_data + name_off); int i = 0;
        while (i < name_len/2 && i < MAX_PATH - 1) { search_pattern[i] = (char)uname[i]; i++; }
    }
    if (search_pattern[0] == 0) strcpy(search_pattern, "*"); 
    
    char target_path[MAX_PATH] = "C:\\";
    for (int i = 0; i < handle_count; i++) { if (handles[i].fid == req_fid) { strcpy(target_path, handles[i].path); break; } }
    
    char local_search[MAX_PATH];
    if (target_path[strlen(target_path)-1] == '\\' && search_pattern[0] == '\\') snprintf(local_search, sizeof(local_search), "%s%s", target_path, search_pattern + 1);
    else snprintf(local_search, sizeof(local_search), "%s\\%s", target_path, search_pattern);
    normalize_local_path(local_search);
    
    server_log("SMB2 Query Directory (Class %d) -> %s", info_class, local_search);
    
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, SMB2_QUERY_DIRECTORY, 0);
    uint8_t *w = resp_buf + 64; *(uint16_t*)w = 9; w += 2; *(uint16_t*)w = 72; w += 2; uint32_t *out_len_ptr = (uint32_t*)w; w += 4; 
    
    uint8_t *data_start = w; WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(local_search, &fd);
    uint8_t *last_entry = NULL; int count = 0;
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (w + 512 > resp_buf + 65000) break;
            
            last_entry = w;
            uint32_t *next_off = (uint32_t*)w; w += 4; *(uint32_t*)w = 0; w += 4; 
            *(uint64_t*)w = ((uint64_t)fd.ftCreationTime.dwHighDateTime << 32) | fd.ftCreationTime.dwLowDateTime; w += 8;
            *(uint64_t*)w = ((uint64_t)fd.ftLastAccessTime.dwHighDateTime << 32) | fd.ftLastAccessTime.dwLowDateTime; w += 8;
            *(uint64_t*)w = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime; w += 8;
            *(uint64_t*)w = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime; w += 8;
            
            uint64_t fsize = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            *(uint64_t*)w = fsize; w += 8; *(uint64_t*)w = fsize; w += 8; *(uint32_t*)w = fd.dwFileAttributes; w += 4;
            uint32_t *name_len_ptr = (uint32_t*)w; w += 4; 
            
            if (info_class == 2 || info_class == 3 || info_class == 37) { *(uint32_t*)w = 0; w += 4; }
            if (info_class == 3 || info_class == 37) { *w++ = 0; *w++ = 0; memset(w, 0, 24); w += 24; }
            if (info_class == 37) { *(uint16_t*)w = 0; w += 2; *(uint64_t*)w = 0; w += 8; }
            
            uint16_t *uname = (uint16_t*)w; int i = 0;
            while (fd.cFileName[i]) { uname[i] = (uint16_t)fd.cFileName[i]; i++; }
            *name_len_ptr = i * 2; w += i * 2;
            
            int epad = (8 - ((w - last_entry) % 8)) % 8; w += epad; *next_off = (uint32_t)(w - last_entry); 
            count++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    
    if (last_entry) *(uint32_t*)last_entry = 0; 
    
    if (count == 0) { hdr->status = 0x80000006; *out_len_ptr = 0; return 72; } 
    else { *out_len_ptr = (uint32_t)(w - data_start); return 64 + 8 + (*out_len_ptr); }
}

static uint32_t handle_smb2_read(SMB2Header *req, uint8_t *resp_buf, HandleMap *handles, int handle_count) {
    uint8_t *req_data = (uint8_t*)req;
    uint64_t fid = *(uint64_t*)(req_data + 64 + 16);
    int dcerpc_state = 0, is_srvsvc = 0, handle_idx = -1;
    for(int i = 0; i < handle_count; i++) {
        if(handles[i].fid == fid) { if (_stricmp(handles[i].path, "\\srvsvc") == 0) { is_srvsvc = 1; dcerpc_state = handles[i].dcerpc_state; handle_idx = i; } break; }
    }
    
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, SMB2_READ, 0);
    uint8_t *w = resp_buf + 64; *(uint16_t*)w = 17; w += 2; *w++ = 80; *w++ = 0; uint32_t *len_ptr = (uint32_t*)w; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4;
    
    if (is_srvsvc && handle_idx != -1) {
        uint8_t *data_start = w;
        if (dcerpc_state == 1) {
            uint8_t bind_ack[] = { 0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x73, 0x72, 0x76, 0x73, 0x76, 0x63, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };
            *(uint32_t*)(bind_ack + 12) = handles[handle_idx].dcerpc_call_id; memcpy(w, bind_ack, sizeof(bind_ack)); w += sizeof(bind_ack);
        } else if (dcerpc_state == 2) {
            uint8_t head[] = { 0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            *(uint32_t*)(head + 12) = handles[handle_idx].dcerpc_call_id; *(uint16_t*)(head + 20) = handles[handle_idx].dcerpc_ctx_id;
            memcpy(w, head, sizeof(head)); uint8_t *dce_start = w; w += sizeof(head);
            *(uint32_t*)w = 1; w += 4; *(uint32_t*)w = 1; w += 4; *(uint32_t*)w = 0x00020000; w += 4; *(uint32_t*)w = g_share_count; w += 4; *(uint32_t*)w = 0x00020004; w += 4; *(uint32_t*)w = g_share_count; w += 4;
            uint32_t ptr_id = 0x00020008;
            for(int j = 0; j < g_share_count; j++) { *(uint32_t*)w = ptr_id++; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = ptr_id++; w += 4; }
            for(int j = 0; j < g_share_count; j++) {
                size_t slen = strlen(g_shares[j].name); *(uint32_t*)w = slen + 1; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = slen + 1; w += 4; 
                for(size_t k = 0; k <= slen; k++) { *(uint16_t*)w = (uint16_t)g_shares[j].name[k]; w += 2; }
                if ((w - dce_start) % 4 != 0) w += 4 - ((w - dce_start) % 4);
                *(uint32_t*)w = 1; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 1; w += 4; *(uint16_t*)w = 0; w += 2;
                if ((w - dce_start) % 4 != 0) w += 4 - ((w - dce_start) % 4);
            }
            *(uint32_t*)w = g_share_count; w += 4; *(uint32_t*)w = 0x00024321; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4; 
            uint16_t frag_len = (uint16_t)(w - dce_start); *(uint16_t*)(dce_start + 8) = frag_len; *(uint32_t*)(dce_start + 16) = frag_len - 24;
            server_log("Handled: SMB2 NetShareEnumAll (Returned %d shares)", g_share_count);
        } else if (dcerpc_state == 3) {
            uint8_t head[] = { 0x05, 0x00, 0x03, 0x03, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            *(uint32_t*)(head + 12) = handles[handle_idx].dcerpc_call_id; *(uint16_t*)(head + 20) = handles[handle_idx].dcerpc_ctx_id;
            memcpy(w, head, sizeof(head)); w += sizeof(head); *(uint32_t*)w = 0x1C010002; w += 4; *(uint32_t*)w = 0; w += 4; 
        }
        handles[handle_idx].dcerpc_state = 0; *len_ptr = (uint32_t)(w - data_start);
        return (uint32_t)(w - resp_buf);
    }
    return (uint32_t)(w - resp_buf);
}

static uint32_t handle_smb2_close(SMB2Header *req, uint8_t *resp_buf) {
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, SMB2_CLOSE, 0);
    uint8_t *w = resp_buf + 64; *(uint16_t*)w = 60; w += 2; *(uint16_t*)w = 0; w += 2; *(uint32_t*)w = 0; w += 4; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint64_t*)w = 0; w += 8; *(uint32_t*)w = 0x80; w += 4; 
    return (uint32_t)(w - resp_buf);
}

static uint32_t handle_smb2_unsupported(SMB2Header *req, uint8_t *resp_buf) {
    SMB2Header *hdr = (SMB2Header*)resp_buf; build_smb2_resp_header(hdr, req, req->command, 0xC00000BB);
    *(uint16_t*)(resp_buf + 64) = 9; return 64 + 9;
}

static DWORD WINAPI ClientThread(LPVOID param) {
    SOCKET client = (SOCKET)param;
    uint8_t header[4];
    TidMap maps[32]; int map_count = 0;
    HandleMap handles[256]; int handle_count = 0;
    
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
        
        if (received == len && len >= 4) {
            if (memcmp(payload, "\xFFSMB", 4) == 0) {
                uint8_t out_pkt[256];
                uint32_t out_len = handle_smb1_upgrade(out_pkt + 4);
                send_packet(client, out_pkt + 4, out_len);
            } else if (memcmp(payload, "\xFE\x53\x4D\x42", 4) == 0 && len >= 64) {
                uint8_t *cur_req = payload;
                uint32_t remaining = len;
                
                uint8_t *out_pkt = malloc(131072);
                uint32_t out_len = 0;
                
                while (remaining >= 64) {
                    SMB2Header *smb2 = (SMB2Header*)cur_req;
                    uint32_t next_cmd = smb2->next_command;
                    
                    uint8_t *resp_ptr = out_pkt + 4 + out_len;
                    uint32_t resp_len = 0;
                    
                    switch(smb2->command) {
                        case SMB2_NEGOTIATE: resp_len = handle_smb2_negotiate(smb2, resp_ptr); break;
                        case SMB2_SESSION_SETUP: resp_len = handle_smb2_session_setup(smb2, resp_ptr); break;
                        case SMB2_TREE_CONNECT: resp_len = handle_smb2_tree_connect(smb2, resp_ptr, maps, &map_count); break;
                        case SMB2_CREATE: resp_len = handle_smb2_create(smb2, resp_ptr, maps, map_count, handles, &handle_count); break;
                        case SMB2_QUERY_DIRECTORY: resp_len = handle_smb2_query_directory(smb2, resp_ptr, handles, handle_count); break;
                        case SMB2_WRITE: resp_len = handle_smb2_write(smb2, resp_ptr, handles, handle_count); break;
                        case SMB2_READ: resp_len = handle_smb2_read(smb2, resp_ptr, handles, handle_count); break;
                        case SMB2_CLOSE: resp_len = handle_smb2_close(smb2, resp_ptr); break;
                        default: resp_len = handle_smb2_unsupported(smb2, resp_ptr); break;
                    }
                    
                    if (next_cmd != 0 && next_cmd <= remaining) {
                        int pad = (8 - (resp_len % 8)) % 8;
                        resp_len += pad;
                        ((SMB2Header*)resp_ptr)->next_command = resp_len;
                    } else { ((SMB2Header*)resp_ptr)->next_command = 0; }
                    
                    out_len += resp_len;
                    if (next_cmd == 0 || next_cmd > remaining) break;
                    cur_req += next_cmd; remaining -= next_cmd;
                }
                
                if (out_len > 0) send_packet(client, out_pkt + 4, out_len);
                free(out_pkt);
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
    server_log("SMB2 Server listening on port %d...", g_port);

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

static void FreePidl(LPITEMIDLIST pidl) {
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    if (hOle32) {
        void (WINAPI *pCoTaskMemFree)(LPVOID) = (void*)GetProcAddress(hOle32, "CoTaskMemFree");
        if (pCoTaskMemFree) pCoTaskMemFree(pidl);
        FreeLibrary(hOle32);
    }
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
            strcpy(g_nid.szTip, "SMB2 Server"); Shell_NotifyIcon(NIM_ADD, &g_nid);
            ToggleServer(); return 0;
        case WM_TRAYICON: if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP) ShowContextMenu(hwnd); return 0;
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_TRAY_TOGGLE: ToggleServer(); break;
                case ID_TRAY_SETTINGS:
                    if (!g_hSettings) {
                        WNDCLASSEXA wcx = {sizeof(WNDCLASSEXA), 0, SettingsWndProc, 0, 0, g_hInst, NULL, LoadCursor(NULL, IDC_ARROW), (HBRUSH)(COLOR_WINDOW+1), NULL, "SettingsClass", NULL};
                        RegisterClassExA(&wcx);
                        g_hSettings = CreateWindowExA(WS_EX_CONTROLPARENT, "SettingsClass", "SMB2 Server Settings", WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME, CW_USEDEFAULT, CW_USEDEFAULT, 520, 380, NULL, NULL, g_hInst, NULL);
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
    g_hMain = CreateWindowExA(0, "HiddenMainClass", "SMB2 Tray Server", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        HWND hActive = GetActiveWindow(); if (hActive && IsDialogMessage(hActive, &msg)) continue;
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}