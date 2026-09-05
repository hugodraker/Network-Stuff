/* 
 * Dual-Pane SMB1/SMB2/FTP Client Implementation
 * - Native SMB1/SMB2/FTP support with full recursive transfers
 * - Native Win32 drag-and-drop between panes
 * - Dynamic Subdirectory Connection Parsing & Normalization
 * - Active Session SSPI NTLM Authentication
 * - Multi-select item handling
 *
 * COMPILATION:
 *   gcc -Os -s -o smb2c.exe smb2c.c -lws2_32 -lwininet -lcomctl32 -lgdi32 -luser32 -ladvapi32 -lcrypt32 -lnetapi32 -lsecur32 -mwindows
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <wininet.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <commctrl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "secur32.lib")
#pragma warning(disable: 4996)

#define MAX_SMB_PATH        1024
#define MAX_SMB_PATH_LEN    4096
#define MAX_ITEMS           500
#define MAX_SHARES          50
#define SMB_BUFFER_SIZE     131072
#define PANE_LOCAL          0
#define PANE_REMOTE         1
#define CONN_NONE           0
#define CONN_SMB            1
#define CONN_FTP            2

#define PROTO_AUTO          0
#define PROTO_SMB1          1
#define PROTO_SMB2          2
#define PROTO_FTP           3

#define ID_LIST_LOCAL       1001
#define ID_LIST_REMOTE      1002
#define ID_STATUSBAR        1003
#define ID_COMBO_CONN       1004
#define ID_BTN_CONNECT      1005
#define ID_BTN_EDIT_CONN    1006
#define ID_PROGRESS         1007

#define ID_BTN_COPY         1101
#define ID_BTN_MOVE         1102
#define ID_BTN_RENAME       1103
#define ID_BTN_DELETE       1104
#define ID_BTN_MKDIR        1105

#define IDE_NAME            2001
#define IDE_SERVER          2002
#define IDE_PORT            2010
#define IDE_SHARE           2003
#define IDE_USER            2004
#define IDE_PASS            2005
#define IDB_SAVE            2006
#define IDB_CANCEL          2007
#define IDB_ADD             2008
#define IDB_DELETE          2009
#define IDC_CHK_FTP         2011
#define IDC_PROTO_SMB2      2012
#define IDB_TEST            2013

#define IDB_RENAME_OK       3001
#define IDE_RENAME_NEW      3002
#define IDE_MKDIR_NAME      3003
#define IDB_MKDIR_OK        3004

#define TIMER_PROGRESS_HIDE 999

#define SMB2_PORT           445
#define SMB2_DIALECT_0202   0x0202
#define SMB2_DIALECT_0210   0x0210
#define SMB2_DIALECT_0300   0x0300

#define SMB2_NEGOTIATE      0x0000
#define SMB2_SESSION_SETUP  0x0001
#define SMB2_TREE_CONNECT   0x0003
#define SMB2_CREATE         0x0005
#define SMB2_CLOSE          0x0006
#define SMB2_QUERY_DIRECTORY 0x000E
#define SMB2_READ           0x0008
#define SMB2_WRITE          0x0009
#define SMB2_LOGOFF         0x0002
#define SMB2_TREE_DISCONNECT 0x0004
#define SMB2_SET_INFO       0x0011

#define STATUS_SUCCESS              0x00000000
#define STATUS_MORE_PROCESSING      0xC0000016
#define SMB2_FILE_BOTH_DIRECTORY_INFORMATION 3

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

typedef struct {
    uint16_t structure_size;
    uint16_t dialect_count;
    uint16_t security_mode;
    uint16_t reserved;
    uint32_t capabilities;
    uint8_t  client_guid[16];
    uint32_t negotiate_context_offset;
    uint16_t negotiate_context_count;
    uint16_t reserved2;
} SMB2NegotiateReq;

typedef struct {
    uint16_t structure_size;
    uint16_t security_mode;
    uint16_t dialect_revision;
    uint16_t reserved;
    uint8_t  server_guid[16];
    uint32_t capabilities;
    uint32_t max_transact_size;
    uint32_t max_read_size;
    uint32_t max_write_size;
    uint64_t system_time;
    uint64_t server_start_time;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
    uint32_t negotiate_context_offset;
} SMB2NegotiateResp;

typedef struct {
    uint16_t structure_size;
    uint8_t  flags;
    uint8_t  security_mode;
    uint32_t capabilities;
    uint32_t channel;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
    uint64_t previous_session_id;
} SMB2SessionSetupReq;

typedef struct {
    uint16_t structure_size;
    uint8_t  session_flags;
    uint8_t  reserved;
    uint16_t security_buffer_offset;
    uint16_t security_buffer_length;
} SMB2SessionSetupResp;

typedef struct {
    uint16_t structure_size;
    uint16_t reserved;
    uint16_t path_offset;
    uint16_t path_length;
} SMB2TreeConnectReq;

typedef struct {
    uint16_t structure_size;
    uint8_t  security_flags;
    uint8_t  requested_oplock_level;
    uint32_t impersonation_level;
    uint64_t smb_create_flags;
    uint64_t reserved;
    uint32_t desired_access;
    uint32_t file_attributes;
    uint32_t share_access;
    uint32_t create_disposition;
    uint32_t create_options;
    uint16_t name_offset;
    uint16_t name_length;
    uint32_t create_contexts_offset;
    uint32_t create_contexts_length;
} SMB2CreateReq;

typedef struct {
    uint16_t structure_size;
    uint8_t  oplock_level;
    uint8_t  flag;
    uint32_t create_action;
    uint64_t creation_time;
    uint64_t last_access_time;
    uint64_t last_write_time;
    uint64_t change_time;
    uint64_t allocation_size;
    uint64_t end_of_file;
    uint32_t file_attributes;
    uint32_t reserved2;
    uint64_t file_id_persistent;
    uint64_t file_id_volatile;
} SMB2CreateResp;

typedef struct {
    uint16_t structure_size;
    uint16_t flags;
    uint32_t reserved;
    uint64_t file_id_persistent;
    uint64_t file_id_volatile;
} SMB2CloseReq;

typedef struct {
    uint16_t structure_size;
    uint8_t  file_information_class;
    uint8_t  flags;
    uint32_t file_index;
    uint64_t file_id_persistent;
    uint64_t file_id_volatile;
    uint16_t name_offset;
    uint16_t name_length;
    uint32_t output_buffer_length;
} SMB2QueryDirReqFixed;

typedef struct {
    uint16_t structure_size;
    uint8_t  padding;
    uint8_t  flags;
    uint32_t length;
    uint64_t offset;
    uint64_t file_id_persistent;
    uint64_t file_id_volatile;
    uint32_t minimum_count;
    uint32_t channel;
    uint32_t remaining_bytes;
    uint16_t read_channel_info_offset;
    uint16_t read_channel_info_length;
} SMB2ReadReq;

typedef struct {
    uint16_t structure_size;
    uint16_t data_offset;
    uint32_t data_length;
    uint32_t data_remaining;
    uint32_t reserved2;
} SMB2ReadResp;

typedef struct {
    uint16_t structure_size;
    uint16_t data_offset;
    uint32_t length;
    uint64_t offset;
    uint64_t file_id_persistent;
    uint64_t file_id_volatile;
    uint32_t channel;
    uint32_t remaining_bytes;
    uint16_t write_channel_info_offset;
    uint16_t write_channel_info_length;
    uint32_t flags;
} SMB2WriteReq;

typedef struct {
    uint16_t structure_size;
    uint8_t  info_type;      
    uint8_t  file_info_class;
    uint32_t buffer_length;
    uint16_t buffer_offset;  
    uint16_t reserved;
    uint32_t additional_information;
    uint64_t file_id_persistent;
    uint64_t file_id_volatile;
} SMB2SetInfoReq;
#pragma pack(pop)

typedef struct {
    char path[MAX_SMB_PATH_LEN];
    int  is_dir;
} DirectoryItem;

typedef struct {
    char name[64];
    char server[128];
    char port[16];
    char share[128];
    char user[64];
    char pass[64];
    int  is_ftp;
    int  proto_pref;
    char shares_hist[512]; 
} ConnectionProfile;

typedef struct {
    HWND hMain, hComboConn, hBtnEdit, hBtnConnect;
    HWND hBtnCopy, hBtnMove, hBtnRename, hBtnDelete, hBtnMkDir;
    HWND hRemoteList, hLocalList, hStatus, hProgress;
    HWND hLblLocal, hLblRemote;
    
    ConnectionProfile *connections;
    int conn_capacity;
    int conn_count, selected_conn_idx;
    RECT original_rect;
    
    char remote_base[MAX_SMB_PATH_LEN];
    char local_base[MAX_SMB_PATH_LEN];
    
    SOCKET sconn;
    HINTERNET hInternet, hFtpSession;
    int conn_type;
    int current_proto;
    
    uint16_t tid, uid, mid_counter;
    char g_session_response[8];
    
    uint64_t smb2_session_id;
    uint32_t smb2_tree_id;
    uint64_t smb2_message_id;
    uint8_t  smb2_server_guid[16];
    
    DirectoryItem remote_items[MAX_ITEMS];
    DirectoryItem local_items[MAX_ITEMS];
    int remote_count, local_count;
    
    int active_pane;
    char pending_server[128];
} AppContext;

static AppContext g_app;
static HINSTANCE g_hInst;
static char g_ini_path[MAX_PATH];

static char g_ren_base[MAX_SMB_PATH];
static char g_ren_item[MAX_SMB_PATH];
char g_conn_log[8192] = "Application Started.\r\n";
HWND g_hToolTip = NULL;

/* ==========================================================================
   FORWARD DECLARATIONS (STRICT ORDERING)
   ========================================================================== */
static void add_log(const char *fmt, ...);
static void set_progress(int percent);
static void trim_str(char *str);
static void normalize_path(char *path, int is_ftp);
static void init_ini_path(void);
static size_t utf8_to_utf16le(const char *src, uint8_t *dst, size_t dst_max);
static void get_random_bytes(uint8_t *buf, size_t len);

static void load_config(HWND hwnd);
static void save_config(HWND hwnd);
static void disconnect_all(void);

static int connect_with_timeout(SOCKET sock, struct sockaddr *addr, int addrlen);

static int smb_send_packet(const void *data, size_t len);
static int smb_recv_packet(uint8_t *buffer, size_t max_len, size_t *out_len);
static SMB1Header* smb_build_header(uint8_t *packet, uint8_t cmd);
static void smb2_init_header(SMB2Header *hdr, uint16_t cmd);

static int smb_negotiate(void);
static int smb_session(const char *user, const char *pass);
static int smb_tree_connect(const char *server, const char *share);
static int smb_list_directory(void);

static int smb2_negotiate(void);
static int smb2_session_setup(const char *user, const char *pass);
static int smb2_tree_connect(const char *server, const char *share);
static int smb2_tree_disconnect(void);
static int smb2_list_directory(void);

static int smb2_ipc_enum_shares(const char *server, char (*shares)[64], int max_shares);
static int enum_shares_ipc(char (*shares)[64], int max_shares);
static int enumerate_shares(char (*shares)[64], int max_shares, int is_smb2_capable);

static int connect_server(ConnectionProfile *p);
static int connect_ftp(ConnectionProfile *p);

static void list_remote(void);
static void list_local(void);
static void update_remote_list(void);
static void update_local_list(void);

static void format_folder_path(char *dst, size_t max_len, const char *base_dir, const char *new_dir, int is_ftp);
static int smb_mkdir_ex(const char *parent_dir, const char *dirname);
static int ftp_mkdir_ex(const char *parent_dir, const char *dirname);
static int smb_delete(const char *path);
static int smb_delete_dir(const char *path);
static int smb_rename(const char *oldp, const char *newp);
static int smb2_mkdir(const char *rpath);
static int smb2_delete_internal(const char* rpath, int is_dir);
static int smb2_rename(const char *oldp, const char *newp);

static int copy_r2l_file(const char *rpath, const char *lpath);
static int copy_l2r_file(const char *lpath, const char *rpath);
static int smb2_copy_r2l_file(const char *rpath, const char *lpath);
static int smb2_copy_l2r_file(const char *lpath, const char *rpath);
static int copy_ftp_r2l_file(const char *rpath, const char *lpath);
static int copy_ftp_l2r_file(const char *lpath, const char *rpath);

static int copy_single_r2l(const char *rpath, const char *lpath);
static int copy_single_l2r(const char *lpath, const char *rpath);
static int create_remote_dir(const char *rpath);
static int fetch_remote_dir_contents(const char *rpath, DirectoryItem **items, int *count);
static void copy_recursive_r2l(const char *rpath, const char *lpath, int is_dir);
static void copy_recursive_l2r(const char *lpath, const char *rpath, int is_dir);
static void delete_recursive_local(const char *path);
static void do_action(int action);

static WNDPROC OldListProc;
static LRESULT CALLBACK ListSubProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam);

/* ==========================================================================
   UTILITY FUNCTIONS
   ========================================================================== */
static int compare_local_items(const void *a, const void *b) {
    const DirectoryItem *itemA = (const DirectoryItem *)a;
    const DirectoryItem *itemB = (const DirectoryItem *)b;
    if (itemA->is_dir && !itemB->is_dir) return -1;
    if (!itemA->is_dir && itemB->is_dir) return 1;
    return _stricmp(itemA->path, itemB->path);
}

static void add_log(const char *fmt, ...) {
    char buf[512]; va_list args;
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    SetWindowTextA(g_app.hStatus, buf);
    if (strlen(g_conn_log) + strlen(buf) + 4 >= sizeof(g_conn_log)) {
        memmove(g_conn_log, g_conn_log + 2048, sizeof(g_conn_log) - 2048);
        g_conn_log[sizeof(g_conn_log)-1] = 0;
    }
    strcat(g_conn_log, buf); strcat(g_conn_log, "\r\n");
    if (g_hToolTip) {
        TOOLINFOA ti = {0}; ti.cbSize = sizeof(TOOLINFOA); ti.hwnd = g_app.hMain;
        ti.uId = (UINT_PTR)g_app.hStatus; ti.lpszText = g_conn_log;
        SendMessageA(g_hToolTip, TTM_UPDATETIPTEXTA, 0, (LPARAM)&ti);
    }
}

static void set_progress(int percent) {
    if (percent < 0) percent = 0;
    if (percent >= 100) {
        ShowWindow(g_app.hProgress, SW_SHOW);
        SendMessageA(g_app.hProgress, PBM_SETPOS, 100, 0);
        SetTimer(g_app.hMain, TIMER_PROGRESS_HIDE, 1000, NULL);
    } else {
        KillTimer(g_app.hMain, TIMER_PROGRESS_HIDE);
        ShowWindow(g_app.hProgress, SW_SHOW);
        SendMessageA(g_app.hProgress, PBM_SETPOS, (WPARAM)percent, 0);
    }
}

static void trim_str(char *str) {
    char *p = str; int l = strlen(p);
    while (l > 0 && (p[l-1] == ' ' || p[l-1] == '\r' || p[l-1] == '\n' || p[l-1] == '\t')) p[--l] = 0;
    while (*p && (*p == ' ' || *p == '\t')) { p++; l--; }
    memmove(str, p, l + 1);
}

static void normalize_path(char *path, int is_ftp) {
    char target = is_ftp ? '/' : '\\';
    char wrong  = is_ftp ? '\\' : '/';
    for (char *p = path; *p; ++p) { if (*p == wrong) *p = target; }
}

static void init_ini_path(void) {
    GetModuleFileNameA(NULL, g_ini_path, MAX_PATH);
    char *ext = strrchr(g_ini_path, '.');
    if (ext) strcpy(ext, ".ini"); else strcat(g_ini_path, ".ini");
}

static size_t utf8_to_utf16le(const char *src, uint8_t *dst, size_t dst_max) {
    size_t di = 0, si = 0;
    while (src[si] && di + 2 <= dst_max) { dst[di++] = (uint8_t)src[si]; dst[di++] = 0; si++; }
    return di;
}

static void get_random_bytes(uint8_t *buf, size_t len) {
    HCRYPTPROV prov;
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(prov, len, buf); CryptReleaseContext(prov, 0);
    } else {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* ==========================================================================
   NETWORK TIMEOUT UTILITY
   ========================================================================== */
static int connect_with_timeout(SOCKET sock, struct sockaddr *addr, int addrlen) {
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    if (connect(sock, addr, addrlen) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) return 0;
    }
    
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000; /* 50ms Timeout */
    
    if (select(0, NULL, &fdset, NULL, &tv) == 1) {
        int so_error = 0;
        int len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        if (so_error == 0) {
            mode = 0;
            ioctlsocket(sock, FIONBIO, &mode);
            DWORD timeout = 50; /* Ensure operations timeout fast too */
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
            return 1;
        }
    }
    return 0;
}

/* ==========================================================================
   CONFIG LOAD/SAVE
   ========================================================================== */
static void load_config(HWND hwnd) {
    g_app.conn_count = GetPrivateProfileIntA("Connections", "Count", 0, g_ini_path);
    g_app.selected_conn_idx = GetPrivateProfileIntA("Connections", "LastSelected", 0, g_ini_path);
    
    if (g_app.conn_count <= 0) {
        g_app.conn_count = 1; g_app.conn_capacity = 10;
        g_app.connections = (ConnectionProfile*)malloc(g_app.conn_capacity * sizeof(ConnectionProfile));
        strcpy(g_app.connections[0].name, "Default Connection"); strcpy(g_app.connections[0].server, "192.168.1.100");
        strcpy(g_app.connections[0].port, ""); strcpy(g_app.connections[0].share, "shared");
        strcpy(g_app.connections[0].user, ""); strcpy(g_app.connections[0].pass, "");
        g_app.connections[0].is_ftp = 0; g_app.connections[0].proto_pref = PROTO_AUTO;
        strcpy(g_app.connections[0].shares_hist, ""); g_app.selected_conn_idx = 0;
    } else {
        g_app.conn_capacity = g_app.conn_count + 10;
        g_app.connections = (ConnectionProfile*)malloc(g_app.conn_capacity * sizeof(ConnectionProfile));
        for (int i = 0; i < g_app.conn_count; i++) {
            char key[32];
            sprintf(key, "Name%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].name, 64, g_ini_path);
            sprintf(key, "Server%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].server, 128, g_ini_path);
            sprintf(key, "Port%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].port, 16, g_ini_path);
            sprintf(key, "Share%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].share, 128, g_ini_path);
            sprintf(key, "User%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].user, 64, g_ini_path);
            sprintf(key, "Pass%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].pass, 64, g_ini_path);
            sprintf(key, "IsFTP%d", i); g_app.connections[i].is_ftp = GetPrivateProfileIntA("Connections", key, 0, g_ini_path);
            sprintf(key, "Proto%d", i); g_app.connections[i].proto_pref = GetPrivateProfileIntA("Connections", key, PROTO_AUTO, g_ini_path);
            sprintf(key, "SharesHist%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].shares_hist, 512, g_ini_path);
        }
    }
    if (g_app.selected_conn_idx < 0 || g_app.selected_conn_idx >= g_app.conn_count) g_app.selected_conn_idx = 0;
}

static void save_config(HWND hwnd) {
    WritePrivateProfileSectionA("Connections", "", g_ini_path);
    char val[32]; sprintf(val, "%d", g_app.conn_count); WritePrivateProfileStringA("Connections", "Count", val, g_ini_path);
    sprintf(val, "%d", g_app.selected_conn_idx); WritePrivateProfileStringA("Connections", "LastSelected", val, g_ini_path);
    for (int i = 0; i < g_app.conn_count; i++) {
        char key[32];
        sprintf(key, "Name%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].name, g_ini_path);
        sprintf(key, "Server%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].server, g_ini_path);
        sprintf(key, "Port%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].port, g_ini_path);
        sprintf(key, "Share%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].share, g_ini_path);
        sprintf(key, "User%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].user, g_ini_path);
        sprintf(key, "Pass%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].pass, g_ini_path);
        sprintf(key, "IsFTP%d", i); sprintf(val, "%d", g_app.connections[i].is_ftp); WritePrivateProfileStringA("Connections", key, val, g_ini_path);
        sprintf(key, "Proto%d", i); sprintf(val, "%d", g_app.connections[i].proto_pref); WritePrivateProfileStringA("Connections", key, val, g_ini_path);
        sprintf(key, "SharesHist%d", i); WritePrivateProfileStringA("Connections", key, g_app.connections[i].shares_hist, g_ini_path);
    }
}

static void disconnect_all(void) {
    if (g_app.sconn) { closesocket(g_app.sconn); g_app.sconn = 0; }
    if (g_app.hFtpSession) { InternetCloseHandle(g_app.hFtpSession); g_app.hFtpSession = NULL; }
    if (g_app.hInternet) { InternetCloseHandle(g_app.hInternet); g_app.hInternet = NULL; }
    g_app.conn_type = CONN_NONE; g_app.current_proto = PROTO_AUTO;
    g_app.smb2_session_id = 0; g_app.smb2_tree_id = 0; g_app.smb2_message_id = 0; g_app.tid = 0; g_app.uid = 0;
}

/* ==========================================================================
   SMB TRANSPORT
   ========================================================================== */
static int smb_send_packet(const void *data, size_t len) {
    uint8_t header[4] = {0, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF};
    if (send(g_app.sconn, (const char*)header, 4, 0) != 4) return 0;
    const uint8_t *buf = (const uint8_t*)data; size_t rem = len;
    while (rem > 0) { int sent = send(g_app.sconn, (const char*)buf, (int)rem, 0); if (sent <= 0) return 0; buf += sent; rem -= sent; }
    return 1;
}

static int smb_recv_packet(uint8_t *buffer, size_t max_len, size_t *out_len) {
    uint8_t header[4];
    while (1) {
        if (recv(g_app.sconn, (char*)header, 4, 0) != 4) return 0;
        size_t expected = ((size_t)(header[1] & 0x01) << 16) | ((size_t)header[2] << 8) | header[3];
        if (header[0] == 0x85 && expected == 0) continue; 
        if (expected > max_len) expected = max_len;
        size_t received = 0;
        while (received < expected) { 
            int rcvd = recv(g_app.sconn, (char*)(buffer + received), (int)(expected - received), 0); 
            if (rcvd <= 0) return 0; received += rcvd; 
        }
        *out_len = received; return 1;
    }
}

static SMB1Header* smb_build_header(uint8_t *packet, uint8_t cmd) {
    SMB1Header *hdr = (SMB1Header*)packet;
    memcpy(hdr->protocol_id, "\xFFSMB", 4); hdr->cmd = cmd;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF; hdr->mid = g_app.mid_counter++;
    hdr->flags1 = 0x80; hdr->flags2 = 0x07C7; hdr->uid = g_app.uid; hdr->tid = g_app.tid;
    memset(hdr->signature, 0, 8); return hdr;
}

static void smb2_init_header(SMB2Header *hdr, uint16_t cmd) {
    memcpy(hdr->protocol_id, "\xFE\x53\x4D\x42", 4); hdr->structure_size = 64;
    hdr->credit_charge = (cmd == SMB2_NEGOTIATE) ? 0 : 1; hdr->status = 0; hdr->command = cmd;
    hdr->credit_request = 32; hdr->flags = 0; hdr->next_command = 0;
    hdr->message_id = g_app.smb2_message_id++; hdr->process_id = 0; 
    hdr->tree_id = g_app.smb2_tree_id; hdr->session_id = g_app.smb2_session_id;
    memset(hdr->signature, 0, 16);
}

/* ==========================================================================
   SMB1 CORE
   ========================================================================== */
static int smb_negotiate(void) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x72); 
    uint8_t *w = pkt + sizeof(SMB1Header);
    const char *dialects[] = { "PC NETWORK PROGRAM 1.0", "MICROSOFT NETWORKS 3.0", "DOS LM1.2X002", "DOS LANMAN2.1", "Windows for Workgroups 3.1a", "NT LM 0.12" };
    *w++ = 0; uint8_t *bcc_ptr = w; w += 2; 
    for (int i = 0; i < 6; i++) { *w++ = 0x02; strcpy((char*)w, dialects[i]); w += strlen(dialects[i]) + 1; }
    *(uint16_t*)bcc_ptr = (w - bcc_ptr) - 2;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    uint32_t status = ((SMB1Header*)pkt)->status; 
    return (status == 0);
}

static int smb_session(const char *user, const char *pass) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x73); uint8_t *w = pkt + sizeof(SMB1Header);
    char domain[64] = "WORKGROUP"; char uname[64] = ""; const char *slash = strchr(user, '\\');
    if (slash) { size_t dlen = slash - user; if (dlen < sizeof(domain)) { strncpy(domain, user, dlen); domain[dlen] = '\0'; } strcpy(uname, slash + 1); } 
    else { strcpy(uname, user); }
    *w++ = 10; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 65535; w += 2; *(uint16_t*)w = 2; w += 2; *(uint16_t*)w = 1; w += 2; *(uint32_t*)w = 0; w += 4;     
    uint16_t pass_len = strlen(pass); *(uint16_t*)w = pass_len ? pass_len + 1 : 1; w += 2; *(uint32_t*)w = 0; w += 4;                           
    uint8_t *bcc_ptr = w; w += 2; uint8_t *data_start = w;
    if (pass_len > 0) { strcpy((char*)w, pass); w += pass_len + 1; } else { *w++ = 0; }
    strcpy((char*)w, uname); w += strlen(uname) + 1; strcpy((char*)w, domain); w += strlen(domain) + 1;
    strcpy((char*)w, "Windows 5.1"); w += strlen("Windows 5.1") + 1; strcpy((char*)w, "LAN Manager"); w += strlen("LAN Manager") + 1;
    *(uint16_t*)bcc_ptr = w - data_start;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    g_app.uid = ((SMB1Header*)pkt)->uid; uint32_t status = ((SMB1Header*)pkt)->status;
    return (status == 0);
}

static int smb_tree_connect(const char *server, const char *share) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt));
    SMB1Header *hdr = smb_build_header(pkt, 0x75); hdr->flags2 |= 0x8000; hdr->tid = 0xFFFF;             
    memcpy(hdr->signature, g_app.g_session_response, 8); uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 4; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 1; w += 2;     
    char path[MAX_SMB_PATH]; const char *clean_share = (share[0] == '\\' || share[0] == '/') ? share + 1 : share;
    snprintf(path, sizeof(path), "\\\\%s\\%s", server, clean_share);
    uint8_t path_utf16[MAX_SMB_PATH * 2]; size_t path_len_utf16 = utf8_to_utf16le(path, path_utf16, sizeof(path_utf16));
    uint16_t byte_count = 1 + path_len_utf16 + 2 + 6; *(uint16_t*)w = byte_count; w += 2; *w++ = 0;                      
    memcpy(w, path_utf16, path_len_utf16); w += path_len_utf16; *w++ = 0; *w++ = 0; strcpy((char*)w, "?????"); w += 6; 
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    g_app.tid = ((SMB1Header*)pkt)->tid; uint32_t status = ((SMB1Header*)pkt)->status;
    return (status == 0);
}

static int smb_simple_path_cmd(uint8_t cmd, const char *path) {
    uint8_t pkt[MAX_SMB_PATH+100]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, cmd); uint8_t *w = pkt + sizeof(SMB1Header);
    if (cmd == 0x06) { *w++ = 1; *(uint16_t*)w = 0x16; w+=2; } else { *w++ = 0; }
    *(uint16_t*)w = strlen(path)+2; w+=2; *w++ = 0x04; strcpy((char*)w, path); w+=strlen(path)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_delete(const char *path) { return smb_simple_path_cmd(0x06, path); }
static int smb_delete_dir(const char *path) { return smb_simple_path_cmd(0x01, path); }

static int smb_rename(const char *oldp, const char *newp) {
    uint8_t pkt[MAX_SMB_PATH*2+100]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x07); uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 1; *(uint16_t*)w = 0x16; w+=2; *(uint16_t*)w = strlen(oldp) + strlen(newp) + 4; w+=2;
    *w++ = 0x04; strcpy((char*)w, oldp); w+=strlen(oldp)+1; *w++ = 0x04; strcpy((char*)w, newp); w+=strlen(newp)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0; size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_list_directory(void) {
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB1Header *hdr = smb_build_header(packet, 0x32); hdr->tid = g_app.tid; hdr->flags2 |= 0x8000; 
    uint8_t *vwv = packet + sizeof(SMB1Header); *vwv++ = 15; 
    uint8_t *bcc_ptr = vwv + 15 * 2; uint8_t *data_start = bcc_ptr + 2; uint8_t *param_ptr = data_start;
    if ((param_ptr - packet) % 2 != 0) { param_ptr++; }
    uint8_t *p = param_ptr;
    *(uint16_t*)p = 0x0016; p += 2; *(uint16_t*)p = 256; p += 2; *(uint16_t*)p = 0x0002; p += 2; *(uint16_t*)p = 0x0104; p += 2; *(uint32_t*)p = 0; p += 4; 
    char search_pattern[MAX_SMB_PATH]; size_t rlen_base = strlen(g_app.remote_base);
    if (g_app.remote_base[rlen_base - 1] == '\\' || g_app.remote_base[rlen_base - 1] == '/') { snprintf(search_pattern, sizeof(search_pattern), "%s*", g_app.remote_base); } 
    else { snprintf(search_pattern, sizeof(search_pattern), "%s\\*", g_app.remote_base); }
    normalize_path(search_pattern, 0);
    uint8_t pattern_utf16[MAX_SMB_PATH * 2]; size_t pat_len_utf16 = utf8_to_utf16le(search_pattern, pattern_utf16, sizeof(pattern_utf16));
    memcpy(p, pattern_utf16, pat_len_utf16); p += pat_len_utf16; *p++ = 0; *p++ = 0; 
    uint16_t param_count = p - param_ptr; uint16_t data_count = 0; uint8_t *v = vwv;
    *(uint16_t*)v = param_count; v += 2; *(uint16_t*)v = data_count; v += 2; *(uint16_t*)v = 1024; v += 2; *(uint16_t*)v = 32768; v += 2; *v++ = 1; *v++ = 0;                  
    *(uint16_t*)v = 0; v += 2; *(uint32_t*)v = 0; v += 4; *(uint16_t*)v = 0; v += 2; *(uint16_t*)v = param_count; v += 2; *(uint16_t*)v = param_ptr - packet; v += 2; *(uint16_t*)v = data_count; v += 2; *(uint16_t*)v = p - packet; v += 2; *v++ = 1; *v++ = 0;                  
    *(uint16_t*)v = 0x0001; v += 2; *(uint16_t*)bcc_ptr = p - data_start;
    if (!smb_send_packet(packet, p - packet)) return 0;
    size_t rlen; if (!smb_recv_packet(packet, sizeof(packet), &rlen)) return 0;
    if (((SMB1Header*)packet)->status != 0) return 0;
    uint8_t wct = *(packet + sizeof(SMB1Header)); if (wct < 10) return 0;
    uint16_t *vwv_words = (uint16_t*)(packet + sizeof(SMB1Header) + 1);
    uint16_t param_off = vwv_words[4]; uint16_t data_off = vwv_words[7]; uint16_t data_cnt = vwv_words[6];
    if (param_off > 0 && data_off > 0 && data_cnt > 0) {
        uint8_t *data_ptr = packet + data_off; uint8_t *data_end = data_ptr + data_cnt;
        while (data_ptr < data_end) {
            uint32_t next_offset = *(uint32_t*)(data_ptr + 0); uint32_t file_attrs = *(uint32_t*)(data_ptr + 56);
            uint32_t name_len = *(uint32_t*)(data_ptr + 60); uint8_t *name_unicode = data_ptr + 94;
            if (name_len > 0 && data_ptr + 94 + name_len <= data_end) {
                char item_name[256] = {0}; int char_idx = 0;
                for (uint32_t i = 0; i < name_len && char_idx < 255; i += 2) item_name[char_idx++] = (char)*(name_unicode + i);
                item_name[char_idx] = '\0';
                if (strcmp(item_name, ".") != 0 && strcmp(item_name, "..") != 0 && g_app.remote_count < MAX_ITEMS) {
                    strncpy(g_app.remote_items[g_app.remote_count].path, item_name, MAX_SMB_PATH - 1);
                    g_app.remote_items[g_app.remote_count].is_dir = (file_attrs & 0x10) ? 1 : 0; g_app.remote_count++;
                }
            }
            if (next_offset == 0) break; data_ptr += next_offset;
        }
    }
    return 1;
}

/* ==========================================================================
   SMB2 PROTOCOL
   ========================================================================== */
static int smb2_negotiate(void) {
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_NEGOTIATE);
    SMB2NegotiateReq *neg = (SMB2NegotiateReq*)(packet + sizeof(SMB2Header));
    neg->structure_size = 36; neg->dialect_count = 3; neg->security_mode = 1; neg->capabilities = 0;
    get_random_bytes(neg->client_guid, 16);
    uint16_t *dialects = (uint16_t*)(packet + sizeof(SMB2Header) + sizeof(SMB2NegotiateReq));
    dialects[0] = SMB2_DIALECT_0202; dialects[1] = SMB2_DIALECT_0210; dialects[2] = SMB2_DIALECT_0300;
    size_t pkt_len = sizeof(SMB2Header) + sizeof(SMB2NegotiateReq) + (neg->dialect_count * sizeof(uint16_t));
    if (!smb_send_packet(packet, pkt_len)) return 0;
    size_t recv_len; if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) return 0;
    hdr = (SMB2Header*)packet; if (hdr->status != 0 && hdr->status != STATUS_SUCCESS) return 0;
    SMB2NegotiateResp *resp = (SMB2NegotiateResp*)(packet + sizeof(SMB2Header));
    memcpy(g_app.smb2_server_guid, resp->server_guid, 16); 
    return 1;
}

static int smb2_session_setup(const char *user, const char *pass) {
    HMODULE hSec = LoadLibraryA("secur32.dll");
    if (!hSec) return 0;
    INIT_SECURITY_INTERFACE_A pInitSec = (INIT_SECURITY_INTERFACE_A)GetProcAddress(hSec, "InitSecurityInterfaceA");
    if (!pInitSec) { FreeLibrary(hSec); return 0; }
    PSecurityFunctionTableA sspi = pInitSec();
    if (!sspi) { FreeLibrary(hSec); return 0; }
    
    SEC_WINNT_AUTH_IDENTITY_A auth_id; memset(&auth_id, 0, sizeof(auth_id));
    char domain[64] = ""; char uname[64] = ""; const char *slash = strchr(user, '\\');
    if (slash) { size_t dlen = slash - user; if (dlen < sizeof(domain)) { strncpy(domain, user, dlen); domain[dlen] = '\0'; } strcpy(uname, slash + 1); } 
    else { strcpy(uname, user); }
    auth_id.User = (unsigned char*)uname; auth_id.UserLength = (unsigned long)strlen(uname);
    auth_id.Domain = domain[0] ? (unsigned char*)domain : NULL; auth_id.DomainLength = (unsigned long)strlen(domain);
    auth_id.Password = (unsigned char*)pass; auth_id.PasswordLength = (unsigned long)strlen(pass);
    auth_id.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    void *pAuthData = (strlen(user) > 0) ? &auth_id : NULL;
    
    CredHandle hCred; TimeStamp ts;
    SECURITY_STATUS stat = sspi->AcquireCredentialsHandleA(NULL, "NTLM", SECPKG_CRED_OUTBOUND, NULL, pAuthData, NULL, NULL, &hCred, &ts);
    if (stat != SEC_E_OK) { FreeLibrary(hSec); return 0; }
    
    CtxtHandle hCtx; memset(&hCtx, 0, sizeof(hCtx));
    SecBufferDesc out_desc; SecBuffer out_buf; uint8_t sec_payload[4096];
    out_buf.BufferType = SECBUFFER_TOKEN; out_buf.cbBuffer = sizeof(sec_payload); out_buf.pvBuffer = sec_payload;
    out_desc.cBuffers = 1; out_desc.pBuffers = &out_buf; out_desc.ulVersion = SECBUFFER_VERSION;
    
    ULONG ctx_attrs; ULONG req_flags = ISC_REQ_CONNECTION | ISC_REQ_USE_DCE_STYLE | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT;
    char target_name[256]; snprintf(target_name, sizeof(target_name), "cifs/%s", g_app.pending_server[0] ? g_app.pending_server : g_app.connections[g_app.selected_conn_idx].server);

    stat = sspi->InitializeSecurityContextA(&hCred, NULL, (SEC_CHAR*)target_name, req_flags, 0, SECURITY_NATIVE_DREP, NULL, 0, &hCtx, &out_desc, &ctx_attrs, &ts);
    if (stat != SEC_I_CONTINUE_NEEDED && stat != SEC_E_OK) { sspi->FreeCredentialsHandle(&hCred); FreeLibrary(hSec); return 0; }
    
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_SESSION_SETUP);
    SMB2SessionSetupReq *setup_req = (SMB2SessionSetupReq*)(packet + sizeof(SMB2Header));
    setup_req->structure_size = 25; setup_req->flags = 0; setup_req->security_mode = 1; setup_req->channel = 0; setup_req->previous_session_id = 0;
    
    uint8_t *payload_ptr = packet + sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    memcpy(payload_ptr, out_buf.pvBuffer, out_buf.cbBuffer);
    setup_req->security_buffer_offset = sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    setup_req->security_buffer_length = (uint16_t)out_buf.cbBuffer;
    size_t pkt_len = setup_req->security_buffer_offset + out_buf.cbBuffer;
    if (!smb_send_packet(packet, pkt_len)) goto cleanup;
    
    size_t recv_len; uint8_t response[SMB_BUFFER_SIZE];
    if (!smb_recv_packet(response, sizeof(response), &recv_len)) goto cleanup;
    
    hdr = (SMB2Header*)response;
    if (hdr->status != STATUS_MORE_PROCESSING) goto cleanup;
    g_app.smb2_session_id = hdr->session_id;
    
    uint16_t sec_offset = *(uint16_t*)(response + 68); uint16_t sec_len = *(uint16_t*)(response + 70);
    if (sec_offset + sec_len > recv_len || sec_offset < 72) goto cleanup;

    SecBufferDesc in_desc; SecBuffer in_buf;
    in_buf.BufferType = SECBUFFER_TOKEN; in_buf.cbBuffer = sec_len; in_buf.pvBuffer = response + sec_offset;
    in_desc.cBuffers = 1; in_desc.pBuffers = &in_buf; in_desc.ulVersion = SECBUFFER_VERSION;
    
    out_buf.cbBuffer = sizeof(sec_payload); out_buf.pvBuffer = sec_payload;
    stat = sspi->InitializeSecurityContextA(&hCred, &hCtx, (SEC_CHAR*)target_name, req_flags, 0, SECURITY_NATIVE_DREP, &in_desc, 0, &hCtx, &out_desc, &ctx_attrs, &ts);
    if (stat != SEC_E_OK) goto cleanup;
    
    memset(packet, 0, sizeof(packet)); hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_SESSION_SETUP);
    hdr->session_id = g_app.smb2_session_id;
    setup_req = (SMB2SessionSetupReq*)(packet + sizeof(SMB2Header));
    setup_req->structure_size = 25; setup_req->flags = 0; setup_req->security_mode = 1; setup_req->channel = 0; setup_req->previous_session_id = 0;
    
    payload_ptr = packet + sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    memcpy(payload_ptr, out_buf.pvBuffer, out_buf.cbBuffer);
    setup_req->security_buffer_offset = sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    setup_req->security_buffer_length = (uint16_t)out_buf.cbBuffer;
    pkt_len = setup_req->security_buffer_offset + out_buf.cbBuffer;
    
    if (!smb_send_packet(packet, pkt_len)) goto cleanup;
    if (!smb_recv_packet(response, sizeof(response), &recv_len)) goto cleanup;
    
    hdr = (SMB2Header*)response;
    sspi->DeleteSecurityContext(&hCtx); sspi->FreeCredentialsHandle(&hCred); FreeLibrary(hSec);
    if (hdr->status != STATUS_SUCCESS) return 0;
    return 1;
    
cleanup:
    sspi->DeleteSecurityContext(&hCtx); sspi->FreeCredentialsHandle(&hCred); FreeLibrary(hSec); return 0;
}

static int smb2_tree_connect(const char *server, const char *share) {
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_TREE_CONNECT);
    SMB2TreeConnectReq *tc = (SMB2TreeConnectReq*)(packet + sizeof(SMB2Header));
    tc->structure_size = 9; tc->reserved = 0;
    char full_path[MAX_SMB_PATH]; const char *clean_share = (share[0] == '\\' || share[0] == '/') ? share + 1 : share;
    snprintf(full_path, sizeof(full_path), "\\\\%s\\%s", server, clean_share);
    uint8_t *path_pos = packet + sizeof(SMB2Header) + sizeof(SMB2TreeConnectReq);
    tc->path_offset = sizeof(SMB2Header) + sizeof(SMB2TreeConnectReq);
    tc->path_length = (uint16_t)utf8_to_utf16le(full_path, path_pos, SMB_BUFFER_SIZE - tc->path_offset);
    size_t pkt_len = tc->path_offset + tc->path_length;
    if (!smb_send_packet(packet, pkt_len)) return 0;
    size_t recv_len; if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) return 0;
    hdr = (SMB2Header*)packet; if (hdr->status != STATUS_SUCCESS) return 0;
    g_app.smb2_tree_id = hdr->tree_id; return 1;
}

static int smb2_tree_disconnect(void) {
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_TREE_DISCONNECT);
    uint16_t *struct_size = (uint16_t*)(packet + sizeof(SMB2Header));
    *struct_size = 4; *(struct_size + 1) = 0; 
    if (!smb_send_packet(packet, sizeof(SMB2Header) + 4)) return 0;
    size_t recv_len; return smb_recv_packet(packet, sizeof(packet), &recv_len);
}

/* ==========================================================================
   SHARE ENUMERATION
   ========================================================================== */
static int smb2_ipc_enum_shares(const char *server, char (*shares)[64], int max_shares) {
    if (!smb2_tree_connect(server, "IPC$")) return 0;
    uint8_t pkt[SMB_BUFFER_SIZE]; size_t rlen; memset(pkt, 0, sizeof(pkt));
    SMB2Header *hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CREATE);
    SMB2CreateReq *cr = (SMB2CreateReq*)(pkt + sizeof(SMB2Header));
    cr->structure_size = 57; cr->impersonation_level = 2; cr->desired_access = 0x0012019F; cr->file_attributes = 0;
    cr->share_access = 0x07; cr->create_disposition = 1; cr->create_options = 0; cr->name_offset = 120;
    cr->name_length = (uint16_t)utf8_to_utf16le("srvsvc", pkt + 120, 256);
    if (!smb_send_packet(pkt, 120 + cr->name_length)) return 0;
    if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    hdr = (SMB2Header*)pkt; if (hdr->status != 0) { smb2_tree_disconnect(); return 0; }
    SMB2CreateResp *cresp = (SMB2CreateResp*)(pkt + sizeof(SMB2Header));
    uint64_t fid_pers = cresp->file_id_persistent; uint64_t fid_vol = cresp->file_id_volatile;
    
    uint8_t bind_req[] = { 0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88, 0x03, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2WriteReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_WRITE);
    SMB2WriteReq *wr = (SMB2WriteReq*)(pkt + sizeof(SMB2Header)); wr->structure_size = 49; wr->data_offset = 112; wr->length = sizeof(bind_req); wr->file_id_persistent = fid_pers; wr->file_id_volatile = fid_vol;
    memcpy(pkt + 112, bind_req, sizeof(bind_req));
    if (!smb_send_packet(pkt, 112 + sizeof(bind_req))) return 0;
    if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2ReadReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_READ);
    SMB2ReadReq *rr = (SMB2ReadReq*)(pkt + sizeof(SMB2Header)); rr->structure_size = 49; rr->length = 1024; rr->file_id_persistent = fid_pers; rr->file_id_volatile = fid_vol;
    if (!smb_send_packet(pkt, sizeof(SMB2Header) + 49)) return 0;
    if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    
    uint8_t enum_req[] = { 0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2WriteReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_WRITE);
    wr = (SMB2WriteReq*)(pkt + sizeof(SMB2Header)); wr->structure_size = 49; wr->data_offset = 112; wr->length = sizeof(enum_req); wr->file_id_persistent = fid_pers; wr->file_id_volatile = fid_vol;
    memcpy(pkt + 112, enum_req, sizeof(enum_req));
    if (!smb_send_packet(pkt, 112 + sizeof(enum_req))) return 0;
    if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2ReadReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_READ);
    rr = (SMB2ReadReq*)(pkt + sizeof(SMB2Header)); rr->structure_size = 49; rr->length = 65536; rr->file_id_persistent = fid_pers; rr->file_id_volatile = fid_vol;
    if (!smb_send_packet(pkt, sizeof(SMB2Header) + 49)) return 0;
    if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    
    int count = 0; hdr = (SMB2Header*)pkt;
    if (hdr->status == 0) {
        SMB2ReadResp *rresp = (SMB2ReadResp*)(pkt + sizeof(SMB2Header));
        if (rresp->data_length > 24) {
            uint8_t *payload = pkt + rresp->data_offset; uint8_t *ptr = payload + 24; 
            uint32_t level = *(uint32_t*)ptr; ptr+=4; uint32_t sw_val = *(uint32_t*)ptr; ptr+=4; uint32_t ptr_ctr = *(uint32_t*)ptr; ptr+=4;
            if (ptr_ctr && ptr + 8 <= payload + rresp->data_length) {
                uint32_t ent_read = *(uint32_t*)ptr; ptr+=4; uint32_t ptr_arr = *(uint32_t*)ptr; ptr+=4;
                if (ptr_arr && ent_read > 0 && ptr + 4 <= payload + rresp->data_length) {
                    uint32_t max_c = *(uint32_t*)ptr; ptr+=4; uint32_t act_c = ent_read;
                    if (act_c < 1000 && ptr + act_c * 12 <= payload + rresp->data_length) {
                        uint32_t *n_ptrs = (uint32_t*)malloc(act_c * 4); uint32_t *types = (uint32_t*)malloc(act_c * 4); uint32_t *r_ptrs = (uint32_t*)malloc(act_c * 4);
                        for(uint32_t i=0; i<act_c; i++) { n_ptrs[i] = *(uint32_t*)ptr; ptr+=4; types[i] = *(uint32_t*)ptr; ptr+=4; r_ptrs[i] = *(uint32_t*)ptr; ptr+=4; }
                        for(uint32_t i=0; i<act_c; i++) {
                            if (n_ptrs[i] && ptr + 12 <= payload + rresp->data_length) {
                                uint32_t sm = *(uint32_t*)ptr; ptr+=4; uint32_t so = *(uint32_t*)ptr; ptr+=4; uint32_t sa = *(uint32_t*)ptr; ptr+=4;
                                if (ptr + sa * 2 <= payload + rresp->data_length) { 
                                    if ((types[i] & 0xFF) == 0) { 
                                        char sname[64] = {0}; int idx = 0;
                                        for(uint32_t c=0; c<sa; c++) { uint16_t wc = *(uint16_t*)ptr; if (wc != 0 && idx < 63) { sname[idx++] = (char)wc; } ptr+=2; }
                                        sname[idx] = '\0';
                                        if (strlen(sname) > 0 && sname[strlen(sname)-1] != '$' && count < max_shares) { strcpy(shares[count++], sname); }
                                    } else { ptr += sa * 2; }
                                }
                                if ((ptr - payload) % 4 != 0) ptr += 4 - ((ptr - payload) % 4);
                            }
                            if (r_ptrs[i] && ptr + 12 <= payload + rresp->data_length) {
                                uint32_t sm = *(uint32_t*)ptr; ptr+=4; uint32_t so = *(uint32_t*)ptr; ptr+=4; uint32_t sa = *(uint32_t*)ptr; ptr+=4;
                                ptr += sa * 2; if ((ptr - payload) % 4 != 0) ptr += 4 - ((ptr - payload) % 4);
                            }
                        }
                        free(n_ptrs); free(types); free(r_ptrs);
                    }
                }
            }
        }
    }
    
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2CloseReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CLOSE);
    SMB2CloseReq *cl = (SMB2CloseReq*)(pkt + sizeof(SMB2Header)); cl->structure_size = 24; cl->file_id_persistent = fid_pers; cl->file_id_volatile = fid_vol;
    smb_send_packet(pkt, sizeof(SMB2Header) + 24); smb_recv_packet(pkt, sizeof(pkt), &rlen);
    smb2_tree_disconnect(); return count;
}

static int enum_shares_ipc(char (*shares)[64], int max_shares) {
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB1Header *hdr = smb_build_header(packet, 0x75); hdr->flags2 |= 0x8000; hdr->tid = 0xFFFF;
    uint8_t *w = packet + sizeof(SMB1Header); *w++ = 4; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 1; w += 2;     
    char ipc_share[256]; snprintf(ipc_share, sizeof(ipc_share), "\\\\%s\\IPC$", g_app.pending_server);
    uint8_t path_utf16[MAX_SMB_PATH * 2]; size_t path_len_utf16 = utf8_to_utf16le(ipc_share, path_utf16, sizeof(path_utf16));
    uint16_t byte_count = 1 + path_len_utf16 + 2 + 6; *(uint16_t*)w = byte_count; w += 2; *w++ = 0;                      
    memcpy(w, path_utf16, path_len_utf16); w += path_len_utf16; *w++ = 0; *w++ = 0; strcpy((char*)w, "?????"); w += 6;
    if (!smb_send_packet(packet, w - packet)) return 0; size_t rlen; if (!smb_recv_packet(packet, sizeof(packet), &rlen)) return 0;
    if (((SMB1Header*)packet)->status != 0) return 0;
    g_app.tid = ((SMB1Header*)packet)->tid;
    memset(packet, 0, sizeof(packet)); hdr = smb_build_header(packet, 0x25); hdr->tid = g_app.tid;
    uint8_t *vwv = packet + sizeof(SMB1Header); *vwv++ = 14; 
    uint8_t *bcc_ptr = vwv + 14 * 2; uint8_t *data_start = bcc_ptr + 2; uint8_t *name_ptr = data_start;
    strcpy((char*)name_ptr, "\\PIPE\\LANMAN"); uint16_t name_len = strlen("\\PIPE\\LANMAN") + 1;
    uint8_t *param_ptr = name_ptr + name_len; uint8_t *p = param_ptr;
    *(uint16_t*)p = 0x0000; p += 2; strcpy((char*)p, "WrLeh"); p += 6; strcpy((char*)p, "B13BWz"); p += 7; *(uint16_t*)p = 0x0001; p += 2; *(uint16_t*)p = 0xFFFF; p += 2;      
    uint16_t param_count = p - param_ptr; uint16_t data_count = 0; uint8_t *v = vwv;
    *(uint16_t*)v = param_count; v += 2; *(uint16_t*)v = data_count; v += 2; *(uint16_t*)v = 1024; v += 2; *(uint16_t*)v = 65535; v += 2; *v++ = 0; *v++ = 0; *(uint16_t*)v = 0; v += 2; *(uint32_t*)v = 0; v += 4; *(uint16_t*)v = 0; v += 2; *(uint16_t*)v = param_count; v += 2; *(uint16_t*)v = param_ptr - packet; v += 2; *(uint16_t*)v = data_count; v += 2; *(uint16_t*)v = 0; v += 2; *v++ = 0; *v++ = 0;                  
    *(uint16_t*)bcc_ptr = p - data_start;
    if (!smb_send_packet(packet, p - packet)) return 0; if (!smb_recv_packet(packet, sizeof(packet), &rlen)) return 0;
    uint8_t wct = *(packet + sizeof(SMB1Header)); if (wct < 10) return 0;
    uint16_t *vwv_words = (uint16_t*)(packet + sizeof(SMB1Header) + 1); uint16_t param_off = vwv_words[4]; uint16_t data_off  = vwv_words[7];
    int count = 0;
    if (param_off > 0 && data_off > 0) {
        uint16_t *resp_param_words = (uint16_t*)(packet + param_off); uint16_t status = resp_param_words[0]; uint16_t entries_returned = resp_param_words[2];
        if (status == 0 || status == 234) { 
            uint8_t *data = packet + data_off;
            for (int i = 0; i < entries_returned && count < max_shares && data + (i * 20) + 13 <= packet + rlen; i++) {
                char share_name[14]; memcpy(share_name, data + (i * 20), 13); share_name[13] = '\0';
                for (int j = 12; j >= 0; j--) { if (share_name[j] == ' ') share_name[j] = '\0'; else if (share_name[j] != '\0') break; }
                if (share_name[0] != '\0' && strcmp(share_name, "ADMIN$") != 0 && strcmp(share_name, "IPC$") != 0) { strcpy(shares[count++], share_name); }
            }
        }
    }
    return count;
}

static int enumerate_shares(char (*shares)[64], int max_shares, int is_smb2_capable) {
    int count = 0;
    if (is_smb2_capable) {
        count = smb2_ipc_enum_shares(g_app.pending_server, shares, max_shares);
        if (count > 0) return count;
    }
    count = enum_shares_ipc(shares, max_shares);
    if (count > 0) return count;
    char *fallback_shares[] = {"shared", "public", "data", "files", "documents", "home"};
    int num_fallback = sizeof(fallback_shares) / sizeof(fallback_shares[0]);
    for (int i = 0; i < num_fallback && i < max_shares; i++) strcpy(shares[i], fallback_shares[i]);
    return num_fallback;
}

/* ==========================================================================
   SMB1/SMB2/FTP PATH FORMATTING & OPERATIONS
   ========================================================================== */
static void format_folder_path(char *dst, size_t max_len, const char *base_dir, const char *new_dir, int is_ftp)
{
    char sep = is_ftp ? '/' : '\\';
    char wrong = is_ftp ? '\\' : '/';
    char clean_new[MAX_SMB_PATH];
    
    strncpy(clean_new, new_dir, sizeof(clean_new) - 1);
    clean_new[sizeof(clean_new) - 1] = '\0';
    
    for (char *p = clean_new; *p; ++p) { if (*p == wrong) *p = sep; }

    if (!base_dir || base_dir[0] == '\0' || ((base_dir[0] == '/' || base_dir[0] == '\\') && base_dir[1] == '\0')) {
        const char *np = clean_new; while (*np == sep) np++;
        if (is_ftp) snprintf(dst, max_len, "/%s", np); else snprintf(dst, max_len, "\\%s", np);
    } else {
        char clean_base[MAX_SMB_PATH_LEN]; strncpy(clean_base, base_dir, sizeof(clean_base) - 1); clean_base[sizeof(clean_base) - 1] = '\0';
        for (char *p = clean_base; *p; ++p) { if (*p == wrong) *p = sep; }
        size_t blen = strlen(clean_base); while (blen > 0 && clean_base[blen - 1] == sep) { clean_base[--blen] = '\0'; }
        const char *np = clean_new; while (*np == sep) np++;
        snprintf(dst, max_len, "%s%c%s", clean_base, sep, np);
    }
}

static int smb_mkdir_ex(const char *parent_dir, const char *dirname) {
    char target_path[MAX_SMB_PATH]; format_folder_path(target_path, sizeof(target_path), parent_dir, dirname, 0);
    uint8_t pkt[MAX_SMB_PATH + 100]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x00);
    uint8_t *w = pkt + sizeof(SMB1Header); *w++ = 0;
    uint16_t byte_count = (uint16_t)(strlen(target_path) + 2); *(uint16_t*)w = byte_count; w += 2; *w++ = 0x04; strcpy((char*)w, target_path); w += strlen(target_path) + 1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    uint32_t status = ((SMB1Header*)pkt)->status;
    if (status == 0 || status == 0xC0000035) return 1; return 0;
}

static int ftp_mkdir_ex(const char *parent_dir, const char *dirname) {
    char target_path[MAX_SMB_PATH]; format_folder_path(target_path, sizeof(target_path), parent_dir, dirname, 1);
    if (FtpCreateDirectoryA(g_app.hFtpSession, target_path)) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 1; return 0;
}

static int smb2_list_directory(void) {
    uint8_t packet[SMB_BUFFER_SIZE]; memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_CREATE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CreateReq *create = (SMB2CreateReq*)(packet + sizeof(SMB2Header));
    create->structure_size = 57; create->impersonation_level = 2;      
    create->desired_access = 0x00100081; create->file_attributes = 0x00000010; create->share_access = 0x00000007; 
    create->create_disposition = 1; create->create_options = 0x00000021; create->name_offset = 120;
    
    char rel_path[MAX_SMB_PATH] = "";
    if (g_app.remote_base[0] != '\0' && strcmp(g_app.remote_base, "\\") != 0 && strcmp(g_app.remote_base, "/") != 0) {
        const char *p = g_app.remote_base; if (*p == '\\' || *p == '/') p++;
        strcpy(rel_path, p); int len = strlen(rel_path); while (len > 0 && (rel_path[len-1] == '\\' || rel_path[len-1] == '/')) { rel_path[len-1] = '\0'; len--; }
    }
    create->name_length = (uint16_t)utf8_to_utf16le(rel_path, packet + 120, SMB_BUFFER_SIZE - 120);
    size_t pkt_len = 120 + create->name_length; if (create->name_length == 0) { packet[120] = 0; packet[121] = 0; pkt_len = 122; }

    if (!smb_send_packet(packet, pkt_len)) return 0;
    size_t recv_len; if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) return 0;
    hdr = (SMB2Header*)packet; if (hdr->status != STATUS_SUCCESS) return 0;

    SMB2CreateResp *create_resp = (SMB2CreateResp*)(packet + sizeof(SMB2Header));
    uint64_t file_id_pers = create_resp->file_id_persistent; uint64_t file_id_vol  = create_resp->file_id_volatile;
    int keep_querying = 1, first_query = 1;

    while (keep_querying && g_app.remote_count < MAX_ITEMS) {
        memset(packet, 0, sizeof(SMB2Header) + 128); hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_QUERY_DIRECTORY); hdr->tree_id = g_app.smb2_tree_id;
        SMB2QueryDirReqFixed *qdir = (SMB2QueryDirReqFixed*)(packet + sizeof(SMB2Header));
        qdir->structure_size = 33; qdir->file_information_class = 37; qdir->flags = first_query ? 0x01 : 0x00; first_query = 0;
        qdir->file_id_persistent = file_id_pers; qdir->file_id_volatile = file_id_vol; qdir->output_buffer_length = 65536; qdir->name_offset = 96; 
        *(uint16_t*)(packet + 96) = '*'; qdir->name_length = 2; pkt_len = 96 + 2;
        
        if (!smb_send_packet(packet, pkt_len)) break;
        if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) break;

        hdr = (SMB2Header*)packet;
        if (hdr->status == STATUS_SUCCESS) {
            uint16_t data_off = *(uint16_t*)(packet + sizeof(SMB2Header) + 2); uint32_t data_len = *(uint32_t*)(packet + sizeof(SMB2Header) + 4);
            if (data_off > 0 && data_len > 0 && (data_off + data_len <= recv_len)) {
                uint8_t *data_ptr = packet + data_off; uint8_t *data_end = data_ptr + data_len;
                while (data_ptr + 104 <= data_end) {
                    uint32_t next_offset = *(uint32_t*)(data_ptr + 0); uint32_t file_attrs = *(uint32_t*)(data_ptr + 56);
                    uint32_t name_len = *(uint32_t*)(data_ptr + 60); uint8_t *name_unicode = data_ptr + 104; 
                    if (name_len > 0 && name_unicode + name_len <= data_end) {
                        char item_name[256] = {0}; int char_idx = 0;
                        for (uint32_t i = 0; i < name_len && char_idx < 255; i += 2) { item_name[char_idx++] = (char)*(name_unicode + i); }
                        item_name[char_idx] = '\0';
                        if (strcmp(item_name, ".") != 0 && strcmp(item_name, "..") != 0 && g_app.remote_count < MAX_ITEMS) {
                            strncpy(g_app.remote_items[g_app.remote_count].path, item_name, MAX_SMB_PATH - 1);
                            g_app.remote_items[g_app.remote_count].is_dir = (file_attrs & 0x10) ? 1 : 0; g_app.remote_count++;
                        }
                    }
                    if (next_offset == 0) break; data_ptr += next_offset;
                }
            } else { keep_querying = 0; }
        } else { keep_querying = 0; }
    }

    memset(packet, 0, sizeof(packet)); hdr = (SMB2Header*)packet; smb2_init_header(hdr, SMB2_CLOSE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CloseReq *cl = (SMB2CloseReq*)(packet + sizeof(SMB2Header)); cl->structure_size = 24; 
    cl->file_id_persistent = file_id_pers; cl->file_id_volatile = file_id_vol; 
    smb_send_packet(packet, sizeof(SMB2Header) + 24); smb_recv_packet(packet, sizeof(packet), &recv_len);
    return 1;
}

static int smb2_mkdir(const char *rpath) {
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB2Header *hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CREATE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CreateReq *create = (SMB2CreateReq*)(pkt + sizeof(SMB2Header));
    create->structure_size = 57; create->impersonation_level = 2; create->desired_access = 0x00120116; 
    create->file_attributes = 0x00000010; create->share_access = 0x07; create->create_disposition = 2; 
    create->create_options = 0x00000021; create->name_offset = 120;
    
    char rel_path[MAX_SMB_PATH]; const char *p = rpath; while (*p == '\\' || *p == '/') p++; strcpy(rel_path, p);
    create->name_length = (uint16_t)utf8_to_utf16le(rel_path, pkt + 120, SMB_BUFFER_SIZE - 120);
    size_t pkt_len = 120 + create->name_length; if (create->name_length == 0) { pkt[120] = 0; pkt[121] = 0; pkt_len = 122; }
    
    if (!smb_send_packet(pkt, pkt_len)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    hdr = (SMB2Header*)pkt;
    
    if (hdr->status == 0 || hdr->status == 0xC0000035) {
        SMB2CreateResp *cresp = (SMB2CreateResp*)(pkt + sizeof(SMB2Header));
        uint64_t fid_pers = cresp->file_id_persistent; uint64_t fid_vol = cresp->file_id_volatile;
        memset(pkt, 0, sizeof(pkt)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CLOSE); hdr->tree_id = g_app.smb2_tree_id;
        SMB2CloseReq *cl = (SMB2CloseReq*)(pkt + sizeof(SMB2Header)); cl->structure_size = 24; cl->file_id_persistent = fid_pers; cl->file_id_volatile = fid_vol;
        smb_send_packet(pkt, sizeof(SMB2Header) + 24); smb_recv_packet(pkt, sizeof(pkt), &rlen); return 1;
    } return 0;
}

static int smb2_delete_internal(const char* rpath, int is_dir) {
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB2Header *hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CREATE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CreateReq *create = (SMB2CreateReq*)(pkt + sizeof(SMB2Header));
    create->structure_size = 57; create->impersonation_level = 2; create->desired_access = 0x00010000; create->file_attributes = 0;
    create->share_access = 0x07; create->create_disposition = 1; create->create_options = 0x00001000 | (is_dir ? 0x00000021 : 0); create->name_offset = 120;
    
    char rel_path[MAX_SMB_PATH]; const char *p = rpath; if (*p == '\\' || *p == '/') p++; strcpy(rel_path, p);
    create->name_length = (uint16_t)utf8_to_utf16le(rel_path, pkt + 120, SMB_BUFFER_SIZE - 120);
    int pkt_len = 120 + create->name_length; if (create->name_length == 0) { pkt[120]=0; pkt[121]=0; pkt_len=122; }
    
    if (!smb_send_packet(pkt, pkt_len)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    hdr = (SMB2Header*)pkt;
    
    if (hdr->status == 0) {
        SMB2CreateResp *cresp = (SMB2CreateResp*)(pkt + sizeof(SMB2Header));
        uint64_t fid_pers = cresp->file_id_persistent; uint64_t fid_vol = cresp->file_id_volatile;
        memset(pkt, 0, sizeof(pkt)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CLOSE); hdr->tree_id = g_app.smb2_tree_id;
        SMB2CloseReq *cl = (SMB2CloseReq*)(pkt + sizeof(SMB2Header)); cl->structure_size = 24; cl->file_id_persistent = fid_pers; cl->file_id_volatile = fid_vol;
        smb_send_packet(pkt, sizeof(SMB2Header) + 24); smb_recv_packet(pkt, sizeof(pkt), &rlen); return 1;
    } return 0;
}

static int smb2_rename(const char *oldp, const char *newp) {
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB2Header *hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CREATE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CreateReq *create = (SMB2CreateReq*)(pkt + sizeof(SMB2Header));
    create->structure_size = 57; create->impersonation_level = 2; create->desired_access = 0x00110080; create->file_attributes = 0;
    create->share_access = 0x07; create->create_disposition = 1; create->create_options = 0; create->name_offset = 120;
    char rel_path[MAX_SMB_PATH]; const char *p = oldp; if (*p == '\\' || *p == '/') p++; strcpy(rel_path, p);
    create->name_length = (uint16_t)utf8_to_utf16le(rel_path, pkt + 120, SMB_BUFFER_SIZE - 120);
    int pkt_len = 120 + create->name_length; if (create->name_length == 0) { pkt[120]=0; pkt[121]=0; pkt_len=122; }
    
    if (!smb_send_packet(pkt, pkt_len)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    hdr = (SMB2Header*)pkt;
    
    if (hdr->status == 0) {
        SMB2CreateResp *cresp = (SMB2CreateResp*)(pkt + sizeof(SMB2Header));
        uint64_t fid_pers = cresp->file_id_persistent; uint64_t fid_vol = cresp->file_id_volatile;
        memset(pkt, 0, sizeof(pkt)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_SET_INFO); hdr->tree_id = g_app.smb2_tree_id;
        SMB2SetInfoReq *setinfo = (SMB2SetInfoReq*)(pkt + sizeof(SMB2Header));
        setinfo->structure_size = 33; setinfo->info_type = 1; setinfo->file_info_class = 10; setinfo->buffer_offset = 96; setinfo->file_id_persistent = fid_pers; setinfo->file_id_volatile = fid_vol;
        
        uint8_t *buf = pkt + 96; buf[0] = 0; memset(buf+1, 0, 15);
        char rel_new[MAX_SMB_PATH]; const char *np = newp; if (*np == '\\' || *np == '/') np++; strcpy(rel_new, np);
        uint32_t nlen = (uint32_t)utf8_to_utf16le(rel_new, buf+20, SMB_BUFFER_SIZE - 116); *(uint32_t*)(buf+16) = nlen; setinfo->buffer_length = 20 + nlen;
        smb_send_packet(pkt, 96 + setinfo->buffer_length); smb_recv_packet(pkt, sizeof(pkt), &rlen);
        
        memset(pkt, 0, sizeof(pkt)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CLOSE); hdr->tree_id = g_app.smb2_tree_id;
        SMB2CloseReq *cl = (SMB2CloseReq*)(pkt + sizeof(SMB2Header)); cl->structure_size = 24; cl->file_id_persistent = fid_pers; cl->file_id_volatile = fid_vol;
        smb_send_packet(pkt, sizeof(SMB2Header) + 24); smb_recv_packet(pkt, sizeof(pkt), &rlen); return 1;
    } return 0;
}

static int copy_r2l_file(const char *rpath, const char *lpath) {
    FILE *f = fopen(lpath, "wb"); if (!f) return 0;
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB1Header *hdr = smb_build_header(pkt, 0xA2); hdr->flags2 |= 0x8000; uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 24; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *w++ = 0; uint8_t *name_len_ptr = w; w += 2; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0x80000000; w += 4; *(uint64_t*)w = 0; w += 8; *(uint32_t*)w = 0x80; w += 4; *(uint32_t*)w = 0x01; w += 4; *(uint32_t*)w = 0x01; w += 4; *(uint32_t*)w = 0x40; w += 4; *(uint32_t*)w = 0x02; w += 4; *w++ = 0;                      
    uint8_t *bcc_ptr = w; w += 2; uint8_t *data_start = w; if ((w - pkt) % 2 != 0) *w++ = 0;
    uint8_t path_utf16[MAX_SMB_PATH * 2]; size_t plen = utf8_to_utf16le(rpath, path_utf16, sizeof(path_utf16)); memcpy(w, path_utf16, plen); w += plen; *w++ = 0; *w++ = 0;
    *(uint16_t*)name_len_ptr = (uint16_t)plen; *(uint16_t*)bcc_ptr = w - data_start;
    if (!smb_send_packet(pkt, w - pkt)) { fclose(f); return 0; }
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) { fclose(f); return 0; }
    hdr = (SMB1Header*)pkt; if (hdr->status != 0) { fclose(f); return 0; }
    uint16_t fid = *(uint16_t*)(pkt + 38); uint64_t file_size = *(uint64_t*)(pkt + 88); uint64_t offset = 0; uint32_t chunk_size = 32768; 
    set_progress(0);
    while (1) {
        memset(pkt, 0, sizeof(SMB1Header) + 50); hdr = smb_build_header(pkt, 0x2E); w = pkt + sizeof(SMB1Header);
        *w++ = 12; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = fid; w += 2; *(uint32_t*)w = (uint32_t)(offset & 0xFFFFFFFF); w += 4; *(uint16_t*)w = (uint16_t)chunk_size; w += 2; *(uint16_t*)w = (uint16_t)chunk_size; w += 2; *(uint32_t*)w = 0; w += 4; *(uint16_t*)w = 0; w += 2; *(uint32_t*)w = (uint32_t)(offset >> 32); w += 4; *(uint16_t*)w = 0; w += 2; 
        if (!smb_send_packet(pkt, w - pkt)) break; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) break;
        hdr = (SMB1Header*)pkt; if (hdr->status != 0 && hdr->status != 0x80000005) break; 
        uint16_t data_len = *(uint16_t*)(pkt + 43); uint16_t data_off = *(uint16_t*)(pkt + 45);
        if (data_len == 0 || data_off + data_len > rlen) break; 
        fwrite(pkt + data_off, 1, data_len, f); offset += data_len;
        if (file_size > 0) set_progress((int)(((double)offset / file_size) * 100)); if (data_len < chunk_size) break; 
    }
    memset(pkt, 0, sizeof(SMB1Header) + 20); hdr = smb_build_header(pkt, 0x04); w = pkt + sizeof(SMB1Header); *w++ = 3; *(uint16_t*)w = fid; w += 2; *(uint32_t*)w = 0; w += 4; *(uint16_t*)w = 0; w += 2; smb_send_packet(pkt, w - pkt); smb_recv_packet(pkt, sizeof(pkt), &rlen);
    fclose(f); set_progress(100); return 1;
}

static int copy_l2r_file(const char *lpath, const char *rpath) {
    FILE *f = fopen(lpath, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long file_size = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB1Header *hdr = smb_build_header(pkt, 0xA2); hdr->flags2 |= 0x8000; uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 24; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *w++ = 0; uint8_t *name_len_ptr = w; w += 2; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0; w += 4; *(uint32_t*)w = 0x40000000; w += 4; *(uint64_t*)w = 0; w += 8; *(uint32_t*)w = 0x80; w += 4; *(uint32_t*)w = 0x00; w += 4; *(uint32_t*)w = 0x05; w += 4; *(uint32_t*)w = 0x40; w += 4; *(uint32_t*)w = 0x02; w += 4; *w++ = 0; 
    uint8_t *bcc_ptr = w; w += 2; uint8_t *data_start = w; if ((w - pkt) % 2 != 0) *w++ = 0; 
    uint8_t path_utf16[MAX_SMB_PATH * 2]; size_t plen = utf8_to_utf16le(rpath, path_utf16, sizeof(path_utf16)); memcpy(w, path_utf16, plen); w += plen; *w++ = 0; *w++ = 0;
    *(uint16_t*)name_len_ptr = (uint16_t)plen; *(uint16_t*)bcc_ptr = w - data_start;
    if (!smb_send_packet(pkt, w - pkt)) { fclose(f); return 0; }
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) { fclose(f); return 0; }
    hdr = (SMB1Header*)pkt; if (hdr->status != 0) { fclose(f); return 0; }
    uint16_t fid = *(uint16_t*)(pkt + 38); uint64_t offset = 0; uint32_t chunk_size = 32768; uint8_t buf[32768]; size_t read_bytes;
    set_progress(0);
    while ((read_bytes = fread(buf, 1, chunk_size, f)) > 0) {
        memset(pkt, 0, sizeof(SMB1Header) + 50); hdr = smb_build_header(pkt, 0x2F); w = pkt + sizeof(SMB1Header);
        *w++ = 14; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = fid; w += 2; *(uint32_t*)w = (uint32_t)(offset & 0xFFFFFFFF); w += 4; *(uint32_t*)w = 0; w += 4; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = (uint16_t)read_bytes; w += 2; 
        uint16_t *data_off_ptr = (uint16_t*)w; w += 2; *(uint32_t*)w = (uint32_t)(offset >> 32); w += 4; uint8_t *bcc = w; w += 2; *w++ = 0; *data_off_ptr = (uint16_t)(w - pkt);
        memcpy(w, buf, read_bytes); w += read_bytes; *(uint16_t*)bcc = w - bcc - 2;
        if (!smb_send_packet(pkt, w - pkt)) break; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) break;
        hdr = (SMB1Header*)pkt; if (hdr->status != 0) break;
        offset += read_bytes; if (file_size > 0) set_progress((int)(((double)offset / file_size) * 100));
    }
    memset(pkt, 0, sizeof(SMB1Header) + 20); hdr = smb_build_header(pkt, 0x04); w = pkt + sizeof(SMB1Header); *w++ = 3; *(uint16_t*)w = fid; w += 2; *(uint32_t*)w = 0; w += 4; *(uint16_t*)w = 0; w += 2; smb_send_packet(pkt, w - pkt); smb_recv_packet(pkt, sizeof(pkt), &rlen);
    fclose(f); set_progress(100); return 1;
}

static int smb2_copy_r2l_file(const char *rpath, const char *lpath) {
    FILE *f = fopen(lpath, "wb"); if (!f) return 0;
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB2Header *hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CREATE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CreateReq *create = (SMB2CreateReq*)(pkt + sizeof(SMB2Header));
    create->structure_size = 57; create->impersonation_level = 2; create->desired_access = 0x80000000; create->file_attributes = 0;
    create->share_access = 0x01; create->create_disposition = 1; create->create_options = 0x00000040; create->name_offset = 120;
    char rel_path[MAX_SMB_PATH]; const char *p = rpath; if (*p == '\\' || *p == '/') p++; strcpy(rel_path, p);
    create->name_length = (uint16_t)utf8_to_utf16le(rel_path, pkt + 120, SMB_BUFFER_SIZE - 120);
    int pkt_len = 120 + create->name_length; if (create->name_length == 0) { pkt[120]=0; pkt[121]=0; pkt_len=122; }
    if (!smb_send_packet(pkt, pkt_len)) { fclose(f); return 0; }
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) { fclose(f); return 0; }
    hdr = (SMB2Header*)pkt; if (hdr->status != 0) { fclose(f); return 0; }
    
    SMB2CreateResp *cresp = (SMB2CreateResp*)(pkt + sizeof(SMB2Header));
    uint64_t fid_pers = cresp->file_id_persistent; uint64_t fid_vol = cresp->file_id_volatile;
    uint64_t file_size = cresp->end_of_file; uint64_t offset = 0; uint32_t chunk = 65536; set_progress(0);

    while (1) {
        memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2ReadReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_READ); hdr->tree_id = g_app.smb2_tree_id;
        SMB2ReadReq *req = (SMB2ReadReq*)(pkt + sizeof(SMB2Header));
        req->structure_size = 49; req->length = chunk; req->offset = offset; req->file_id_persistent = fid_pers; req->file_id_volatile = fid_vol;
        if (!smb_send_packet(pkt, sizeof(SMB2Header) + 49)) break; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) break;
        hdr = (SMB2Header*)pkt; if (hdr->status != 0) break;
        SMB2ReadResp *resp = (SMB2ReadResp*)(pkt + sizeof(SMB2Header)); if (resp->data_length == 0) break;
        fwrite(pkt + resp->data_offset, 1, resp->data_length, f); offset += resp->data_length;
        if (file_size > 0) set_progress((int)(((double)offset / file_size) * 100)); if (resp->data_length < chunk) break; 
    }
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2CloseReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CLOSE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CloseReq *cl = (SMB2CloseReq*)(pkt + sizeof(SMB2Header)); cl->structure_size = 24; cl->file_id_persistent = fid_pers; cl->file_id_volatile = fid_vol;
    smb_send_packet(pkt, sizeof(SMB2Header) + 24); smb_recv_packet(pkt, sizeof(pkt), &rlen);
    fclose(f); set_progress(100); return 1;
}

static int smb2_copy_l2r_file(const char *lpath, const char *rpath) {
    FILE *f = fopen(lpath, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long file_size = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    SMB2Header *hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CREATE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CreateReq *create = (SMB2CreateReq*)(pkt + sizeof(SMB2Header));
    create->structure_size = 57; create->impersonation_level = 2; create->desired_access = 0x40000000; create->file_attributes = 0x00000080; 
    create->share_access = 0x00; create->create_disposition = 5; create->create_options = 0x00000040; create->name_offset = 120;
    char rel_path[MAX_SMB_PATH]; const char *p = rpath; if (*p == '\\' || *p == '/') p++; strcpy(rel_path, p);
    create->name_length = (uint16_t)utf8_to_utf16le(rel_path, pkt + 120, SMB_BUFFER_SIZE - 120);
    int pkt_len = 120 + create->name_length; if (create->name_length == 0) { pkt[120]=0; pkt[121]=0; pkt_len=122; }
    if (!smb_send_packet(pkt, pkt_len)) { fclose(f); return 0; }
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) { fclose(f); return 0; }
    hdr = (SMB2Header*)pkt; if (hdr->status != 0) { fclose(f); return 0; }
    
    SMB2CreateResp *cresp = (SMB2CreateResp*)(pkt + sizeof(SMB2Header));
    uint64_t fid_pers = cresp->file_id_persistent; uint64_t fid_vol = cresp->file_id_volatile;
    uint64_t offset = 0; uint32_t chunk = 65536; uint8_t buf[65536]; size_t read_bytes; set_progress(0);

    while ((read_bytes = fread(buf, 1, chunk, f)) > 0) {
        memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2WriteReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_WRITE); hdr->tree_id = g_app.smb2_tree_id;
        SMB2WriteReq *req = (SMB2WriteReq*)(pkt + sizeof(SMB2Header));
        req->structure_size = 49; req->data_offset = 112; req->length = (uint32_t)read_bytes; req->offset = offset;
        req->file_id_persistent = fid_pers; req->file_id_volatile = fid_vol;
        memcpy(pkt + req->data_offset, buf, read_bytes);
        if (!smb_send_packet(pkt, req->data_offset + read_bytes)) break; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) break;
        hdr = (SMB2Header*)pkt; if (hdr->status != 0) break;
        offset += read_bytes; if (file_size > 0) set_progress((int)(((double)offset / file_size) * 100));
    }
    memset(pkt, 0, sizeof(SMB2Header) + sizeof(SMB2CloseReq)); hdr = (SMB2Header*)pkt; smb2_init_header(hdr, SMB2_CLOSE); hdr->tree_id = g_app.smb2_tree_id;
    SMB2CloseReq *cl = (SMB2CloseReq*)(pkt + sizeof(SMB2Header)); cl->structure_size = 24; cl->file_id_persistent = fid_pers; cl->file_id_volatile = fid_vol;
    smb_send_packet(pkt, sizeof(SMB2Header) + 24); smb_recv_packet(pkt, sizeof(pkt), &rlen);
    fclose(f); set_progress(100); return 1;
}

static int copy_ftp_r2l_file(const char *rpath, const char *lpath) {
    add_log("FTP: Downloading %s...", rpath); set_progress(50); 
    BOOL success = FtpGetFileA(g_app.hFtpSession, rpath, lpath, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0);
    if (!success) { add_log("FTP: Download failed."); set_progress(0); return 0; }
    set_progress(100); return 1;
}

static int copy_ftp_l2r_file(const char *lpath, const char *rpath) {
    add_log("FTP: Uploading %s...", rpath); set_progress(50);
    BOOL success = FtpPutFileA(g_app.hFtpSession, lpath, rpath, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0);
    if (!success) { add_log("FTP: Upload failed."); set_progress(0); return 0; }
    set_progress(100); return 1;
}

static int copy_single_r2l(const char *rpath, const char *lpath) {
    if (g_app.conn_type == CONN_FTP) return copy_ftp_r2l_file(rpath, lpath);
    if (g_app.conn_type == CONN_SMB) { if (g_app.current_proto == PROTO_SMB1) return copy_r2l_file(rpath, lpath); if (g_app.current_proto == PROTO_SMB2) return smb2_copy_r2l_file(rpath, lpath); }
    return 0;
}

static int copy_single_l2r(const char *lpath, const char *rpath) {
    if (g_app.conn_type == CONN_FTP) return copy_ftp_l2r_file(lpath, rpath);
    if (g_app.conn_type == CONN_SMB) { if (g_app.current_proto == PROTO_SMB1) return copy_l2r_file(lpath, rpath); if (g_app.current_proto == PROTO_SMB2) return smb2_copy_l2r_file(lpath, rpath); }
    return 0;
}

static int create_remote_dir(const char *rpath) {
    if (g_app.conn_type == CONN_FTP) return ftp_mkdir_ex("", rpath);
    if (g_app.conn_type == CONN_SMB) {
        if (g_app.current_proto == PROTO_SMB1) return smb_mkdir_ex("", rpath);
        if (g_app.current_proto == PROTO_SMB2) return smb2_mkdir(rpath);
    }
    return 0;
}

static void delete_recursive_local(const char *path) {
    char search[MAX_SMB_PATH]; snprintf(search, sizeof(search), "%s\\*", path);
    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char p[MAX_SMB_PATH]; snprintf(p, sizeof(p), "%s\\%s", path, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) delete_recursive_local(p); else DeleteFileA(p);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryA(path);
}

static void update_remote_list(void) {
    SendMessageA(g_app.hRemoteList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.remote_count; i++) {
        char display[MAX_SMB_PATH_LEN]; snprintf(display, sizeof(display), "%s%s", g_app.remote_items[i].is_dir ? "[DIR] " : "", g_app.remote_items[i].path);
        SendMessageA(g_app.hRemoteList, LB_ADDSTRING, 0, (LPARAM)display);
    }
    char lbl[MAX_SMB_PATH_LEN]; const char *proto = (g_app.conn_type == CONN_SMB) ? (g_app.current_proto == PROTO_SMB2 ? "SMB2" : "SMB1") : (g_app.conn_type == CONN_FTP ? "FTP" : "Disconnected");
    snprintf(lbl, sizeof(lbl), "Remote (%s): %s", proto, g_app.conn_type ? g_app.remote_base : ""); SetWindowTextA(g_app.hLblRemote, lbl);
}

static void update_local_list(void) {
    SendMessageA(g_app.hLocalList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.local_count; i++) {
        char display[MAX_SMB_PATH_LEN]; snprintf(display, sizeof(display), "%s%s", g_app.local_items[i].is_dir ? "[DIR] " : "", g_app.local_items[i].path);
        SendMessageA(g_app.hLocalList, LB_ADDSTRING, 0, (LPARAM)display);
    }
    char lbl[MAX_SMB_PATH_LEN]; snprintf(lbl, sizeof(lbl), "Local: %s", g_app.local_base); SetWindowTextA(g_app.hLblLocal, lbl);
}

static void list_remote(void) {
    if (g_app.conn_type == CONN_NONE) return;
    g_app.remote_count = 0; strcpy(g_app.remote_items[0].path, "."); g_app.remote_items[0].is_dir = 1; strcpy(g_app.remote_items[1].path, ".."); g_app.remote_items[1].is_dir = 1; g_app.remote_count = 2;
    if (g_app.current_proto == PROTO_SMB2) { smb2_list_directory(); } else if (g_app.current_proto == PROTO_SMB1) { smb_list_directory(); }
    else if (g_app.conn_type == CONN_FTP) {
        WIN32_FIND_DATAA fd; FtpSetCurrentDirectoryA(g_app.hFtpSession, g_app.remote_base);
        HINTERNET hFind = FtpFindFirstFileA(g_app.hFtpSession, "*", &fd, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_RESYNCHRONIZE, 0);
        if (hFind) {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue; 
                if (g_app.remote_count >= MAX_ITEMS) break;
                strncpy(g_app.remote_items[g_app.remote_count].path, fd.cFileName, MAX_SMB_PATH-1); 
                g_app.remote_items[g_app.remote_count].is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0; 
                g_app.remote_count++;
            } while (InternetFindNextFileA(hFind, &fd)); InternetCloseHandle(hFind);
        }
    }
    update_remote_list();
}

static void list_local(void) {
    g_app.local_count = 0; strcpy(g_app.local_items[0].path, "."); g_app.local_items[0].is_dir = 1; strcpy(g_app.local_items[1].path, ".."); g_app.local_items[1].is_dir = 1; g_app.local_count = 2;
    if (strlen(g_app.local_base) == 0) {
        char logical_drives[256]; DWORD len = GetLogicalDriveStringsA(sizeof(logical_drives), logical_drives);
        if (len > 0) { char *p = logical_drives; while (*p && g_app.local_count < MAX_ITEMS) { strncpy(g_app.local_items[g_app.local_count].path, p, 3); g_app.local_items[g_app.local_count].path[3] = '\0'; g_app.local_items[g_app.local_count].is_dir = 1; g_app.local_count++; p += strlen(p) + 1; } }
    } else {
        char spath[MAX_SMB_PATH_LEN]; size_t len = strlen(g_app.local_base);
        if (len > 0 && g_app.local_base[len - 1] == '\\') { snprintf(spath, sizeof(spath), "%s*", g_app.local_base); } else { snprintf(spath, sizeof(spath), "%s\\*", g_app.local_base); }
        WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(spath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) { do { if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0 && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { if (g_app.local_count < MAX_ITEMS) { strncpy(g_app.local_items[g_app.local_count].path, fd.cFileName, MAX_SMB_PATH_LEN - 1); g_app.local_items[g_app.local_count].path[MAX_SMB_PATH_LEN - 1] = '\0'; g_app.local_items[g_app.local_count].is_dir = 1; g_app.local_count++; } } } while (FindNextFileA(hFind, &fd)); FindClose(hFind); }
        hFind = FindFirstFileA(spath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) { do { if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0 && !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { if (g_app.local_count < MAX_ITEMS) { strncpy(g_app.local_items[g_app.local_count].path, fd.cFileName, MAX_SMB_PATH_LEN - 1); g_app.local_items[g_app.local_count].path[MAX_SMB_PATH_LEN - 1] = '\0'; g_app.local_items[g_app.local_count].is_dir = 0; g_app.local_count++; } } } while (FindNextFileA(hFind, &fd)); FindClose(hFind); }
    }
    if (g_app.local_count > 2) { qsort(&g_app.local_items[2], g_app.local_count - 2, sizeof(DirectoryItem), compare_local_items); }
    update_local_list();
}

static int fetch_remote_dir_contents(const char *rpath, DirectoryItem **items, int *count) {
    char saved_base[MAX_SMB_PATH_LEN]; strcpy(saved_base, g_app.remote_base);
    DirectoryItem *saved_items = (DirectoryItem *)malloc(sizeof(DirectoryItem) * MAX_ITEMS); if (!saved_items) return 0;
    memcpy(saved_items, g_app.remote_items, sizeof(DirectoryItem) * MAX_ITEMS); int saved_count = g_app.remote_count;
    strcpy(g_app.remote_base, rpath); list_remote(); 
    *count = g_app.remote_count; *items = (DirectoryItem*)malloc(sizeof(DirectoryItem) * (*count)); if (*items) memcpy(*items, g_app.remote_items, sizeof(DirectoryItem) * (*count));
    strcpy(g_app.remote_base, saved_base); memcpy(g_app.remote_items, saved_items, sizeof(DirectoryItem) * MAX_ITEMS); g_app.remote_count = saved_count; free(saved_items);
    if (g_app.conn_type == CONN_FTP) FtpSetCurrentDirectoryA(g_app.hFtpSession, saved_base);
    return (*items != NULL);
}

static void copy_recursive_r2l(const char *rpath, const char *lpath, int is_dir) {
    if (!is_dir) { copy_single_r2l(rpath, lpath); return; }
    CreateDirectoryA(lpath, NULL); DirectoryItem *items = NULL; int count = 0;
    if (fetch_remote_dir_contents(rpath, &items, &count)) {
        char sep = (g_app.conn_type == CONN_FTP) ? '/' : '\\';
        for (int i = 0; i < count; i++) {
            if (strcmp(items[i].path, ".") == 0 || strcmp(items[i].path, "..") == 0) continue;
            char new_rpath[MAX_SMB_PATH], new_lpath[MAX_SMB_PATH];
            if (rpath[strlen(rpath)-1] == sep) snprintf(new_rpath, sizeof(new_rpath), "%s%s", rpath, items[i].path); else snprintf(new_rpath, sizeof(new_rpath), "%s%c%s", rpath, sep, items[i].path);
            if (lpath[strlen(lpath)-1] == '\\') snprintf(new_lpath, sizeof(new_lpath), "%s%s", lpath, items[i].path); else snprintf(new_lpath, sizeof(new_lpath), "%s\\%s", lpath, items[i].path);
            copy_recursive_r2l(new_rpath, new_lpath, items[i].is_dir);
        }
        free(items);
    }
}

static void copy_recursive_l2r(const char *lpath, const char *rpath, int is_dir) {
    if (!is_dir) { copy_single_l2r(lpath, rpath); return; }
    create_remote_dir(rpath); char search_path[MAX_SMB_PATH]; snprintf(search_path, sizeof(search_path), "%s\\*", lpath);
    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(search_path, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char new_lpath[MAX_SMB_PATH], new_rpath[MAX_SMB_PATH]; char sep = (g_app.conn_type == CONN_FTP) ? '/' : '\\';
            if (lpath[strlen(lpath)-1] == '\\') snprintf(new_lpath, sizeof(new_lpath), "%s%s", lpath, fd.cFileName); else snprintf(new_lpath, sizeof(new_lpath), "%s\\%s", lpath, fd.cFileName);
            if (rpath[strlen(rpath)-1] == sep) snprintf(new_rpath, sizeof(new_rpath), "%s%s", rpath, fd.cFileName); else snprintf(new_rpath, sizeof(new_rpath), "%s%c%s", rpath, sep, fd.cFileName);
            int child_is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
            copy_recursive_l2r(new_lpath, new_rpath, child_is_dir);
        } while (FindNextFileA(hFind, &fd)); FindClose(hFind);
    }
}

static void do_action(int action) {
    int is_remote = (g_app.active_pane == PANE_REMOTE); 
    int is_ftp = (g_app.conn_type == CONN_FTP);
    HWND hList = is_remote ? g_app.hRemoteList : g_app.hLocalList;

    if (action == ID_BTN_MKDIR) {
        CreateWindowExA(WS_EX_DLGMODALFRAME, "CreateDirClass", "Create Directory", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, 110, g_app.hMain, NULL, g_hInst, NULL); 
        EnableWindow(g_app.hMain, FALSE);
        return;
    }

    int sel_count = SendMessageA(hList, LB_GETSELCOUNT, 0, 0); 
    int *sel_indices = NULL;
    
    if (sel_count > 0) {
        sel_indices = (int*)malloc(sel_count * sizeof(int)); 
        SendMessageA(hList, LB_GETSELITEMS, sel_count, (LPARAM)sel_indices);
    } else {
        sel_count = 1; sel_indices = (int*)malloc(sizeof(int)); sel_indices[0] = 0; 
    }

    int current_dir_deleted = 0;

    for (int s = 0; s < sel_count; s++) {
        int idx = sel_indices[s]; 
        char item_name[MAX_SMB_PATH]; int is_dir = 0;
        
        if (is_remote) { 
            if (idx >= g_app.remote_count) continue;
            strcpy(item_name, g_app.remote_items[idx].path); is_dir = g_app.remote_items[idx].is_dir; 
        } else { 
            if (idx >= g_app.local_count) continue;
            strcpy(item_name, g_app.local_items[idx].path); is_dir = g_app.local_items[idx].is_dir; 
        }
        
        if (strcmp(item_name, "..") == 0) continue;

        char sep_r = is_ftp ? '/' : '\\'; 
        char rem_path[MAX_SMB_PATH], loc_path[MAX_SMB_PATH];
        char src_folder_name[MAX_SMB_PATH] = "";
        int is_current_dir = (strcmp(item_name, ".") == 0);
        
        if (is_current_dir) {
            char temp_base[MAX_SMB_PATH]; strcpy(temp_base, is_remote ? g_app.remote_base : g_app.local_base);
            int len = strlen(temp_base); while(len > 0 && (temp_base[len-1] == '\\' || temp_base[len-1] == '/')) temp_base[--len] = '\0';
            char *ls = strrchr(temp_base, '\\'); char *ls_f = strrchr(temp_base, '/'); if (ls_f > ls) ls = ls_f;
            if (ls) strcpy(src_folder_name, ls + 1); else strcpy(src_folder_name, temp_base);
            if (strlen(src_folder_name) == 0 || (src_folder_name[1] == ':' && strlen(src_folder_name) <= 2) || strcmp(src_folder_name, "\\") == 0 || strcmp(src_folder_name, "/") == 0) { continue; }
            strcpy(item_name, src_folder_name);
        }

        if (is_current_dir) {
            strcpy(rem_path, g_app.remote_base); strcpy(loc_path, g_app.local_base);
            if (is_remote) { if (loc_path[strlen(loc_path)-1] != '\\') strcat(loc_path, "\\"); strcat(loc_path, item_name); } 
            else { char sep_str[2] = {sep_r, '\0'}; if (rem_path[strlen(rem_path)-1] != sep_r) strcat(rem_path, sep_str); strcat(rem_path, item_name); }
        } else {
            if (g_app.remote_base[strlen(g_app.remote_base)-1] == sep_r) snprintf(rem_path, sizeof(rem_path), "%s%s", g_app.remote_base, item_name);
            else snprintf(rem_path, sizeof(rem_path), "%s%c%s", g_app.remote_base, sep_r, item_name);
            if (g_app.local_base[strlen(g_app.local_base)-1] == '\\') snprintf(loc_path, sizeof(loc_path), "%s%s", g_app.local_base, item_name);
            else snprintf(loc_path, sizeof(loc_path), "%s\\%s", g_app.local_base, item_name);
        }
        
        normalize_path(rem_path, is_ftp); normalize_path(loc_path, 0);

        if (action == ID_BTN_COPY || action == ID_BTN_MOVE) {
            if (is_remote) {
                copy_recursive_r2l(rem_path, loc_path, is_dir);
                if (action == ID_BTN_MOVE) { 
                    if (g_app.conn_type == CONN_FTP) { if (is_dir) FtpRemoveDirectoryA(g_app.hFtpSession, rem_path); else FtpDeleteFileA(g_app.hFtpSession, rem_path); } 
                    else if (g_app.current_proto == PROTO_SMB1) { if (is_dir) smb_delete_dir(rem_path); else smb_delete(rem_path); } 
                    else if (g_app.current_proto == PROTO_SMB2) { smb2_delete_internal(rem_path, is_dir); } 
                    if (is_current_dir) current_dir_deleted = 1;
                }
            } else {
                copy_recursive_l2r(loc_path, rem_path, is_dir);
                if (action == ID_BTN_MOVE) { 
                    if (is_dir) delete_recursive_local(loc_path); else DeleteFileA(loc_path); 
                    if (is_current_dir) current_dir_deleted = 1;
                }
            }
        } else if (action == ID_BTN_DELETE) {
            if (is_remote) { 
                if (g_app.current_proto == PROTO_SMB1) { if (is_dir) smb_delete_dir(rem_path); else smb_delete(rem_path); } 
                else if (g_app.current_proto == PROTO_SMB2) { smb2_delete_internal(rem_path, is_dir); } 
                else if (g_app.conn_type == CONN_FTP) { if (is_dir) FtpRemoveDirectoryA(g_app.hFtpSession, rem_path); else FtpDeleteFileA(g_app.hFtpSession, rem_path); } 
            } else { if (is_dir) delete_recursive_local(loc_path); else DeleteFileA(loc_path); }
            if (is_current_dir) current_dir_deleted = 1;
        } else if (action == ID_BTN_RENAME && s == 0) { 
            if (is_current_dir) {
                char temp_base[MAX_SMB_PATH]; strcpy(temp_base, is_remote ? g_app.remote_base : g_app.local_base);
                int len = strlen(temp_base); while(len > 0 && (temp_base[len-1] == '\\' || temp_base[len-1] == '/')) temp_base[--len] = '\0';
                char *ls = strrchr(temp_base, '\\'); char *ls_f = strrchr(temp_base, '/'); if (ls_f > ls) ls = ls_f;
                if (ls) { *ls = '\0'; strcpy(g_ren_base, temp_base); if (strlen(g_ren_base) == 0) strcpy(g_ren_base, is_remote ? (is_ftp ? "/" : "\\") : "C:\\"); } 
                else { strcpy(g_ren_base, is_remote ? (is_ftp ? "/" : "\\") : "C:\\"); }
                strcpy(g_ren_item, item_name);
            } else { strcpy(g_ren_base, is_remote ? g_app.remote_base : g_app.local_base); strcpy(g_ren_item, item_name); }
            CreateWindowExA(WS_EX_DLGMODALFRAME, "RenameClass", "Rename Item", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, 110, g_app.hMain, NULL, g_hInst, NULL); 
            EnableWindow(g_app.hMain, FALSE);
        }
    }
    
    if (sel_indices) free(sel_indices);
    
    if (current_dir_deleted) {
        if (is_remote) {
            char sep = is_ftp ? '/' : '\\'; char *ls = strrchr(g_app.remote_base, sep);
            if (ls && ls != g_app.remote_base) *ls = '\0'; else if (ls == g_app.remote_base) *(ls+1) = '\0';
        } else {
            if (strlen(g_app.local_base) <= 3 && g_app.local_base[1] == ':') strcpy(g_app.local_base, ""); 
            else { char *ls = strrchr(g_app.local_base, '\\'); if (ls) { if (ls == g_app.local_base + 2) *(ls + 1) = '\0'; else *ls = '\0'; } }
        }
    }
    
    if (action == ID_BTN_COPY || action == ID_BTN_MOVE || action == ID_BTN_DELETE) { list_local(); list_remote(); }
}

static int connect_server(ConnectionProfile *p) {
    disconnect_all(); WSADATA wd; WSAStartup(MAKEWORD(2,2), &wd);
    struct addrinfo hints={0}, *res; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    char *conn_port = (p->port[0] != '\0') ? p->port : "445";
    if (getaddrinfo(p->server, conn_port, &hints, &res) != 0) { add_log("Host lookup failed."); return 0; }
    
    g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (!connect_with_timeout(g_app.sconn, res->ai_addr, res->ai_addrlen)) { 
        add_log("Socket conn failed (50ms timeout)."); closesocket(g_app.sconn); g_app.sconn = 0; freeaddrinfo(res); return 0; 
    }
    
    char full_share[MAX_SMB_PATH]; strcpy(full_share, p->share); normalize_path(full_share, 0); 
    char share_root[128] = ""; char sub_dir[MAX_SMB_PATH] = "\\";
    char *first_slash = strchr(full_share, '\\'); if (first_slash == full_share) first_slash = strchr(full_share + 1, '\\');
    if (first_slash) { int root_len = first_slash - full_share; if (full_share[0] == '\\') { root_len = first_slash - (full_share + 1); strncpy(share_root, full_share + 1, root_len); } else strncpy(share_root, full_share, root_len); share_root[root_len] = '\0'; strcpy(sub_dir, first_slash); } else { if (full_share[0] == '\\') strcpy(share_root, full_share + 1); else strcpy(share_root, full_share); }

    int try_smb2 = (p->proto_pref == PROTO_SMB2 || p->proto_pref == PROTO_AUTO);
    int try_smb1 = (p->proto_pref == PROTO_SMB1 || p->proto_pref == PROTO_AUTO);
    int smb1_connected = 0;
    
    /* SMB1 priority */
    if (try_smb1) {
        add_log("Connecting via SMB1...");
        g_app.uid = 0; g_app.tid = 0; g_app.mid_counter = 1;
        if (smb_negotiate()) {
            int auth_success = smb_session(p->user, p->pass);
            if (!auth_success && (strlen(p->user) > 0 || strlen(p->pass) > 0)) {
                closesocket(g_app.sconn); g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (connect_with_timeout(g_app.sconn, res->ai_addr, res->ai_addrlen)) { 
                    g_app.uid = 0; g_app.tid = 0; g_app.mid_counter = 1; 
                    if (smb_negotiate()) auth_success = smb_session("", ""); 
                }
            }
            if (auth_success) {
                if (smb_tree_connect(p->server, share_root)) { 
                    g_app.conn_type = CONN_SMB; g_app.current_proto = PROTO_SMB1; strcpy(g_app.remote_base, sub_dir); 
                    list_remote(); add_log("Connected via SMB1"); freeaddrinfo(res); return 1; 
                } 
            }
        } 
    }
    
    /* Fallback to SMB2 */
    if (!smb1_connected && try_smb2) {
        closesocket(g_app.sconn); g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (connect_with_timeout(g_app.sconn, res->ai_addr, res->ai_addrlen)) {
            add_log("Connecting via SMB2...");
            if (smb2_negotiate()) {
                if (smb2_session_setup(p->user, p->pass)) {
                    if (smb2_tree_connect(p->server, share_root)) {
                        g_app.conn_type = CONN_SMB; g_app.current_proto = PROTO_SMB2; strcpy(g_app.remote_base, sub_dir); 
                        list_remote(); add_log("Connected via SMB2"); freeaddrinfo(res); return 1;
                    }
                } 
            }
        }
    }
    
    freeaddrinfo(res); return 0;
}

static int connect_ftp(ConnectionProfile *p) {
    disconnect_all(); g_app.hInternet = InternetOpenA("DualPaneClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); if (!g_app.hInternet) return 0;
    
    DWORD timeout = 50;
    InternetSetOptionA(g_app.hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(g_app.hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOptionA(g_app.hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    
    const char *ftp_user = (p->user[0] != '\0') ? p->user : NULL; const char *ftp_pass = (p->pass[0] != '\0') ? p->pass : NULL;
    INTERNET_PORT ftp_port = INTERNET_DEFAULT_FTP_PORT; if (p->port[0] != '\0') { int parsed = atoi(p->port); if (parsed > 0) ftp_port = (INTERNET_PORT)parsed; }
    g_app.hFtpSession = InternetConnectA(g_app.hInternet, p->server, ftp_port, ftp_user, ftp_pass, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    if (!g_app.hFtpSession) { InternetCloseHandle(g_app.hInternet); g_app.hInternet = NULL; return 0; }
    g_app.conn_type = CONN_FTP; normalize_path(p->share, 1);
    char ftp_path[MAX_SMB_PATH_LEN] = "/"; if (p->share[0] != '\0') snprintf(ftp_path, sizeof(ftp_path), "/%s", p->share); normalize_path(ftp_path, 1);
    strncpy(g_app.remote_base, ftp_path, MAX_SMB_PATH_LEN-1);
    if (strcmp(g_app.remote_base, "/") != 0) { if (!FtpSetCurrentDirectoryA(g_app.hFtpSession, g_app.remote_base)) { strcpy(g_app.remote_base, "/"); FtpSetCurrentDirectoryA(g_app.hFtpSession, "/"); } }
    list_remote(); return 1;
}

/* ==========================================================================
   NATIVE UI SUBCLASS & DIALOG PROCEDURES
   ========================================================================== */
BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

static LRESULT CALLBACK ListSubProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_GETDLGCODE) {
        LRESULT res = CallWindowProc(OldListProc, hwnd, msg, wp, lp);
        if (lp) { MSG *pMsg = (MSG *)lp; if (pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_RETURN) return res | DLGC_WANTMESSAGE; }
        return res;
    }
    if (msg == WM_KEYDOWN && wp == VK_RETURN) {
        HWND hParent = GetParent(hwnd); int id = GetDlgCtrlID(hwnd);
        SendMessageA(hParent, WM_COMMAND, MAKEWPARAM(id, LBN_DBLCLK), (LPARAM)hwnd);
        return 0;
    }

    static int is_dragging = 0; static POINT drag_start;
    if (msg == WM_LBUTTONDOWN) { drag_start.x = (short)LOWORD(lp); drag_start.y = (short)HIWORD(lp); is_dragging = 0; } 
    else if (msg == WM_MOUSEMOVE && (wp & MK_LBUTTON)) {
        int dx = (short)LOWORD(lp) - drag_start.x; int dy = (short)HIWORD(lp) - drag_start.y;
        if (!is_dragging && (abs(dx) > 5 || abs(dy) > 5)) { 
            int idx = SendMessageA(hwnd, LB_ITEMFROMPOINT, 0, MAKELPARAM(drag_start.x, drag_start.y));
            if (HIWORD(idx) == 0) { if (SendMessageA(hwnd, LB_GETSEL, LOWORD(idx), 0) > 0) { is_dragging = 1; SetCapture(hwnd); SetCursor(LoadCursor(NULL, IDC_SIZEALL)); return 0; } }
        }
        if (is_dragging) { SetCursor(LoadCursor(NULL, IDC_SIZEALL)); return 0; }
    } 
    else if (msg == WM_LBUTTONUP) {
        if (is_dragging) {
            is_dragging = 0; ReleaseCapture(); POINT pt; GetCursorPos(&pt); HWND hTarget = WindowFromPoint(pt);
            HWND hOther = (hwnd == g_app.hLocalList) ? g_app.hRemoteList : g_app.hLocalList;
            if (hTarget == hOther) { g_app.active_pane = (hwnd == g_app.hRemoteList) ? PANE_REMOTE : PANE_LOCAL; do_action((GetKeyState(VK_SHIFT) & 0x8000) ? ID_BTN_MOVE : ID_BTN_COPY); }
            return 0;
        }
    }
    return CallWindowProc(OldListProc, hwnd, msg, wp, lp);
}

static LRESULT CALLBACK CreateDirWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hEdit;
    switch (msg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "Folder Name:", WS_CHILD|WS_VISIBLE, 10, 10, 90, 20, hwnd, NULL, g_hInst, NULL);
            hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 105, 10, 165, 20, hwnd, (HMENU)IDE_MKDIR_NAME, g_hInst, NULL);
            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 100, 40, 80, 25, hwnd, (HMENU)IDB_MKDIR_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 190, 40, 80, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas"); EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF); SetFocus(hEdit); return 0;
        }
        case DM_GETDEFID: return MAKELRESULT(IDB_MKDIR_OK, DC_HASDEFID);
        case WM_COMMAND: {
            if (LOWORD(wp) == IDB_MKDIR_OK || LOWORD(wp) == IDOK) {
                char dir_name[MAX_SMB_PATH]; GetWindowTextA(hEdit, dir_name, sizeof(dir_name)); trim_str(dir_name);
                if (strlen(dir_name) > 0) {
                    int is_rem = (g_app.active_pane == PANE_REMOTE);
                    if (is_rem) {
                        if (g_app.conn_type == CONN_FTP) { ftp_mkdir_ex(g_app.remote_base, dir_name); } 
                        else if (g_app.current_proto == PROTO_SMB1) { smb_mkdir_ex(g_app.remote_base, dir_name); } 
                        else if (g_app.current_proto == PROTO_SMB2) { char rel_target[MAX_SMB_PATH]; format_folder_path(rel_target, sizeof(rel_target), g_app.remote_base, dir_name, 0); smb2_mkdir(rel_target); }
                        list_remote();
                    } else {
                        char target_path[MAX_SMB_PATH]; format_folder_path(target_path, sizeof(target_path), g_app.local_base, dir_name, 0);
                        CreateDirectoryA(target_path, NULL); list_local();
                    }
                }
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
            } else if (LOWORD(wp) == IDB_CANCEL || LOWORD(wp) == IDCANCEL) { SendMessageA(hwnd, WM_CLOSE, 0, 0); }
            break;
        }
        case WM_CLOSE: EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE); DestroyWindow(hwnd); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK RenameWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hEdit;
    switch (msg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "New Name:", WS_CHILD|WS_VISIBLE, 10, 10, 80, 20, hwnd, NULL, g_hInst, NULL);
            hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_ren_item, WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 100, 10, 170, 20, hwnd, (HMENU)IDE_RENAME_NEW, g_hInst, NULL);
            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 100, 40, 80, 25, hwnd, (HMENU)IDB_RENAME_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 190, 40, 80, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas"); EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF); SetFocus(hEdit); return 0;
        }
        case DM_GETDEFID: return MAKELRESULT(IDB_RENAME_OK, DC_HASDEFID);
        case WM_COMMAND: {
            if (LOWORD(wp) == IDB_RENAME_OK || LOWORD(wp) == IDOK) {
                char new_name[MAX_SMB_PATH], src_full[MAX_SMB_PATH], dst_full[MAX_SMB_PATH]; GetWindowTextA(hEdit, new_name, MAX_SMB_PATH);
                int is_rem = (g_app.active_pane == PANE_REMOTE); int is_ftp = (g_app.conn_type == CONN_FTP); char sep = (is_rem && is_ftp) ? '/' : '\\';
                if (g_ren_base[strlen(g_ren_base)-1] == sep) { snprintf(src_full, sizeof(src_full), "%s%s", g_ren_base, g_ren_item); snprintf(dst_full, sizeof(dst_full), "%s%s", g_ren_base, new_name); } 
                else { snprintf(src_full, sizeof(src_full), "%s%c%s", g_ren_base, sep, g_ren_item); snprintf(dst_full, sizeof(dst_full), "%s%c%s", g_ren_base, sep, new_name); }
                normalize_path(src_full, is_rem && is_ftp); normalize_path(dst_full, is_rem && is_ftp);
                
                int current_renamed = 0;
                if (is_rem) { char norm_rem[MAX_SMB_PATH]; strcpy(norm_rem, g_app.remote_base); normalize_path(norm_rem, is_ftp); if (_stricmp(src_full, norm_rem) == 0) current_renamed = 1; } 
                else { char norm_loc[MAX_SMB_PATH]; strcpy(norm_loc, g_app.local_base); normalize_path(norm_loc, 0); if (_stricmp(src_full, norm_loc) == 0) current_renamed = 1; }

                if (is_rem) { 
                    if (g_app.current_proto == PROTO_SMB1) smb_rename(src_full, dst_full); else if (g_app.current_proto == PROTO_SMB2) smb2_rename(src_full, dst_full); else if (g_app.conn_type == CONN_FTP) FtpRenameFileA(g_app.hFtpSession, src_full, dst_full); 
                    if (current_renamed) strcpy(g_app.remote_base, dst_full); list_remote(); 
                } else { MoveFileA(src_full, dst_full); if (current_renamed) strcpy(g_app.local_base, dst_full); list_local(); }
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
            } else if (LOWORD(wp) == IDB_CANCEL || LOWORD(wp) == IDCANCEL) { SendMessageA(hwnd, WM_CLOSE, 0, 0); }
            break;
        }
        case WM_CLOSE: EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE); DestroyWindow(hwnd); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK EditConnWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hN, hS, hPrt, hSh, hU, hP, hChkFTP, hChkSMB2;
    switch (msg) {
          case WM_CREATE: {
            int y = 10;
            CreateWindowA("STATIC", "Name:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL); hN = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Server:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL); hS = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Port (Blank=Def):", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL); hPrt = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Share/Path:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL); hSh = CreateWindowExA(WS_EX_CLIENTEDGE, "COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_VSCROLL|CBS_DROPDOWN|CBS_AUTOHSCROLL, 110, y, 140, 150, hwnd, NULL, g_hInst, NULL); CreateWindowA("BUTTON", "Test", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 255, y, 55, 22, hwnd, (HMENU)IDB_TEST, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "User:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL); hU = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Pass:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL); hP = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            hChkFTP = CreateWindowA("BUTTON", "FTP Protocol Mode", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 110, y, 200, 20, hwnd, (HMENU)IDC_CHK_FTP, g_hInst, NULL); y+=25;
            hChkSMB2 = CreateWindowA("BUTTON", "Force SMB2 Only", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 110, y, 200, 20, hwnd, (HMENU)IDC_PROTO_SMB2, g_hInst, NULL); y+=25;
            CreateWindowA("BUTTON", "Add", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 10, y, 70, 25, hwnd, (HMENU)IDB_ADD, g_hInst, NULL); 
            CreateWindowA("BUTTON", "Save", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 87, y, 70, 25, hwnd, (HMENU)IDB_SAVE, g_hInst, NULL); 
            CreateWindowA("BUTTON", "Delete", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 164, y, 70, 25, hwnd, (HMENU)IDB_DELETE, g_hInst, NULL); 
            CreateWindowA("BUTTON", "Close", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 241, y, 70, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            
            ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
            SetWindowTextA(hN, p->name); SetWindowTextA(hS, p->server); SetWindowTextA(hPrt, p->port); SetWindowTextA(hU, p->user); SetWindowTextA(hP, p->pass); 
            SendMessageA(hChkFTP, BM_SETCHECK, p->is_ftp ? BST_CHECKED : BST_UNCHECKED, 0); SendMessageA(hChkSMB2, BM_SETCHECK, p->proto_pref == PROTO_SMB2 ? BST_CHECKED : BST_UNCHECKED, 0);
            char hist_copy[512]; strcpy(hist_copy, p->shares_hist); char *token = strtok(hist_copy, "|"); while (token) { SendMessageA(hSh, CB_ADDSTRING, 0, (LPARAM)token); token = strtok(NULL, "|"); } SetWindowTextA(hSh, p->share);
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas"); EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF); return 0;
        }
        case DM_GETDEFID: return MAKELRESULT(IDB_SAVE, DC_HASDEFID);
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (id == IDB_TEST) {
                char srv[128], prt[16], usr[64], pwd[64]; GetWindowTextA(hS, srv, sizeof(srv)); GetWindowTextA(hPrt, prt, sizeof(prt)); GetWindowTextA(hU, usr, sizeof(usr)); GetWindowTextA(hP, pwd, sizeof(pwd));
                add_log("Testing connection and enumerating shares for %s...", srv);
                WSADATA wd; WSAStartup(MAKEWORD(2,2), &wd);
                struct addrinfo hints={0}, *res; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
                char *cport = (prt[0] != '\0') ? prt : "445";
                
                if (getaddrinfo(srv, cport, &hints, &res) == 0) {
                    g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                    if (connect_with_timeout(g_app.sconn, res->ai_addr, res->ai_addrlen)) {
                        strcpy(g_app.pending_server, srv);
                        g_app.uid = 0; g_app.tid = 0; g_app.mid_counter = 1; g_app.smb2_message_id = 0; g_app.smb2_session_id = 0; g_app.smb2_tree_id = 0;
                        int smb2_connected = 0; int smb1_connected = 0;
                        int proto_pref = (SendMessageA(hChkSMB2, BM_GETCHECK, 0, 0) == BST_CHECKED) ? PROTO_SMB2 : PROTO_AUTO;
                        
                        if (proto_pref == PROTO_SMB1 || proto_pref == PROTO_AUTO) {
                            g_app.uid = 0; g_app.tid = 0; g_app.mid_counter = 1;
                            if (smb_negotiate()) {
                                int auth_success = smb_session(usr, pwd);
                                if (!auth_success && (strlen(usr) > 0 || strlen(pwd) > 0)) {
                                    closesocket(g_app.sconn); g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                                    if (connect_with_timeout(g_app.sconn, res->ai_addr, res->ai_addrlen)) { g_app.uid = 0; g_app.tid = 0; g_app.mid_counter = 1; if (smb_negotiate()) { auth_success = smb_session("", ""); } }
                                }
                                if (auth_success) smb1_connected = 1;
                            }
                        }
                        if (!smb1_connected && (proto_pref == PROTO_SMB2 || proto_pref == PROTO_AUTO)) {
                            closesocket(g_app.sconn); g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                            if (connect_with_timeout(g_app.sconn, res->ai_addr, res->ai_addrlen)) { if (smb2_negotiate()) { if (smb2_session_setup(usr, pwd)) { smb2_connected = 1; } } }
                        }
                        if (smb2_connected || smb1_connected) {
                            char shares[MAX_SHARES][64]; int count = enumerate_shares(shares, MAX_SHARES, smb2_connected);
                            if (count > 0) {
                                SendMessageA(hSh, CB_RESETCONTENT, 0, 0); char new_hist[512] = {0};
                                for(int i = 0; i < count; i++) { SendMessageA(hSh, CB_ADDSTRING, 0, (LPARAM)shares[i]); if (i > 0) strcat(new_hist, "|"); strcat(new_hist, shares[i]); }
                                SendMessageA(hSh, CB_SETCURSEL, 0, 0); strcpy(g_app.connections[g_app.selected_conn_idx].shares_hist, new_hist); add_log("Found %d shares.", count);
                            } else { add_log("Connected but no readable shares found."); }
                        } else { add_log("Session setup (authentication) failed."); }
                        if (g_app.sconn) { closesocket(g_app.sconn); g_app.sconn = 0; }
                    } else add_log("Socket connection failed (50ms timeout).");
                    freeaddrinfo(res);
                } else add_log("Host lookup failed.");
            }
            else if (id == IDB_SAVE || id == IDOK) {
                ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
                GetWindowTextA(hN, p->name, 64); GetWindowTextA(hS, p->server, 128); GetWindowTextA(hPrt, p->port, 16); GetWindowTextA(hSh, p->share, 128); GetWindowTextA(hU, p->user, 64); GetWindowTextA(hP, p->pass, 64);
                p->is_ftp = (SendMessageA(hChkFTP, BM_GETCHECK, 0, 0) == BST_CHECKED); p->proto_pref = (SendMessageA(hChkSMB2, BM_GETCHECK, 0, 0) == BST_CHECKED) ? PROTO_SMB2 : PROTO_AUTO;
                SendMessageA(g_app.hComboConn, CB_DELETESTRING, g_app.selected_conn_idx, 0); SendMessageA(g_app.hComboConn, CB_INSERTSTRING, g_app.selected_conn_idx, (LPARAM)p->name); SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0); save_config(GetWindow(hwnd, GW_OWNER)); add_log("Connection profile saved.");
            } else if (id == IDB_ADD) {
                if (g_app.conn_count >= g_app.conn_capacity) { g_app.conn_capacity = (g_app.conn_capacity == 0) ? 10 : g_app.conn_capacity * 2; g_app.connections = (ConnectionProfile*)realloc(g_app.connections, g_app.conn_capacity * sizeof(ConnectionProfile)); }
                int idx = g_app.conn_count++;
                GetWindowTextA(hN, g_app.connections[idx].name, 64); GetWindowTextA(hS, g_app.connections[idx].server, 128); GetWindowTextA(hPrt, g_app.connections[idx].port, 16); GetWindowTextA(hSh, g_app.connections[idx].share, 128); GetWindowTextA(hU, g_app.connections[idx].user, 64); GetWindowTextA(hP, g_app.connections[idx].pass, 64);
                g_app.connections[idx].is_ftp = (SendMessageA(hChkFTP, BM_GETCHECK, 0, 0) == BST_CHECKED); g_app.connections[idx].proto_pref = (SendMessageA(hChkSMB2, BM_GETCHECK, 0, 0) == BST_CHECKED) ? PROTO_SMB2 : PROTO_AUTO; strcpy(g_app.connections[idx].shares_hist, g_app.connections[g_app.selected_conn_idx].shares_hist);
                if (strlen(g_app.connections[idx].name) == 0) { strcpy(g_app.connections[idx].name, "New Connection"); SetWindowTextA(hN, "New Connection"); }
                SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[idx].name); g_app.selected_conn_idx = idx; SendMessageA(g_app.hComboConn, CB_SETCURSEL, idx, 0); save_config(GetWindow(hwnd, GW_OWNER)); add_log("New connection profile added.");
            } else if (id == IDB_DELETE) {
                if (g_app.conn_count > 1) {
                    int del_idx = g_app.selected_conn_idx; for (int i = del_idx; i < g_app.conn_count - 1; i++) g_app.connections[i] = g_app.connections[i + 1];
                    g_app.conn_count--; if (g_app.selected_conn_idx >= g_app.conn_count) g_app.selected_conn_idx = g_app.conn_count - 1;
                    SendMessageA(g_app.hComboConn, CB_RESETCONTENT, 0, 0); for (int i = 0; i < g_app.conn_count; i++) SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[i].name); SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0);
                    ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
                    SetWindowTextA(hN, p->name); SetWindowTextA(hS, p->server); SetWindowTextA(hPrt, p->port); SetWindowTextA(hSh, p->share); SetWindowTextA(hU, p->user); SetWindowTextA(hP, p->pass); SendMessageA(hChkFTP, BM_SETCHECK, p->is_ftp ? BST_CHECKED : BST_UNCHECKED, 0); SendMessageA(hChkSMB2, BM_SETCHECK, p->proto_pref == PROTO_SMB2 ? BST_CHECKED : BST_UNCHECKED, 0);
                    SendMessageA(hSh, CB_RESETCONTENT, 0, 0); char hist_copy[512]; strcpy(hist_copy, p->shares_hist); char *token = strtok(hist_copy, "|"); while (token) { SendMessageA(hSh, CB_ADDSTRING, 0, (LPARAM)token); token = strtok(NULL, "|"); } SetWindowTextA(hSh, p->share); save_config(GetWindow(hwnd, GW_OWNER)); add_log("Connection profile deleted.");
                } else add_log("Cannot delete the last remaining connection profile.");
            } else if (id == IDB_CANCEL || id == IDCANCEL) { SendMessageA(hwnd, WM_CLOSE, 0, 0); }
            break;
        }
        case WM_CLOSE: EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE); DestroyWindow(hwnd); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            init_ini_path(); g_app.hMain = hwnd; g_app.conn_type = CONN_NONE; g_app.current_proto = PROTO_AUTO;
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas");
            int x = 10;
            g_app.hComboConn = CreateWindowExA(0, "COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_TABSTOP, x, 10, 180, 200, hwnd, (HMENU)ID_COMBO_CONN, g_hInst, NULL); x += 185;
            g_app.hBtnEdit = CreateWindowExA(0, "BUTTON", "Edit", WS_CHILD|WS_VISIBLE|WS_TABSTOP, x, 10, 45, 25, hwnd, (HMENU)ID_BTN_EDIT_CONN, g_hInst, NULL); x += 50;
            g_app.hBtnConnect = CreateWindowExA(0, "BUTTON", "Connect", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, x, 10, 65, 25, hwnd, (HMENU)ID_BTN_CONNECT, g_hInst, NULL); x += 70;
            g_app.hBtnCopy = CreateWindowExA(0, "BUTTON", "Copy", WS_CHILD|WS_VISIBLE|WS_TABSTOP, x, 10, 55, 25, hwnd, (HMENU)ID_BTN_COPY, g_hInst, NULL); x += 60;
            g_app.hBtnMove = CreateWindowExA(0, "BUTTON", "Move", WS_CHILD|WS_VISIBLE|WS_TABSTOP, x, 10, 55, 25, hwnd, (HMENU)ID_BTN_MOVE, g_hInst, NULL); x += 60;
            g_app.hBtnRename = CreateWindowExA(0, "BUTTON", "Rename", WS_CHILD|WS_VISIBLE|WS_TABSTOP, x, 10, 60, 25, hwnd, (HMENU)ID_BTN_RENAME, g_hInst, NULL); x += 65;
            g_app.hBtnDelete = CreateWindowExA(0, "BUTTON", "Delete", WS_CHILD|WS_VISIBLE|WS_TABSTOP, x, 10, 60, 25, hwnd, (HMENU)ID_BTN_DELETE, g_hInst, NULL); x += 65;
            g_app.hBtnMkDir = CreateWindowExA(0, "BUTTON", "MkDir", WS_CHILD|WS_VISIBLE|WS_TABSTOP, x, 10, 55, 25, hwnd, (HMENU)ID_BTN_MKDIR, g_hInst, NULL);
            g_app.hLblLocal = CreateWindowExA(0, "STATIC", "Local:", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
            g_app.hLblRemote = CreateWindowExA(0, "STATIC", "Remote:", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
            g_app.hLocalList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOTIFY|LBS_EXTENDEDSEL|WS_TABSTOP, 0, 0, 0, 0, hwnd, (HMENU)ID_LIST_LOCAL, g_hInst, NULL);
            g_app.hRemoteList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOTIFY|LBS_EXTENDEDSEL|WS_TABSTOP, 0, 0, 0, 0, hwnd, (HMENU)ID_LIST_REMOTE, g_hInst, NULL);
            OldListProc = (WNDPROC)SetWindowLongPtr(g_app.hLocalList, GWLP_WNDPROC, (LONG_PTR)ListSubProc); SetWindowLongPtr(g_app.hRemoteList, GWLP_WNDPROC, (LONG_PTR)ListSubProc);
            g_app.hStatus = CreateWindowExA(0, "STATIC", "Ready", WS_CHILD|WS_VISIBLE|SS_LEFT|SS_NOTIFY, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);
            g_app.hProgress = CreateWindowExA(0, PROGRESS_CLASSA, NULL, WS_CHILD|WS_VISIBLE|PBS_SMOOTH, 0, 0, 0, 0, hwnd, (HMENU)ID_PROGRESS, g_hInst, NULL); ShowWindow(g_app.hProgress, SW_HIDE); SendMessageA(g_app.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100)); SendMessageA(g_app.hProgress, PBM_SETPOS, 0, 0);
            g_hToolTip = CreateWindowExA(WS_EX_TOPMOST, TOOLTIPS_CLASSA, NULL, WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL); SendMessageA(g_hToolTip, TTM_SETMAXTIPWIDTH, 0, 600);
            TOOLINFOA ti = {0}; ti.cbSize = sizeof(TOOLINFOA); ti.hwnd = hwnd; ti.uFlags = TTF_SUBCLASS | TTF_IDISHWND; ti.uId = (UINT_PTR)g_app.hStatus; ti.lpszText = g_conn_log; SendMessageA(g_hToolTip, TTM_ADDTOOLA, 0, (LPARAM)&ti);
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF);
            load_config(hwnd); for (int i=0; i<g_app.conn_count; i++) SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[i].name); SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0);
            GetModuleFileNameA(NULL, g_app.local_base, MAX_PATH); char *last_slash = strrchr(g_app.local_base, '\\'); if (last_slash) *last_slash = '\0';
            list_local(); g_app.active_pane = PANE_LOCAL; update_remote_list();
            return 0;
        }
        case DM_GETDEFID: return MAKELRESULT(ID_BTN_CONNECT, DC_HASDEFID);
        case WM_TIMER: { if (wp == TIMER_PROGRESS_HIDE) { KillTimer(hwnd, TIMER_PROGRESS_HIDE); ShowWindow(g_app.hProgress, SW_HIDE); } return 0; }
        case WM_SIZE: {
            int w = LOWORD(lp), h = HIWORD(lp); int progress_w = 180;
            SetWindowPos(g_app.hLblLocal, NULL, 0, 45, w/2, 20, SWP_NOZORDER); SetWindowPos(g_app.hLblRemote, NULL, w/2, 45, w/2, 20, SWP_NOZORDER);
            SetWindowPos(g_app.hLocalList, NULL, 0, 65, w/2, h-95, SWP_NOZORDER); SetWindowPos(g_app.hRemoteList, NULL, w/2, 65, w/2, h-95, SWP_NOZORDER);
            SetWindowPos(g_app.hStatus, NULL, 0, h-25, w - progress_w - 10, 25, SWP_NOZORDER); SetWindowPos(g_app.hProgress, NULL, w - progress_w - 5, h-25, progress_w, 20, SWP_NOZORDER);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (HIWORD(wp) == LBN_SETFOCUS) g_app.active_pane = (id == ID_LIST_REMOTE) ? PANE_REMOTE : PANE_LOCAL;
            if (HIWORD(wp) == LBN_DBLCLK) {
                int is_rem = (id == ID_LIST_REMOTE); HWND hL = is_rem ? g_app.hRemoteList : g_app.hLocalList; int idx = SendMessageA(hL, LB_GETCURSEL, 0, 0);
                if (idx >= 0) {
                    char *item = is_rem ? g_app.remote_items[idx].path : g_app.local_items[idx].path; int dir = is_rem ? g_app.remote_items[idx].is_dir : g_app.local_items[idx].is_dir;
                    if (dir) {
                        if (is_rem) {
                            char sep = (g_app.conn_type == CONN_FTP) ? '/' : '\\';
                            if (strcmp(item, "..") == 0) { char *ls = strrchr(g_app.remote_base, sep); if (ls && ls != g_app.remote_base) *ls = '\0'; else if (ls == g_app.remote_base) *(ls+1) = '\0'; } 
                            else if (strcmp(item, ".") != 0) { if (g_app.remote_base[strlen(g_app.remote_base)-1] != sep) { char sep_str[2] = {sep, '\0'}; strcat(g_app.remote_base, sep_str); } strcat(g_app.remote_base, item); }
                            list_remote();
                        } else {
                            if (strcmp(item, "..") == 0) { if (strlen(g_app.local_base) <= 3 && g_app.local_base[1] == ':') strcpy(g_app.local_base, ""); else { char *ls = strrchr(g_app.local_base, '\\'); if (ls) { if (ls == g_app.local_base + 2) *(ls + 1) = '\0'; else *ls = '\0'; } } } 
                            else if (strcmp(item, ".") != 0) { if (strlen(g_app.local_base) == 0) snprintf(g_app.local_base, MAX_PATH, "%s\\", item); else { if (g_app.local_base[strlen(g_app.local_base)-1] != '\\') strcat(g_app.local_base, "\\"); strcat(g_app.local_base, item); } }
                            list_local();
                        }
                    }
                }
            }
            switch (id) {
                case ID_BTN_CONNECT:
                case IDOK: {
                    int idx = SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0); if (idx == CB_ERR) break;
                    g_app.selected_conn_idx = idx; save_config(hwnd); 
                    if (g_app.connections[idx].is_ftp) connect_ftp(&g_app.connections[idx]); else connect_server(&g_app.connections[idx]);
                    break;
                }
                case ID_BTN_EDIT_CONN: {
                    g_app.selected_conn_idx = SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0);
                    CreateWindowExA(WS_EX_DLGMODALFRAME, "EditConnClass", "Edit Connection", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 335, 290, hwnd, NULL, g_hInst, NULL); EnableWindow(hwnd, FALSE); break;
                }
                case ID_BTN_COPY: case ID_BTN_MOVE: case ID_BTN_RENAME: case ID_BTN_DELETE: case ID_BTN_MKDIR: do_action(id); break;
            }
            break;
        }
        case WM_DESTROY: disconnect_all(); save_config(hwnd); if (g_app.connections) free(g_app.connections); PostQuitMessage(0); ExitProcess(0); break;
        default: return DefWindowProcA(hwnd, msg, wp, lp);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex; icex.dwSize = sizeof(INITCOMMONCONTROLSEX); icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex); srand((unsigned)time(NULL)); g_hInst = hInst; memset(&g_app, 0, sizeof(g_app)); g_app.mid_counter = 1;
    WNDCLASSEXA wc={sizeof(WNDCLASSEXA),CS_HREDRAW|CS_VREDRAW,MainWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"MainClass",NULL}; RegisterClassExA(&wc);
    WNDCLASSEXA wce={sizeof(WNDCLASSEXA),0,EditConnWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"EditConnClass",NULL}; RegisterClassExA(&wce);
    WNDCLASSEXA wcr={sizeof(WNDCLASSEXA),0,RenameWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"RenameClass",NULL}; RegisterClassExA(&wcr);
    WNDCLASSEXA wcm={sizeof(WNDCLASSEXA),0,CreateDirWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"CreateDirClass",NULL}; RegisterClassExA(&wcm);
    
    HWND hwnd = CreateWindowExA(WS_EX_CONTROLPARENT, "MainClass", "Dual Pane SMB1/SMB2/FTP Client", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInst, NULL);
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    
    MSG msg; BOOL bRet; 
    while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0) { 
        if (bRet == -1) break; 
        HWND hActive = GetActiveWindow();
        if (hActive && IsDialogMessage(hActive, &msg)) continue;
        TranslateMessage(&msg); DispatchMessage(&msg); 
    }
    ExitProcess((UINT)msg.wParam); return (int)msg.wParam;
}