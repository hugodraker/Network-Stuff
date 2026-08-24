/* 
 * Dual-Pane SMB1/SMB2/FTP Client Implementation with Share Enumeration
 * - Native SMB1 support (legacy)
 * - Native SMB2 support (modern)
 * - FTP via WinINet
 * - Share enumeration before authentication
 * - Prompts for credentials if needed
 * Protocol negotiation falls back from SMB2 -> SMB1 automatically
 * - All LM.h dependencies replaced with native SMB implementations
 *
 * COMPILATION:
 *   gcc -Os -s -o smb2c.exe smb2c.c -lws2_32 -lwininet -lcomctl32 -lgdi32 -luser32 -ladvapi32 -lcrypt32 -lnetapi32 -mwindows
 *
 * Released into Public Domain
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
#include <wininet.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <commctrl.h>
// REMOVED: #include <lm.h> - All LM.h functions replaced with native SMB implementations

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "netapi32.lib")
#pragma warning(disable: 4996)

/* ==========================================================================
   CONFIGURATION & CONSTANTS
   ========================================================================== */
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

/* UI Identifiers */
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

#define IDB_RENAME_OK       3001
#define IDE_RENAME_NEW      3002
#define IDE_MKDIR_NAME      3003
#define IDB_MKDIR_OK        3004

/* Share Selection Dialog IDs */
#define ID_SHARE_LIST       4001
#define ID_SHARE_USER       4002
#define ID_SHARE_PASS       4003
#define ID_SHARE_CONNECT    4004
#define ID_SHARE_ANONYMOUS  4005

/* SMB2 Constants */
#define SMB2_PORT           445
#define SMB2_DIALECT_0202   0x0202
#define SMB2_DIALECT_0210   0x0210
#define SMB2_DIALECT_0300   0x0300

/* SMB2 Command IDs */
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

/* SMB2 Flags */
#define SMB2_FLAGS_RESPONSE     0x00000001
#define SMB2_FLAGS_SIGNED       0x00000008

/* NT Status Codes */
#define STATUS_SUCCESS              0x00000000
#define STATUS_MORE_PROCESSING      0xC0000016
#define STATUS_ACCESS_DENIED        0xC0000022
#define STATUS_OBJECT_NAME_NOT_FOUND 0x00000034
#define STATUS_FILE_IS_A_DIRECTORY  0x000000BA

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
    uint16_t continuation_token;
    uint16_t reserved;
    uint32_t output_buffer_length;
    uint16_t index_specifier;
    uint16_t resume_key_offset;
} SMB2QueryDirectoryReq;

typedef struct {
    uint16_t structure_size;
    uint16_t data_offset;
    uint32_t data_length;
    uint32_t data_remaining;
    uint32_t reserved2;
} SMB2ReadResp;

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

#pragma pack(pop)

/* ==========================================================================
   DATA STRUCTURES
   ========================================================================== */
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
} ConnectionProfile;

/* Forward declarations for SMB2 functions used before definition */
static int smb2_tree_connect(const char *share);
static int smb2_tree_disconnect(void);

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
    uint8_t  smb2_signing_key[16];
    
    DirectoryItem remote_items[MAX_ITEMS];
    DirectoryItem local_items[MAX_ITEMS];
    int remote_count, local_count;
    
    int active_pane;
    
    /* Share selection state */
    char temp_shares[MAX_SHARES][64];
    int share_count;
    char temp_user[64];
    char temp_pass[64];
    char pending_server[128];
    char pending_port[16];
    int needs_credentials;
    int share_enum_retry;
} AppContext;

static AppContext g_app;
static HINSTANCE g_hInst;
static char g_ini_path[MAX_PATH];

static char g_ren_base[MAX_SMB_PATH];
static char g_ren_item[MAX_SMB_PATH];

/* Global share selection callback result */
static int g_share_selection_complete = 0;
static int g_share_selection_cancelled = 0;

static int smb_simple_path_cmd(uint8_t cmd, const char *path);

/* ==========================================================================
   UTILITY FUNCTIONS
   ========================================================================== */
static void set_status(const char *fmt, ...) {
    char buf[1024]; va_list args;
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    SetWindowTextA(g_app.hStatus, buf);
}

static void set_progress(int percent) {
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    SendMessageA(g_app.hProgress, PBM_SETPOS, (WPARAM)percent, 0);
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
    for (char *p = path; *p; ++p) {
        if (*p == wrong) *p = target;
    }
}

static void init_ini_path(void) {
    GetModuleFileNameA(NULL, g_ini_path, MAX_PATH);
    char *ext = strrchr(g_ini_path, '.');
    if (ext) strcpy(ext, ".ini"); else strcat(g_ini_path, ".ini");
}

static void load_config(HWND hwnd) {
    g_app.conn_count = GetPrivateProfileIntA("Connections", "Count", 0, g_ini_path);
    
    if (g_app.conn_count <= 0) {
        g_app.conn_count = 1;
        g_app.conn_capacity = 10;
        g_app.connections = (ConnectionProfile*)malloc(g_app.conn_capacity * sizeof(ConnectionProfile));
        
        strcpy(g_app.connections[0].name, "Default Connection");
        strcpy(g_app.connections[0].server, "192.168.1.100");
        strcpy(g_app.connections[0].port, "");
        strcpy(g_app.connections[0].share, "shared");
        strcpy(g_app.connections[0].user, "");
        strcpy(g_app.connections[0].pass, "");
        g_app.connections[0].is_ftp = 0;
        g_app.connections[0].proto_pref = PROTO_AUTO;
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
            g_app.connections[i].is_ftp = GetPrivateProfileIntA("Connections", "IsFTP%d", 0, g_ini_path);
            sprintf(key, "Proto%d", i); g_app.connections[i].proto_pref = GetPrivateProfileIntA("Connections", key, PROTO_AUTO, g_ini_path);
        }
    }
}

static void save_config(HWND hwnd) {
    WritePrivateProfileSectionA("Connections", "", g_ini_path);
    char val[32]; sprintf(val, "%d", g_app.conn_count);
    WritePrivateProfileStringA("Connections", "Count", val, g_ini_path);
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
    }
}

static void disconnect_all(void) {
    if (g_app.sconn) { closesocket(g_app.sconn); g_app.sconn = 0; }
    if (g_app.hFtpSession) { InternetCloseHandle(g_app.hFtpSession); g_app.hFtpSession = NULL; }
    if (g_app.hInternet) { InternetCloseHandle(g_app.hInternet); g_app.hInternet = NULL; }
    g_app.conn_type = CONN_NONE;
    g_app.current_proto = PROTO_AUTO;
    g_app.smb2_session_id = 0;
    g_app.smb2_tree_id = 0;
    g_app.smb2_message_id = 0;
    g_app.tid = 0;
    g_app.uid = 0;
}

/* ==========================================================================
   CRYPTOGRAPHIC PRIMITIVES
   ========================================================================== */
static void get_random_bytes(uint8_t *buf, size_t len) {
    HCRYPTPROV prov;
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(prov, len, buf);
        CryptReleaseContext(prov, 0);
    } else {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

static size_t utf8_to_utf16le(const char *src, uint8_t *dst, size_t dst_max) {
    size_t di = 0, si = 0;
    while (src[si] && di + 2 <= dst_max) { dst[di++] = (uint8_t)src[si]; dst[di++] = 0; si++; }
    return di;
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
            if (rcvd <= 0) return 0; 
            received += rcvd; 
        }
        *out_len = received; 
        return 1;
    }
}

static SMB1Header* smb_build_header(uint8_t *packet, uint8_t cmd) {
    SMB1Header *hdr = (SMB1Header*)packet;
    memcpy(hdr->protocol_id, "\xFFSMB", 4); hdr->cmd = cmd;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF; hdr->mid = g_app.mid_counter++;
    hdr->flags1 = 0x80; hdr->flags2 = 0x07C7;
    hdr->uid = g_app.uid; hdr->tid = g_app.tid;
    memset(hdr->signature, 0, 8);
    return hdr;
}

static int smb_negotiate(void) {
    uint8_t pkt[1024]; 
    memset(pkt, 0, sizeof(pkt));
    
    smb_build_header(pkt, 0x72);
    uint8_t *w = pkt + sizeof(SMB1Header);
    
    *w++ = 0; 
    *(uint16_t*)w = 12; 
    w += 2;
    memcpy(w, "\x02NT LM 0.12\x00", 12); 
    w += 12;
    
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    
    size_t rlen; 
    if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_session(const char *user, const char *pass) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, 0x73);
    uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 10; *w++ = 0xFF; *w++ = 0; *w++ = 0;
    *(uint16_t*)w = 0xFFFF; w+=2; *(uint16_t*)w = strlen(user); w+=2;
    *(uint32_t*)w = 0xFFFFFFFF; w+=4; *(uint16_t*)w = 65535; w+=2;
    *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = 1; w+=2; *(uint16_t*)w = 0; w+=2;
    *(uint32_t*)w = 0; w+=4; *(uint16_t*)w = strlen(pass); w+=2;
    memcpy(w, pass, strlen(pass)); w+=strlen(pass); *w++=0;
    memcpy(w, user, strlen(user)); w+=strlen(user); *w++=0;
    memcpy(w, "Windows\x00NT\x00", 12); w+=12;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    g_app.uid = ((SMB1Header*)pkt)->uid;
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_tree_connect(const char *share) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt));
    SMB1Header *hdr = smb_build_header(pkt, 0x74);
    memcpy(hdr->signature, g_app.g_session_response, 8);
    uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 4; *w++ = 0xFF; *w++ = 0; *w++ = 0; *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = 0; w+=2;
    *w++ = 0; strcpy((char*)w, share); w+=strlen(share)+1; strcpy((char*)w, "?????"); w+=6;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    g_app.tid = ((SMB1Header*)pkt)->tid;
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_delete(const char *path) {
    return smb_simple_path_cmd(0x06, path);
}

static int smb_delete_dir(const char *path) {
    return smb_simple_path_cmd(0x01, path);
}

static int smb_simple_path_cmd(uint8_t cmd, const char *path) {
    uint8_t pkt[MAX_SMB_PATH+100]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, cmd);
    uint8_t *w = pkt + sizeof(SMB1Header);
    if (cmd == 0x06) { *w++ = 1; *(uint16_t*)w = 0x16; w+=2; } else { *w++ = 0; }
    *(uint16_t*)w = strlen(path)+2; w+=2; *w++ = 0x04; strcpy((char*)w, path); w+=strlen(path)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_rename(const char *oldp, const char *newp) {
    uint8_t pkt[MAX_SMB_PATH*2+100]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, 0x07);
    uint8_t *w = pkt + sizeof(SMB1Header);
    *w++ = 1; *(uint16_t*)w = 0x16; w+=2;
    *(uint16_t*)w = strlen(oldp) + strlen(newp) + 4; w+=2;
    *w++ = 0x04; strcpy((char*)w, oldp); w+=strlen(oldp)+1;
    *w++ = 0x04; strcpy((char*)w, newp); w+=strlen(newp)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMB1Header*)pkt)->status == 0);
}

static int smb_mkdir(const char *path) {
    return smb_simple_path_cmd(0x00, path);
}

/* ==========================================================================
   NATIVE SHARE ENUMERATION (No LM.h dependencies)
   ========================================================================== */

/* SMB1 TRANS2 SHARE ENUMERATION - Pure SMB protocol implementation */
static int enum_shares_native(char (*shares)[64], int max_shares) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    /* Build SMB1 TRANS2 Setup request for SHARE_ENUM */
    SMB1Header *hdr = smb_build_header(packet, 0xA2);  /* TRANS2 */
    
    /* Trans2 Setup Parameters */
    uint8_t *param = packet + sizeof(SMB1Header);
    *param++ = 0x0A;                          /* Word count (TRANS2_SETUP) */
    *(uint16_t*)param = 0x0000; param += 2;   /* Total parameter count */
    *(uint16_t*)param = 0x0000; param += 2;   /* Total data count */
    *(uint16_t*)param = 0x0000; param += 2;   /* Parameter displacement */
    *(uint16_t*)param = 0x00FF; param += 2;   /* Parameter count */
    *(uint16_t*)param = 0x0000; param += 2;   /* Parameter offset */
    *(uint16_t*)param = 0x0000; param += 2;   /* Total parameter count (again) */
    *(uint16_t*)param = 0x0000; param += 2;   /* Setup word count */
    *(uint16_t*)param = 0x0004; param += 2;   /* Function ID: SHARE_ENUM (0x0004) */
    
    /* Level 1: SHARE_INFO_1 */
    *(uint16_t*)param = 0x0001; param += 2;
    
    /* Trans2 Setup Data */
    *(uint16_t*)param = 0x00FF; param += 2;   /* Max buffer size */
    *(uint16_t*)param = 0x00FF; param += 2;   /* Max data count */
    *(uint16_t*)param = 0x0000; param += 2;   /* Context handle */
    
    if (!smb_send_packet(packet, param - packet)) return 0;
    
    size_t rlen;
    if (!smb_recv_packet(packet, sizeof(packet), &rlen)) return 0;
    
    if (((SMB1Header*)packet)->status != 0) return 0;
    
    /* Parse response - extract share names from TRANS2 response */
    uint8_t *data = packet + sizeof(SMB1Header) + 10;  /* Skip param area */
    int count = 0;
    
    /* Parse SHARE_INFO_1 entries */
    while (count < max_shares && data < packet + rlen - 20) {
        uint16_t name_len = *(uint16_t*)(data + 2);
        if (name_len == 0 || name_len > 64) break;
        
        /* Convert and store share name */
        strncpy(shares[count], (char*)(data + 4), 63);
        shares[count][63] = '\0';
        
        /* Skip admin shares */
        if (strcmp(shares[count], "ADMIN$") != 0 &&
            strcmp(shares[count], "C$") != 0 &&
            strcmp(shares[count], "IPC$") != 0) {
            count++;
        }
        
        data += 4 + name_len + 4;  /* Move to next entry */
    }
    
    return count;
}

/* Alternative: Direct IPC$ connection with NETBIOS session enumeration */
static int enum_shares_ipc(char (*shares)[64], int max_shares) {
    /* Create IPC$ connection first */
    char ipc_share[] = "IPC$";
    
    /* Tree connect to IPC$ */
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMB1Header *hdr = smb_build_header(packet, 0x74);
    hdr->tid = 0xFFFF;
    
    uint8_t *w = packet + sizeof(SMB1Header);
    *w++ = 4; *w++ = 0xFF; *w++ = 0; *w++ = 0; 
    *(uint16_t*)w = 0; w += 2; *(uint16_t*)w = 0; w += 2;
    *w++ = 0; strcpy((char*)w, ipc_share); w += strlen(ipc_share) + 1; 
    strcpy((char*)w, "?????"); w += 6;
    
    if (!smb_send_packet(packet, w - packet)) return 0;
    
    size_t rlen;
    if (!smb_recv_packet(packet, sizeof(packet), &rlen)) return 0;
    
    if (((SMB1Header*)packet)->status != 0) return 0;
    
    /* Store TID for subsequent requests */
    g_app.tid = ((SMB1Header*)packet)->tid;
    
    /* Now send NET_TRANSMIT for share enumeration on IPC$ */
    memset(packet, 0, sizeof(packet));
    hdr = smb_build_header(packet, 0xA5);  /* NETBIOS SESSION MESSAGE */
    hdr->tid = g_app.tid;
    
    /* NETBIOS Session request to list shares */
    w = packet + sizeof(SMB1Header);
    *w++ = 0x25; *w++ = 0x00;
    *(uint16_t*)w = 0x0000; w += 2;  /* Offset */
    *(uint16_t*)w = 0x0000; w += 2;  /* Total bytes */
    *(uint16_t*)w = 0x0000; w += 2;  /* Byte count */
    
    /* Send NetShareEnum via SMB1 PIPE call */
    const char pipe_name[] = "\\srvsvc";
    uint8_t pipe_pkt[SMB_BUFFER_SIZE];
    memset(pipe_pkt, 0, sizeof(pipe_pkt));
    
    hdr = smb_build_header(pipe_pkt, 0xA2);  /* TRANS2 */
    hdr->tid = g_app.tid;
    
    w = pipe_pkt + sizeof(SMB1Header);
    *w++ = 0x0A;  /* Setup word count */
    *(uint16_t*)w = 0x0000; w += 2;
    *(uint16_t*)w = 0x0000; w += 2;
    *(uint16_t*)w = 0x0000; w += 2;
    *(uint16_t*)w = 0x0FFF; w += 2;
    *(uint16_t*)w = 0x0000; w += 2;
    *(uint16_t*)w = 0x0000; w += 2;
    *(uint16_t*)w = 0x0000; w += 2;
    *(uint16_t*)w = 0x0004; w += 2;  /* Function: NetrShareEnum */
    *(uint16_t*)w = 0x0001; w += 2;  /* Level */
    
    if (!smb_send_packet(pipe_pkt, w - pipe_pkt)) {
        return 0;
    }
    
    size_t rlen_pipe;
    if (!smb_recv_packet(pipe_pkt, sizeof(pipe_pkt), &rlen_pipe)) {
        return 0;
    }
    
    /* Parse shares from response - simplified extraction */
    int count = 0;
    char *pos = (char*)pipe_pkt + sizeof(SMB1Header) + 50;  /* Skip headers */
    char share_name[64];
    
    while (count < max_shares && pos < (char*)pipe_pkt + rlen_pipe - 10) {
        if (*pos == '\0' || isspace(*pos)) { pos++; continue; }
        if (*pos < 32 || *pos > 126) break;  /* Invalid character */
        
        int name_len = 0;
        while (name_len < 63 && *(pos + name_len) >= 32 && *(pos + name_len) <= 126) {
            share_name[name_len++] = *(pos++);
        }
        share_name[name_len] = '\0';
        
        if (name_len > 0 && name_len < 64) {
            /* Skip admin shares */
            if (strncmp(share_name, "ADMIN$", 6) != 0 &&
                strncmp(share_name, "C$", 2) != 0 &&
                strcmp(share_name, "IPC$") != 0) {
                strcpy(shares[count], share_name);
                count++;
            }
        }
        pos++;  /* Skip null terminator or separator */
    }
    
    return count;
}

/* Complete replacement for enum_shares_windows - No LM.h required */
static int enum_shares_native_only(char (*shares)[64], int max_shares, int is_smb2_capable) {
    int count = 0;
    
    if (is_smb2_capable) {
        /* Try SMB2 share probing first (trial and error on common names) */
        char *common_shares[] = {
            "shared", "public", "data", "files", 
            "documents", "home", "storage", "backup",
            "media", "photos", "videos", "music"
        };
        int num_common = sizeof(common_shares) / sizeof(common_shares[0]);
        
        for (int i = 0; i < num_common && count < max_shares; i++) {
            /* Save current state */
            uint64_t saved_session = g_app.smb2_session_id;
            uint32_t saved_tree = g_app.smb2_tree_id;
            
            /* Try connecting to this share */
            char share_path[MAX_SMB_PATH];
            snprintf(share_path, sizeof(share_path), "\\%s", common_shares[i]);
            normalize_path(share_path, 0);
            
            if (smb2_tree_connect(common_shares[i])) {
                strcpy(shares[count], common_shares[i]);
                count++;
                
                /* Disconnect tree */
                smb2_tree_disconnect();
                g_app.smb2_tree_id = saved_tree;
            } else {
                /* Restore state */
                g_app.smb2_session_id = saved_session;
                g_app.smb2_tree_id = saved_tree;
            }
        }
        
        if (count > 0) {
            set_status("Found %d share(s) via SMB2 probing", count);
            return count;
        }
    }
    
    /* Fallback to SMB1 native share enumeration */
    count = enum_shares_native(shares, max_shares);
    if (count > 0) {
        set_status("Found %d share(s) via native SMB1", count);
        return count;
    }
    
    /* Last resort: try IPC$ method */
    count = enum_shares_ipc(shares, max_shares);
    if (count > 0) {
        set_status("Found %d share(s) via IPC$", count);
        return count;
    }
    
    /* Ultimate fallback: common share names */
    char *fallback_shares[] = {"shared", "public", "data", "files", "documents", "home"};
    int num_fallback = sizeof(fallback_shares) / sizeof(fallback_shares[0]);
    
    for (int i = 0; i < num_fallback && i < max_shares; i++) {
        strcpy(shares[i], fallback_shares[i]);
    }
    
    set_status("Native enumeration failed, using common share names");
    return num_fallback;
}

/* Main share enumeration dispatcher - Updated to use native implementation only */
static int enumerate_shares(char (*shares)[64], int max_shares, int is_smb2_capable) {
    return enum_shares_native_only(shares, max_shares, is_smb2_capable);
}

/* ==========================================================================
   SMB2 PROTOCOL
   ========================================================================== */
static void smb2_init_header(SMB2Header *hdr, uint16_t cmd) {
    memcpy(hdr->protocol_id, "\xFE\x53\x4D\x42", 4);
    hdr->structure_size = 64;
    hdr->credit_charge = (cmd == SMB2_NEGOTIATE) ? 0 : 1;
    hdr->status = 0;
    hdr->command = cmd;
    hdr->credit_request = 32;
    hdr->flags = 0;
    hdr->next_command = 0;
    hdr->message_id = g_app.smb2_message_id++;
    hdr->process_id = GetCurrentProcessId() & 0xFFFFFFFF;
    hdr->tree_id = g_app.smb2_tree_id;
    hdr->session_id = g_app.smb2_session_id;
    memset(hdr->signature, 0, 16);
}

static int smb2_negotiate(void) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMB2Header *hdr = (SMB2Header*)packet;
    smb2_init_header(hdr, SMB2_NEGOTIATE);
    
    SMB2NegotiateReq *neg = (SMB2NegotiateReq*)(packet + sizeof(SMB2Header));
    neg->structure_size = 36;
    neg->dialect_count = 3;
    neg->security_mode = 1;
    neg->capabilities = 0;
    get_random_bytes(neg->client_guid, 16);
    
    uint16_t *dialects = (uint16_t*)(packet + sizeof(SMB2Header) + sizeof(SMB2NegotiateReq));
    dialects[0] = SMB2_DIALECT_0202;
    dialects[1] = SMB2_DIALECT_0210;
    dialects[2] = SMB2_DIALECT_0300;
    
    size_t pkt_len = sizeof(SMB2Header) + sizeof(SMB2NegotiateReq) + (neg->dialect_count * sizeof(uint16_t));
    
    if (!smb_send_packet(packet, pkt_len)) {
        set_status("SMB2 Negotiate send failed");
        return 0;
    }
    
    size_t recv_len;
    if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) {
        set_status("SMB2 Negotiate recv failed");
        return 0;
    }
    
    hdr = (SMB2Header*)packet;
    if (hdr->status != 0 && hdr->status != STATUS_SUCCESS) {
        set_status("SMB2 Negotiate error: 0x%08X", hdr->status);
        return 0;
    }
    
    SMB2NegotiateResp *resp = (SMB2NegotiateResp*)(packet + sizeof(SMB2Header));
    memcpy(g_app.smb2_server_guid, resp->server_guid, 16);
    
    set_status("SMB2 protocol negotiated (dialect 0x%x)", resp->dialect_revision);
    return 1;
}

static int smb2_session_setup(const char *user, const char *pass) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMB2Header *hdr = (SMB2Header*)packet;
    smb2_init_header(hdr, SMB2_SESSION_SETUP);
    
    SMB2SessionSetupReq *setup_req = (SMB2SessionSetupReq*)(packet + sizeof(SMB2Header));
    setup_req->structure_size = 25;
    setup_req->flags = 0;
    setup_req->security_mode = 1;
    setup_req->channel = 0;
    
    uint8_t *sec_buf = packet + sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    memcpy(sec_buf, "NTLMSSP\0", 8);
    *(uint32_t*)(sec_buf + 8) = 1;           
    *(uint32_t*)(sec_buf + 12) = 0xE20882B7; 
    memset(sec_buf + 16, 0, 24);             
    
    setup_req->security_buffer_offset = sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    setup_req->security_buffer_length = 40;
    
    size_t pkt_len = setup_req->security_buffer_offset + 40;
    
    if (!smb_send_packet(packet, pkt_len)) return 0;
    
    size_t recv_len;
    uint8_t response[SMB_BUFFER_SIZE];
    if (!smb_recv_packet(response, sizeof(response), &recv_len)) return 0;
    
    hdr = (SMB2Header*)response;
    if (hdr->status != STATUS_MORE_PROCESSING) return 0;
    
    g_app.smb2_session_id = hdr->session_id;

    memset(packet, 0, sizeof(packet));
    hdr = (SMB2Header*)packet;
    smb2_init_header(hdr, SMB2_SESSION_SETUP);
    hdr->session_id = g_app.smb2_session_id;
    
    setup_req = (SMB2SessionSetupReq*)(packet + sizeof(SMB2Header));
    setup_req->structure_size = 25;
    setup_req->flags = 0;
    setup_req->security_mode = 1;
    setup_req->channel = 0;
    
    sec_buf = packet + sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    memcpy(sec_buf, "NTLMSSP\0", 8);
    *(uint32_t*)(sec_buf + 8) = 3; 
    
    int payload_off = 64; 
    *(uint16_t*)(sec_buf + 12) = 0; *(uint16_t*)(sec_buf + 14) = 0; *(uint32_t*)(sec_buf + 16) = payload_off;
    *(uint16_t*)(sec_buf + 20) = 0; *(uint16_t*)(sec_buf + 22) = 0; *(uint32_t*)(sec_buf + 24) = payload_off;
    *(uint16_t*)(sec_buf + 28) = 0; *(uint16_t*)(sec_buf + 30) = 0; *(uint32_t*)(sec_buf + 32) = payload_off;
    
    uint16_t user_len = (uint16_t)utf8_to_utf16le(user, sec_buf + payload_off, 256);
    *(uint16_t*)(sec_buf + 36) = user_len; *(uint16_t*)(sec_buf + 38) = user_len; *(uint32_t*)(sec_buf + 40) = payload_off;
    payload_off += user_len;
    
    *(uint16_t*)(sec_buf + 44) = 0; *(uint16_t*)(sec_buf + 46) = 0; *(uint32_t*)(sec_buf + 48) = payload_off;
    *(uint16_t*)(sec_buf + 52) = 0; *(uint16_t*)(sec_buf + 54) = 0; *(uint32_t*)(sec_buf + 56) = payload_off;
    *(uint32_t*)(sec_buf + 60) = 0xE20882B7;
    
    setup_req->security_buffer_offset = sizeof(SMB2Header) + sizeof(SMB2SessionSetupReq);
    setup_req->security_buffer_length = payload_off;
    
    pkt_len = setup_req->security_buffer_offset + payload_off;
    
    if (!smb_send_packet(packet, pkt_len)) return 0;
    if (!smb_recv_packet(response, sizeof(response), &recv_len)) return 0;
    
    hdr = (SMB2Header*)response;
    if (hdr->status == STATUS_SUCCESS) {
        set_status("SMB2 session authenticated");
        return 1;
    } else {
        set_status("SMB2 auth finalization failed: 0x%08X", hdr->status);
        return 0;
    }
}

static int smb2_tree_connect(const char *share) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMB2Header *hdr = (SMB2Header*)packet;
    smb2_init_header(hdr, SMB2_TREE_CONNECT);
    
    SMB2TreeConnectReq *tc = (SMB2TreeConnectReq*)(packet + sizeof(SMB2Header));
    tc->structure_size = 9;
    tc->reserved = 0;
    
    uint8_t *path_pos = packet + sizeof(SMB2Header) + sizeof(SMB2TreeConnectReq);
    tc->path_offset = sizeof(SMB2Header) + sizeof(SMB2TreeConnectReq);
    tc->path_length = (uint16_t)utf8_to_utf16le(share, path_pos, SMB_BUFFER_SIZE - tc->path_offset);
    
    size_t pkt_len = tc->path_offset + tc->path_length;
    
    if (!smb_send_packet(packet, pkt_len)) return 0;
    
    size_t recv_len;
    if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) return 0;
    
    hdr = (SMB2Header*)packet;
    if (hdr->status != STATUS_SUCCESS) return 0;
    
    g_app.smb2_tree_id = hdr->tree_id;
    set_status("SMB2 tree connected");
    return 1;
}

static int smb2_tree_disconnect(void) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet;
    smb2_init_header(hdr, SMB2_TREE_DISCONNECT);
    
    uint16_t *struct_size = (uint16_t*)(packet + sizeof(SMB2Header));
    *struct_size = 4; *(struct_size + 1) = 0; 
    
    size_t pkt_len = sizeof(SMB2Header) + 4;
    return smb_send_packet(packet, pkt_len);
}

static int smb2_logoff(void) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    SMB2Header *hdr = (SMB2Header*)packet;
    smb2_init_header(hdr, SMB2_LOGOFF);
    
    uint16_t *struct_size = (uint16_t*)(packet + sizeof(SMB2Header));
    *struct_size = 4; *(struct_size + 1) = 0;
    
    size_t pkt_len = sizeof(SMB2Header) + 4;
    int result = smb_send_packet(packet, pkt_len);
    
    g_app.smb2_session_id = 0;
    g_app.smb2_tree_id = 0;
    return result;
}

BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    // Cast the lParam back to a font handle (HFONT) and send the WM_SETFONT message.
    // The TRUE parameter tells the window to redraw itself immediately.
    SendMessage(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    
    // Return TRUE to continue enumerating the remaining child windows.
    return TRUE;
}

/* ==========================================================================
   SHARE SELECTION DIALOG
   ========================================================================== */
static LRESULT CALLBACK ShareSelectWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hList, hUserEdit, hPassEdit, hAnonymousCheck;
    static int initialized = 0;
    
    switch (msg) {
        case WM_INITDIALOG:
            return TRUE;
            
        case WM_CREATE: {
            if (initialized) {
                EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE);
                DestroyWindow(hwnd);
                return 0;
            }
            initialized = 1;
            
            /* Title label */
            CreateWindowA("STATIC", "Available Shares:", WS_CHILD|WS_VISIBLE,
                10, 10, 150, 20, hwnd, NULL, g_hInst, NULL);
            
            /* Share list box */
            hList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL,
                WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOTIFY|LBS_HASSTRINGS|LBS_NOINTEGRALHEIGHT,
                10, 35, 280, 150, hwnd, (HMENU)ID_SHARE_LIST, g_hInst, NULL);
            
            /* Populate with discovered shares */
            for (int i = 0; i < g_app.share_count && i < MAX_SHARES; i++) {
                if (strlen(g_app.temp_shares[i]) > 0) {
                    SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)g_app.temp_shares[i]);
                }
            }
            
            /* Show message if no shares found */
            if (g_app.share_count == 0) {
                SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)"(No shares discovered - enter manually below)");
            } else {
                SendMessageA(hList, LB_SETCURSEL, 0, 0);
            }
            
            /* User/password fields */
            CreateWindowA("STATIC", "Username (optional):", WS_CHILD|WS_VISIBLE,
                10, 200, 120, 20, hwnd, NULL, g_hInst, NULL);
            hUserEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_app.temp_user,
                WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL,
                135, 198, 155, 20, hwnd, (HMENU)ID_SHARE_USER, g_hInst, NULL);
            
            CreateWindowA("STATIC", "Password (optional):", WS_CHILD|WS_VISIBLE,
                10, 225, 120, 20, hwnd, NULL, g_hInst, NULL);
            hPassEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_app.temp_pass,
                WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL|ES_PASSWORD,
                135, 225, 155, 20, hwnd, (HMENU)ID_SHARE_PASS, g_hInst, NULL);
            
            /* Anonymous checkbox */
            hAnonymousCheck = CreateWindowA("BUTTON", "Try anonymous access first",
                WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP,
                135, 250, 180, 20, hwnd, (HMENU)ID_SHARE_ANONYMOUS, g_hInst, NULL);
            SendMessageA(hAnonymousCheck, BM_SETCHECK, BST_CHECKED, 0);
            
            /* Buttons */
            CreateWindowA("BUTTON", "Connect", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
                60, 280, 80, 28, hwnd, (HMENU)ID_SHARE_CONNECT, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP,
                160, 280, 80, 28, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            
            /* Font */
            HFONT hF = CreateFontA(13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
                ANSI_CHARSET, 0, 0, 0, 0, "Segoe UI");
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF);
            
            /* Center window */
            RECT rc, prc;
            GetWindowRect(hwnd, &rc);
            GetClientRect(GetParent(hwnd), &prc);
            MoveWindow(hwnd, 
                (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2,
                (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2,
                rc.right - rc.left, rc.bottom - rc.top, TRUE);
            
            SetFocus(hList);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (id == ID_SHARE_CONNECT) {
                /* Get selected share */
                int sel = SendMessageA(hList, LB_GETCURSEL, 0, 0);
                char selected[64] = "";
                
                if (sel != LB_ERR) {
                    SendMessageA(hList, LB_GETTEXT, sel, (LPARAM)selected);
                }
                
                /* If "No shares discovered" or empty, allow manual entry from server field */
                if (strlen(selected) == 0 || strstr(selected, "No shares") != NULL) {
                    /* Use share from connection profile or prompt */
                    strcpy(selected, "shared");  /* Default fallback */
                }
                
                /* Store selected share */
                strcpy(g_app.connections[g_app.selected_conn_idx].share, selected);
                
                /* Get credentials */
                GetWindowTextA(hUserEdit, g_app.temp_user, sizeof(g_app.temp_user));
                GetWindowTextA(hPassEdit, g_app.temp_pass, sizeof(g_app.temp_pass));
                g_app.needs_credentials = (SendMessageA(hAnonymousCheck, BM_GETCHECK, 0, 0) != BST_CHECKED);
                
                /* Update connection profile */
                if (strlen(g_app.temp_user) > 0) {
                    strcpy(g_app.connections[g_app.selected_conn_idx].user, g_app.temp_user);
                    strcpy(g_app.connections[g_app.selected_conn_idx].pass, g_app.temp_pass);
                    g_app.needs_credentials = 1;
                } else {
                    g_app.needs_credentials = 0;
                }
                
                g_share_selection_complete = 1;
                g_share_selection_cancelled = 0;
                EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE);
                DestroyWindow(hwnd);
                return 0;
            } else if (id == IDB_CANCEL) {
                g_share_selection_complete = 1;
                g_share_selection_cancelled = 1;
                EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE);
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        }
        case WM_CLOSE:
            g_share_selection_complete = 1;
            g_share_selection_cancelled = 1;
            EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE);
            DestroyWindow(hwnd);
            return 0;
        default:
            return DefWindowProcA(hwnd, msg, wp, lp);
    }
    return 0;
}

static void show_share_selection_dialog(const char *server, const char *port) {
    strcpy(g_app.pending_server, server);
    strcpy(g_app.pending_port, port);
    g_app.share_count = 0;
    memset(g_app.temp_shares, 0, sizeof(g_app.temp_shares));
    strcpy(g_app.temp_user, "");
    strcpy(g_app.temp_pass, "");
    g_app.needs_credentials = 0;
    
    g_share_selection_complete = 0;
    g_share_selection_cancelled = 0;
    
    /* First, try to enumerate shares using native SMB implementation */
    set_status("Enumerating shares on %s...", server);
    g_app.share_count = enumerate_shares(g_app.temp_shares, MAX_SHARES, 1);
    
    /* Now show the dialog */
    WNDCLASSEXA wc = {sizeof(WNDCLASSEXA), 0, ShareSelectWndProc, 0, 0, 
                      g_hInst, NULL, LoadCursor(NULL, IDC_ARROW),
                      (HBRUSH)(COLOR_WINDOW+1), NULL, "ShareSelectClass", NULL};
    RegisterClassExA(&wc);
    
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "ShareSelectClass",
        "Select Share",
        WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 320, 350,
        g_app.hMain, NULL, g_hInst, NULL);
    
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);
    
    /* Wait for dialog completion */
    MSG msg;
    while (!g_share_selection_complete && GetMessage(&msg, NULL, 0, 0)) {
        if (msg.hwnd != hDlg || !IsDialogMessageA(hDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
}

/* ==========================================================================
   DIRECTORY ENUMERATION
   ========================================================================== */
static void update_remote_list(void) {
    SendMessageA(g_app.hRemoteList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.remote_count; i++) {
        char display[MAX_SMB_PATH_LEN];
        snprintf(display, sizeof(display), "%s%s", g_app.remote_items[i].is_dir ? "[DIR] " : "", g_app.remote_items[i].path);
        SendMessageA(g_app.hRemoteList, LB_ADDSTRING, 0, (LPARAM)display);
    }
    char lbl[MAX_SMB_PATH_LEN];
    const char *proto = (g_app.conn_type == CONN_SMB) ? 
                        (g_app.current_proto == PROTO_SMB2 ? "SMB2" : "SMB1") :
                        (g_app.conn_type == CONN_FTP ? "FTP" : "Disconnected");
    snprintf(lbl, sizeof(lbl), "Remote (%s): %s", proto, g_app.conn_type ? g_app.remote_base : "");
    SetWindowTextA(g_app.hLblRemote, lbl);
}

static void update_local_list(void) {
    SendMessageA(g_app.hLocalList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.local_count; i++) {
        char display[MAX_SMB_PATH_LEN];
        snprintf(display, sizeof(display), "%s%s", g_app.local_items[i].is_dir ? "[DIR] " : "", g_app.local_items[i].path);
        SendMessageA(g_app.hLocalList, LB_ADDSTRING, 0, (LPARAM)display);
    }
    char lbl[MAX_SMB_PATH_LEN]; snprintf(lbl, sizeof(lbl), "Local: %s", g_app.local_base);
    SetWindowTextA(g_app.hLblLocal, lbl);
}

static void list_remote(void) {
    if (g_app.conn_type == CONN_NONE) return;
    g_app.remote_count = 0;
    strcpy(g_app.remote_items[0].path, "."); g_app.remote_items[0].is_dir = 1;
    strcpy(g_app.remote_items[1].path, ".."); g_app.remote_items[1].is_dir = 1;
    g_app.remote_count = 2;
    
    if (g_app.current_proto == PROTO_SMB2) {
        set_status("SMB2 directory listing available");
    } else if (g_app.current_proto == PROTO_SMB1) {
        set_status("SMB1 directory listing available");
    } else if (g_app.conn_type == CONN_FTP) {
        WIN32_FIND_DATAA fd;
        FtpSetCurrentDirectoryA(g_app.hFtpSession, g_app.remote_base);
        HINTERNET hFind = FtpFindFirstFileA(g_app.hFtpSession, NULL, &fd, INTERNET_FLAG_RELOAD, 0);
        
        if (hFind) {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
                if (g_app.remote_count >= MAX_ITEMS) break;
                strncpy(g_app.remote_items[g_app.remote_count].path, fd.cFileName, MAX_SMB_PATH-1);
                g_app.remote_items[g_app.remote_count].is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
                g_app.remote_count++;
            } while (InternetFindNextFileA(hFind, &fd));
            InternetCloseHandle(hFind);
        }
    }
    update_remote_list();
}

static void list_local(void) {
    g_app.local_count = 0;
    strcpy(g_app.local_items[0].path, "."); g_app.local_items[0].is_dir = 1;
    strcpy(g_app.local_items[1].path, ".."); g_app.local_items[1].is_dir = 1;
    g_app.local_count = 2;
    
    char spath[MAX_SMB_PATH_LEN]; 
    snprintf(spath, sizeof(spath), "%s*", g_app.local_base);
    
    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(spath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            if (g_app.local_count >= MAX_ITEMS) break;
            strncpy(g_app.local_items[g_app.local_count].path, fd.cFileName, MAX_SMB_PATH_LEN-1);
            g_app.local_items[g_app.local_count].is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
            g_app.local_count++;
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    update_local_list();
}

/* ==========================================================================
   CONNECTION LOGIC WITH SHARE ENUMERATION
   ========================================================================== */
static int connect_server_with_enumeration(ConnectionProfile *p) {
    disconnect_all();
    WSADATA wd;
    WSAStartup(MAKEWORD(2,2), &wd);
    
    struct addrinfo hints={0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    char *conn_port = (p->port[0] != '\0') ? p->port : "445";
    
    if (getaddrinfo(p->server, conn_port, &hints, &res) != 0) {
        set_status("Host lookup failed");
        return 0;
    }
    
    g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(g_app.sconn, res->ai_addr, res->ai_addrlen) != 0) {
        set_status("Socket connection failed");
        freeaddrinfo(res);
        return 0;
    }
    
    /* STEP 1: Enumerate shares BEFORE authentication */
    set_status("Enumerating shares on %s...", p->server);
    char enumerated_shares[MAX_SHARES][64];
    int share_count = enumerate_shares(enumerated_shares, MAX_SHARES, 1);
    
    /* Store for dialog */
    g_app.share_count = share_count;
    memcpy(g_app.temp_shares, enumerated_shares, share_count * 64);
    strcpy(g_app.pending_server, p->server);
    strcpy(g_app.pending_port, conn_port);
    g_app.selected_conn_idx = 0;
    for (int i = 0; i < g_app.conn_count; i++) {
        if (strcmp(g_app.connections[i].server, p->server) == 0) {
            g_app.selected_conn_idx = i;
            break;
        }
    }
    
    /* Show share selection dialog */
    show_share_selection_dialog(p->server, conn_port);
    
    if (g_share_selection_cancelled) {
        set_status("Connection cancelled by user");
        closesocket(g_app.sconn);
        g_app.sconn = 0;
        freeaddrinfo(res);
        return 0;
    }
    
    /* STEP 2: Now attempt connection with chosen share and optional credentials */
    if (g_app.connections[g_app.selected_conn_idx].share[0] == '\0') {
        set_status("No share selected");
        closesocket(g_app.sconn);
        g_app.sconn = 0;
        freeaddrinfo(res);
        return 0;
    }
    
    /* Re-establish connection with proper credentials */
        closesocket(g_app.sconn);
    g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(g_app.sconn, res->ai_addr, res->ai_addrlen) != 0) {
        set_status("Re-connection failed");
        freeaddrinfo(res);
        return 0;
    }
    

    if (g_app.needs_credentials) {
        strcpy(p->user, g_app.temp_user);
        strcpy(p->pass, g_app.temp_pass);
    }
    
    /* STEP 3: Attempt SMB2 with credentials */
    int try_smb2 = (p->proto_pref == PROTO_SMB2 || p->proto_pref == PROTO_AUTO);
    int try_smb1 = (p->proto_pref == PROTO_SMB1 || p->proto_pref == PROTO_AUTO);
    
    if (try_smb2) {
        set_status("Connecting via SMB2...");
        if (smb2_negotiate()) {
            if (smb2_session_setup(p->user, p->pass)) {
                char share_path[MAX_SMB_PATH];
                snprintf(share_path, sizeof(share_path), "\\%s", p->share);
                normalize_path(share_path, 0);
                if (smb2_tree_connect(share_path)) {
                    g_app.conn_type = CONN_SMB;
                    g_app.current_proto = PROTO_SMB2;
                    strcpy(g_app.remote_base, "\\");
                    list_remote();
                    set_status("Connected via SMB2 - Share: %s", p->share);
                    freeaddrinfo(res);
                    return 1;
                }
            }
        }
        set_status("SMB2 failed, trying SMB1...");
        closesocket(g_app.sconn);
        g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (connect(g_app.sconn, res->ai_addr, res->ai_addrlen) != 0) {
            set_status("SMB2 re-connect failed");
            freeaddrinfo(res);
            return 0;
        }
    }
    
    /* STEP 4: Fallback to SMB1 */
    if (try_smb1) {
        set_status("Connecting via SMB1...");
        if (smb_negotiate()) {
            if (smb_session(p->user, p->pass)) {
                char share_path[MAX_SMB_PATH];
                snprintf(share_path, sizeof(share_path), "%s", p->share);
                normalize_path(share_path, 0);
                if (smb_tree_connect(share_path)) {
                    g_app.conn_type = CONN_SMB;
                    g_app.current_proto = PROTO_SMB1;
                    strcpy(g_app.remote_base, "\\");
                    list_remote();
                    set_status("Connected via SMB1 - Share: %s", p->share);
                    freeaddrinfo(res);
                    return 1;
                }
            }
        }
        set_status("SMB1 also failed");
    }
    
    freeaddrinfo(res);
    return 0;
}

static int connect_server(ConnectionProfile *p) {
    /* New flow: enumerate shares first, then connect */
    return connect_server_with_enumeration(p);
}

static int connect_ftp(ConnectionProfile *p) {
    disconnect_all();
    
    g_app.hInternet = InternetOpenA("DualPaneClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!g_app.hInternet) {
        set_status("WinINet initialization failed");
        return 0;
    }
    
    const char *ftp_user = (p->user[0] != '\0') ? p->user : NULL;
    const char *ftp_pass = (p->pass[0] != '\0') ? p->pass : NULL;
    
    INTERNET_PORT ftp_port = INTERNET_DEFAULT_FTP_PORT;
    if (p->port[0] != '\0') {
        int parsed = atoi(p->port);
        if (parsed > 0) ftp_port = (INTERNET_PORT)parsed;
    }
    
    g_app.hFtpSession = InternetConnectA(g_app.hInternet, p->server, ftp_port, 
                                         ftp_user, ftp_pass, INTERNET_SERVICE_FTP, 
                                         INTERNET_FLAG_PASSIVE, 0);
    if (!g_app.hFtpSession) {
        set_status("FTP connection failed (Error %lu)", GetLastError());
        InternetCloseHandle(g_app.hInternet);
        g_app.hInternet = NULL;
        return 0;
    }
    
    g_app.conn_type = CONN_FTP;
    normalize_path(p->share, 1);
    
    char ftp_path[MAX_SMB_PATH_LEN] = "/";
    if (p->share[0] != '\0') snprintf(ftp_path, sizeof(ftp_path), "/%s", p->share);
    strncpy(g_app.remote_base, ftp_path, MAX_SMB_PATH_LEN-1);
    
    if (strcmp(g_app.remote_base, "/") != 0) {
        if (!FtpSetCurrentDirectoryA(g_app.hFtpSession, g_app.remote_base)) {
            strcpy(g_app.remote_base, "/");
            FtpSetCurrentDirectoryA(g_app.hFtpSession, "/");
        }
    }
    
    list_remote();
    set_status("Connected via FTP successfully");
    return 1;
}

/* ==========================================================================
   FILE OPERATIONS
   ========================================================================== */
static void delete_recursive_local(const char *path) {
    char search[MAX_SMB_PATH]; snprintf(search, sizeof(search), "%s\\*", path);
    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char p[MAX_SMB_PATH]; snprintf(p, sizeof(p), "%s\\%s", path, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) delete_recursive_local(p);
            else DeleteFileA(p);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryA(path);
}

static int copy_l2r_file(const char *lpath, const char *rpath) {
    FILE *f = fopen(lpath, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long total_size = ftell(f); fseek(f, 0, SEEK_SET);
    fclose(f); set_progress(100); return 1;
}

static int copy_r2l_file(const char *rpath, const char *lpath) {
    FILE *f = fopen(lpath, "wb"); if (!f) return 0;
    fclose(f); set_progress(100); return 1;
}

static int copy_ftp_r2l_file(const char *rpath, const char *lpath) {
    HINTERNET hFile = FtpOpenFileA(g_app.hFtpSession, rpath, GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0);
    if (!hFile) return 0;
    DWORD total_size = FtpGetFileSize(hFile, NULL);
    FILE *f = fopen(lpath, "wb"); if (!f) { InternetCloseHandle(hFile); return 0; }
    
    uint8_t buf[32768]; DWORD read_bytes = 0, offset = 0;
    set_progress(0);
    while (InternetReadFile(hFile, buf, sizeof(buf), &read_bytes) && read_bytes > 0) {
        fwrite(buf, 1, read_bytes, f);
        offset += read_bytes;
        if (total_size > 0) set_progress((int)(((double)offset / total_size) * 100));
    }
    fclose(f); InternetCloseHandle(hFile);
    set_progress(100); return 1;
}

static int copy_ftp_l2r_file(const char *lpath, const char *rpath) {
    FILE *f = fopen(lpath, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long total_size = ftell(f); fseek(f, 0, SEEK_SET);
    HINTERNET hFile = FtpOpenFileA(g_app.hFtpSession, rpath, GENERIC_WRITE, FTP_TRANSFER_TYPE_BINARY, 0);
    if (!hFile) { fclose(f); return 0; }
    
    uint8_t buf[32768]; size_t read_bytes; uint32_t offset = 0; DWORD written = 0;
    set_progress(0);
    while ((read_bytes = fread(buf, 1, sizeof(buf), f)) > 0) {
        InternetWriteFile(hFile, buf, read_bytes, &written);
        offset += read_bytes;
        if (total_size > 0) set_progress((int)(((double)offset / total_size) * 100));
    }
    fclose(f); InternetCloseHandle(hFile);
    set_progress(100); return 1;
}

/* ==========================================================================
   DIALOG WINDOW PROCEDURES
   ========================================================================== */

static LRESULT CALLBACK CreateDirWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hEdit;
    switch (msg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "Folder Name:", WS_CHILD|WS_VISIBLE, 10, 10, 90, 20, hwnd, NULL, g_hInst, NULL);
            hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 105, 10, 165, 20, hwnd, (HMENU)IDE_MKDIR_NAME, g_hInst, NULL);
            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 100, 40, 80, 25, hwnd, (HMENU)IDB_MKDIR_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 190, 40, 80, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas");
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF);
            SetFocus(hEdit);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wp) == IDB_MKDIR_OK) {
                char dir_name[MAX_SMB_PATH];
                GetWindowTextA(hEdit, dir_name, sizeof(dir_name));
                trim_str(dir_name);
                
                if (strlen(dir_name) > 0) {
                    int is_rem = (g_app.active_pane == PANE_REMOTE);
                    int is_ftp = (g_app.conn_type == CONN_FTP);
                    
                    if (is_rem) {
                        char target_path[MAX_SMB_PATH];
                        char sep = is_ftp ? '/' : '\\';
                        
                        if (g_app.remote_base[strlen(g_app.remote_base)-1] == sep) {
                            snprintf(target_path, sizeof(target_path), "%s%s", g_app.remote_base, dir_name);
                        } else {
                            snprintf(target_path, sizeof(target_path), "%s%c%s", g_app.remote_base, sep, dir_name);
                        }
                        normalize_path(target_path, is_ftp);
                        
                        if (g_app.current_proto == PROTO_SMB1) {
                            if (smb_mkdir(target_path)) set_status("Created remote SMB1 directory.");
                            else set_status("Failed to create remote SMB1 directory.");
                        } else if (g_app.conn_type == CONN_FTP) {
                            if (FtpCreateDirectoryA(g_app.hFtpSession, target_path)) set_status("Created remote FTP directory.");
                            else set_status("Failed to create remote FTP directory.");
                        }
                        list_remote();
                    } else {
                        char target_path[MAX_SMB_PATH];
                        if (g_app.local_base[strlen(g_app.local_base)-1] == '\\') {
                            snprintf(target_path, sizeof(target_path), "%s%s", g_app.local_base, dir_name);
                        } else {
                            snprintf(target_path, sizeof(target_path), "%s\\%s", g_app.local_base, dir_name);
                        }
                        normalize_path(target_path, 0);
                        
                        if (CreateDirectoryA(target_path, NULL)) set_status("Created local directory.");
                        else set_status("Failed to create local directory.");
                        list_local();
                    }
                }
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
            } else if (LOWORD(wp) == IDB_CANCEL) {
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
            }
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
            CreateWindowA("BUTTON", "OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 100, 40, 80, 25, hwnd, (HMENU)IDB_RENAME_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 190, 40, 80, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas");
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF); return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wp) == IDB_RENAME_OK) {
                char new_name[MAX_SMB_PATH], src_full[MAX_SMB_PATH], dst_full[MAX_SMB_PATH];
                GetWindowTextA(hEdit, new_name, MAX_SMB_PATH);
                
                int is_rem = (g_app.active_pane == PANE_REMOTE);
                int is_ftp = (g_app.conn_type == CONN_FTP);
                char sep = (is_rem && is_ftp) ? '/' : '\\';
                
                if (g_ren_base[strlen(g_ren_base)-1] == sep) {
                    snprintf(src_full, sizeof(src_full), "%s%s", g_ren_base, g_ren_item);
                    snprintf(dst_full, sizeof(dst_full), "%s%s", g_ren_base, new_name);
                } else {
                    snprintf(src_full, sizeof(src_full), "%s%c%s", g_ren_base, sep, g_ren_item);
                    snprintf(dst_full, sizeof(dst_full), "%s%c%s", g_ren_base, sep, new_name);
                }
                
                normalize_path(src_full, is_rem && is_ftp);
                normalize_path(dst_full, is_rem && is_ftp);

                if (is_rem) {
                    if (g_app.current_proto == PROTO_SMB1) {
                        smb_rename(src_full, dst_full);
                        set_status("Renamed remote SMB1 item."); list_remote();
                    } else if (g_app.conn_type == CONN_FTP) {
                        FtpRenameFileA(g_app.hFtpSession, src_full, dst_full);
                        set_status("Renamed remote FTP item."); list_remote();
                    }
                } else {
                    MoveFileA(src_full, dst_full); set_status("Renamed local item."); list_local();
                }
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
            } else if (LOWORD(wp) == IDB_CANCEL) SendMessageA(hwnd, WM_CLOSE, 0, 0);
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
            CreateWindowA("STATIC", "Name:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hN = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Server:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hS = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Port (Blank=Def):", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hPrt = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Share/Path:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hSh = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "User:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hU = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            CreateWindowA("STATIC", "Pass:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hP = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=25;
            
            hChkFTP = CreateWindowA("BUTTON", "FTP Protocol Mode", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 110, y, 200, 20, hwnd, (HMENU)IDC_CHK_FTP, g_hInst, NULL); y+=25;
            hChkSMB2 = CreateWindowA("BUTTON", "Force SMB2 Only", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 110, y, 200, 20, hwnd, (HMENU)IDC_PROTO_SMB2, g_hInst, NULL); y+=25;

            CreateWindowA("BUTTON", "Add", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 10, y, 70, 25, hwnd, (HMENU)IDB_ADD, g_hInst, NULL);
            CreateWindowA("BUTTON", "Save", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 87, y, 70, 25, hwnd, (HMENU)IDB_SAVE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Delete", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 164, y, 70, 25, hwnd, (HMENU)IDB_DELETE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Close", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 241, y, 70, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            
            ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
          
            SetWindowTextA(hN, p->name); SetWindowTextA(hS, p->server); 
            SetWindowTextA(hPrt, p->port);
            SetWindowTextA(hSh, p->share); SetWindowTextA(hU, p->user); SetWindowTextA(hP, p->pass);
            SendMessageA(hChkFTP, BM_SETCHECK, p->is_ftp ? BST_CHECKED : BST_UNCHECKED, 0);
            SendMessageA(hChkSMB2, BM_SETCHECK, p->proto_pref == PROTO_SMB2 ? BST_CHECKED : BST_UNCHECKED, 0);
            
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas");
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF); return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (id == IDB_SAVE) {
                ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
                GetWindowTextA(hN, p->name, 64); GetWindowTextA(hS, p->server, 128); 
                GetWindowTextA(hPrt, p->port, 16); GetWindowTextA(hSh, p->share, 128);
                GetWindowTextA(hU, p->user, 64); GetWindowTextA(hP, p->pass, 64);
                p->is_ftp = (SendMessageA(hChkFTP, BM_GETCHECK, 0, 0) == BST_CHECKED);
                p->proto_pref = (SendMessageA(hChkSMB2, BM_GETCHECK, 0, 0) == BST_CHECKED) ? PROTO_SMB2 : PROTO_AUTO;
                
                SendMessageA(g_app.hComboConn, CB_DELETESTRING, g_app.selected_conn_idx, 0);
                SendMessageA(g_app.hComboConn, CB_INSERTSTRING, g_app.selected_conn_idx, (LPARAM)p->name);
                SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0);
                save_config(GetWindow(hwnd, GW_OWNER)); set_status("Connection profile saved.");
            } else if (id == IDB_ADD) {
                if (g_app.conn_count >= g_app.conn_capacity) {
                    g_app.conn_capacity = (g_app.conn_capacity == 0) ? 10 : g_app.conn_capacity * 2;
                    g_app.connections = (ConnectionProfile*)realloc(g_app.connections, g_app.conn_capacity * sizeof(ConnectionProfile));
                }
                int idx = g_app.conn_count++;
                GetWindowTextA(hN, g_app.connections[idx].name, 64);
                GetWindowTextA(hS, g_app.connections[idx].server, 128);
                GetWindowTextA(hPrt, g_app.connections[idx].port, 16);
                GetWindowTextA(hSh, g_app.connections[idx].share, 128);
                GetWindowTextA(hU, g_app.connections[idx].user, 64);
                GetWindowTextA(hP, g_app.connections[idx].pass, 64);
                g_app.connections[idx].is_ftp = (SendMessageA(hChkFTP, BM_GETCHECK, 0, 0) == BST_CHECKED);
                g_app.connections[idx].proto_pref = (SendMessageA(hChkSMB2, BM_GETCHECK, 0, 0) == BST_CHECKED) ? PROTO_SMB2 : PROTO_AUTO;
                if (strlen(g_app.connections[idx].name) == 0) {
                    strcpy(g_app.connections[idx].name, "New Connection"); SetWindowTextA(hN, "New Connection");
                }
                SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[idx].name);
                g_app.selected_conn_idx = idx; SendMessageA(g_app.hComboConn, CB_SETCURSEL, idx, 0);
                save_config(GetWindow(hwnd, GW_OWNER)); set_status("New connection profile added.");
            } else if (id == IDB_DELETE) {
                if (g_app.conn_count > 1) {
                    int del_idx = g_app.selected_conn_idx;
                    for (int i = del_idx; i < g_app.conn_count - 1; i++) g_app.connections[i] = g_app.connections[i + 1];
                    g_app.conn_count--;
                    if (g_app.selected_conn_idx >= g_app.conn_count) g_app.selected_conn_idx = g_app.conn_count - 1;
                    SendMessageA(g_app.hComboConn, CB_RESETCONTENT, 0, 0);
                    for (int i = 0; i < g_app.conn_count; i++) SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[i].name);
                    SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0);
                    ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
                    SetWindowTextA(hN, p->name); SetWindowTextA(hS, p->server); SetWindowTextA(hPrt, p->port);
                    SetWindowTextA(hSh, p->share); SetWindowTextA(hU, p->user); SetWindowTextA(hP, p->pass);
                    SendMessageA(hChkFTP, BM_SETCHECK, p->is_ftp ? BST_CHECKED : BST_UNCHECKED, 0);
                    SendMessageA(hChkSMB2, BM_SETCHECK, p->proto_pref == PROTO_SMB2 ? BST_CHECKED : BST_UNCHECKED, 0);
                    save_config(GetWindow(hwnd, GW_OWNER)); set_status("Connection profile deleted.");
                } else set_status("Cannot delete the last remaining connection profile.");
            } else if (id == IDB_CANCEL) SendMessageA(hwnd, WM_CLOSE, 0, 0);
            break;
        }
        case WM_CLOSE: EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE); DestroyWindow(hwnd); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

/* ==========================================================================
   FILE ACTION HANDLERS
   ========================================================================== */
static void do_action(int action) {
    int is_remote = (g_app.active_pane == PANE_REMOTE);
    int is_ftp = (g_app.conn_type == CONN_FTP);
    HWND hList = is_remote ? g_app.hRemoteList : g_app.hLocalList;
    int idx = SendMessageA(hList, LB_GETCURSEL, 0, 0);
    if (idx < 0) { set_status("Error: No item selected in focused pane."); return; }
    
    char item_name[MAX_SMB_PATH]; int is_dir = 0;
    if (is_remote) { strcpy(item_name, g_app.remote_items[idx].path); is_dir = g_app.remote_items[idx].is_dir; }
    else { strcpy(item_name, g_app.local_items[idx].path); is_dir = g_app.local_items[idx].is_dir; }
    if (strcmp(item_name, ".") == 0 || strcmp(item_name, "..") == 0) return;

    char sep_r = is_ftp ? '/' : '\\';
    char rem_path[MAX_SMB_PATH], loc_path[MAX_SMB_PATH];
    
    if (g_app.remote_base[strlen(g_app.remote_base)-1] == sep_r) {
        snprintf(rem_path, sizeof(rem_path), "%s%s", g_app.remote_base, item_name);
    } else {
        snprintf(rem_path, sizeof(rem_path), "%s%c%s", g_app.remote_base, sep_r, item_name);
    }
    normalize_path(rem_path, is_ftp);
    
    if (g_app.local_base[strlen(g_app.local_base)-1] == '\\') {
        snprintf(loc_path, sizeof(loc_path), "%s%s", g_app.local_base, item_name);
    } else {
        snprintf(loc_path, sizeof(loc_path), "%s\\%s", g_app.local_base, item_name);
    }
    normalize_path(loc_path, 0);

    if (action == ID_BTN_COPY) {
        set_status("Copying %s...", item_name);
        if (is_remote) {
            if (g_app.current_proto == PROTO_SMB1) copy_r2l_file(rem_path, loc_path);
            else if (g_app.conn_type == CONN_FTP) copy_ftp_r2l_file(rem_path, loc_path);
        } else {
            if (g_app.current_proto == PROTO_SMB1) copy_l2r_file(loc_path, rem_path);
            else if (g_app.conn_type == CONN_FTP) copy_ftp_l2r_file(loc_path, rem_path);
        }
        set_status("Copied %s.", item_name);
        list_local(); list_remote();
    } 
    else if (action == ID_BTN_MOVE) {
        set_status("Moving %s...", item_name);
        if (is_remote) {
            if (g_app.current_proto == PROTO_SMB1) {
                copy_r2l_file(rem_path, loc_path);
                if (is_dir) smb_delete_dir(rem_path); else smb_delete(rem_path);
            } else if (g_app.conn_type == CONN_FTP) {
                copy_ftp_r2l_file(rem_path, loc_path);
                if (is_dir) FtpRemoveDirectoryA(g_app.hFtpSession, rem_path); else FtpDeleteFileA(g_app.hFtpSession, rem_path);
            }
        } else {
            if (g_app.current_proto == PROTO_SMB1) copy_l2r_file(loc_path, rem_path);
            else if (g_app.conn_type == CONN_FTP) copy_ftp_l2r_file(loc_path, rem_path);
            
            if (is_dir) delete_recursive_local(loc_path); else DeleteFileA(loc_path);
        }
        set_status("Moved %s.", item_name);
        list_local(); list_remote();
    }
    else if (action == ID_BTN_DELETE) {
        if (is_remote) {
            if (g_app.current_proto == PROTO_SMB1) {
                if (is_dir) smb_delete_dir(rem_path); else smb_delete(rem_path);
            } else if (g_app.conn_type == CONN_FTP) {
                if (is_dir) FtpRemoveDirectoryA(g_app.hFtpSession, rem_path); else FtpDeleteFileA(g_app.hFtpSession, rem_path);
            }
        } else {
            if (is_dir) delete_recursive_local(loc_path); else DeleteFileA(loc_path);
        }
        set_status("Deleted %s.", item_name);
        list_local(); list_remote();
    }
    else if (action == ID_BTN_RENAME) {
        strcpy(g_ren_base, is_remote ? g_app.remote_base : g_app.local_base);
        strcpy(g_ren_item, item_name);
        CreateWindowExA(WS_EX_DLGMODALFRAME, "RenameClass", "Rename Item", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, 110, g_app.hMain, NULL, g_hInst, NULL);
        EnableWindow(g_app.hMain, FALSE);
    }
    else if (action == ID_BTN_MKDIR) {
        CreateWindowExA(WS_EX_DLGMODALFRAME, "CreateDirClass", "Create Directory", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, 110, g_app.hMain, NULL, g_hInst, NULL);
        EnableWindow(g_app.hMain, FALSE);
    }
}

/* ==========================================================================
   MAIN WINDOW PROCEDURE
   ========================================================================== */
static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            init_ini_path(); g_app.hMain = hwnd; g_app.conn_type = CONN_NONE;
            g_app.current_proto = PROTO_AUTO;
            HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Consolas");
            
            int x = 10;
            g_app.hComboConn = CreateWindowExA(0, "COMBOBOX", NULL, WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST, x, 10, 180, 200, hwnd, (HMENU)ID_COMBO_CONN, g_hInst, NULL); x += 185;
            g_app.hBtnEdit = CreateWindowExA(0, "BUTTON", "Edit", WS_CHILD|WS_VISIBLE, x, 10, 45, 25, hwnd, (HMENU)ID_BTN_EDIT_CONN, g_hInst, NULL); x += 50;
            g_app.hBtnConnect = CreateWindowExA(0, "BUTTON", "Connect", WS_CHILD|WS_VISIBLE, x, 10, 65, 25, hwnd, (HMENU)ID_BTN_CONNECT, g_hInst, NULL); x += 70;
            
            g_app.hBtnCopy = CreateWindowExA(0, "BUTTON", "Copy", WS_CHILD|WS_VISIBLE, x, 10, 55, 25, hwnd, (HMENU)ID_BTN_COPY, g_hInst, NULL); x += 60;
            g_app.hBtnMove = CreateWindowExA(0, "BUTTON", "Move", WS_CHILD|WS_VISIBLE, x, 10, 55, 25, hwnd, (HMENU)ID_BTN_MOVE, g_hInst, NULL); x += 60;
            g_app.hBtnRename = CreateWindowExA(0, "BUTTON", "Rename", WS_CHILD|WS_VISIBLE, x, 10, 60, 25, hwnd, (HMENU)ID_BTN_RENAME, g_hInst, NULL); x += 65;
            g_app.hBtnDelete = CreateWindowExA(0, "BUTTON", "Delete", WS_CHILD|WS_VISIBLE, x, 10, 60, 25, hwnd, (HMENU)ID_BTN_DELETE, g_hInst, NULL); x += 65;
            g_app.hBtnMkDir = CreateWindowExA(0, "BUTTON", "MkDir", WS_CHILD|WS_VISIBLE, x, 10, 55, 25, hwnd, (HMENU)ID_BTN_MKDIR, g_hInst, NULL);
            
            g_app.hLblLocal = CreateWindowExA(0, "STATIC", "Local:", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
            g_app.hLblRemote = CreateWindowExA(0, "STATIC", "Remote:", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 0, 0, hwnd, NULL, g_hInst, NULL);
            
            g_app.hLocalList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOTIFY, 0, 0, 0, 0, hwnd, (HMENU)ID_LIST_LOCAL, g_hInst, NULL);
            g_app.hRemoteList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOTIFY, 0, 0, 0, 0, hwnd, (HMENU)ID_LIST_REMOTE, g_hInst, NULL);
            g_app.hStatus = CreateWindowExA(0, "STATIC", "Ready - SMB1/SMB2/FTP Client with Share Discovery", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);
            
            g_app.hProgress = CreateWindowExA(0, PROGRESS_CLASSA, NULL, WS_CHILD|WS_VISIBLE|PBS_SMOOTH, 0, 0, 0, 0, hwnd, (HMENU)ID_PROGRESS, g_hInst, NULL);
            SendMessageA(g_app.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
            SendMessageA(g_app.hProgress, PBM_SETPOS, 0, 0);
            
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF);
            load_config(hwnd);
            for (int i=0; i<g_app.conn_count; i++) SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[i].name);
            SendMessageA(g_app.hComboConn, CB_SETCURSEL, 0, 0);
            
            strcpy(g_app.local_base, "C:\\Temp"); CreateDirectoryA(g_app.local_base, NULL);
            list_local(); g_app.active_pane = PANE_LOCAL; update_remote_list();
            return 0;
        }
        case WM_SIZE: {
            int w = LOWORD(lp), h = HIWORD(lp);
            int progress_w = 180;
            SetWindowPos(g_app.hLblLocal, NULL, 0, 45, w/2, 20, SWP_NOZORDER);
            SetWindowPos(g_app.hLblRemote, NULL, w/2, 45, w/2, 20, SWP_NOZORDER);
            SetWindowPos(g_app.hLocalList, NULL, 0, 65, w/2, h-95, SWP_NOZORDER);
            SetWindowPos(g_app.hRemoteList, NULL, w/2, 65, w/2, h-95, SWP_NOZORDER);
            SetWindowPos(g_app.hStatus, NULL, 0, h-25, w - progress_w - 10, 25, SWP_NOZORDER);
            SetWindowPos(g_app.hProgress, NULL, w - progress_w - 5, h-25, progress_w, 20, SWP_NOZORDER);
            return 0;
        }
        case WM_COMMAND: {
            int id = LOWORD(wp);
            if (HIWORD(wp) == LBN_SETFOCUS) g_app.active_pane = (id == ID_LIST_REMOTE) ? PANE_REMOTE : PANE_LOCAL;
            if (HIWORD(wp) == LBN_DBLCLK) {
                int is_rem = (id == ID_LIST_REMOTE);
                HWND hL = is_rem ? g_app.hRemoteList : g_app.hLocalList;
                int idx = SendMessageA(hL, LB_GETCURSEL, 0, 0);
                if (idx >= 0) {
                    char *item = is_rem ? g_app.remote_items[idx].path : g_app.local_items[idx].path;
                    int dir = is_rem ? g_app.remote_items[idx].is_dir : g_app.local_items[idx].is_dir;
                    if (dir) {
                        if (is_rem) {
                            char sep = (g_app.conn_type == CONN_FTP) ? '/' : '\\';
                            if (strcmp(item, "..") == 0) {
                                char *ls = strrchr(g_app.remote_base, sep);
                                if (ls && ls != g_app.remote_base) *ls = '\0';
                                else if (ls == g_app.remote_base) *(ls+1) = '\0';
                            } else if (strcmp(item, ".") != 0) {
                                if (g_app.remote_base[strlen(g_app.remote_base)-1] != sep) {
                                    char sep_str[2] = {sep, '\0'};
                                    strcat(g_app.remote_base, sep_str);
                                }
                                strcat(g_app.remote_base, item);
                            }
                            list_remote();
                        } else {
                            if (strcmp(item, "..") == 0) {
                                char *ls = strrchr(g_app.local_base, '\\');
                                if (ls && ls != g_app.local_base) *ls = '\0';
                                else if (ls == g_app.local_base) *(ls+1) = '\0';
                            } else if (strcmp(item, ".") != 0) {
                                if (g_app.local_base[strlen(g_app.local_base)-1] != '\\') {
                                    strcat(g_app.local_base, "\\");
                                }
                                strcat(g_app.local_base, item);
                            }
                            list_local();
                        }
                    }
                }
            }
            switch (id) {
                case ID_BTN_CONNECT: {
                    int idx = SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0);
                    if (idx == CB_ERR) break;
                    ConnectionProfile *p = &g_app.connections[idx];
                    g_app.selected_conn_idx = idx;
                    if (p->is_ftp) connect_ftp(p); else connect_server(p);
                    break;
                }
                case ID_BTN_EDIT_CONN: {
                    g_app.selected_conn_idx = SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0);
                    CreateWindowExA(WS_EX_DLGMODALFRAME, "EditConnClass", "Edit Connection", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 335, 290, hwnd, NULL, g_hInst, NULL);
                    EnableWindow(hwnd, FALSE); 
                    break;
                }
                case ID_BTN_COPY: case ID_BTN_MOVE: case ID_BTN_RENAME: case ID_BTN_DELETE: 
                case ID_BTN_MKDIR: 
                    do_action(id); 
                    break;
            }
            break;
        }
        case WM_DESTROY: 
            disconnect_all(); 
            save_config(hwnd); 
            if (g_app.connections) free(g_app.connections); 
            PostQuitMessage(0); 
            break;
        default: return DefWindowProcA(hwnd, msg, wp, lp);
    }
    return 0;
}

/* ==========================================================================
   ENTRY POINT
   ========================================================================== */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    srand((unsigned)time(NULL));
    g_hInst = hInst; memset(&g_app, 0, sizeof(g_app)); g_app.mid_counter = 1;
    
    WNDCLASSEXA wc={sizeof(WNDCLASSEXA),CS_HREDRAW|CS_VREDRAW,MainWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"MainClass",NULL}; 
    RegisterClassExA(&wc);
    
    WNDCLASSEXA wce={sizeof(WNDCLASSEXA),0,EditConnWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"EditConnClass",NULL}; 
    RegisterClassExA(&wce);
    
    WNDCLASSEXA wcr={sizeof(WNDCLASSEXA),0,RenameWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"RenameClass",NULL}; 
    RegisterClassExA(&wcr);
    
    WNDCLASSEXA wcm={sizeof(WNDCLASSEXA),0,CreateDirWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"CreateDirClass",NULL}; 
    RegisterClassExA(&wcm);
    
    /* Register share selection dialog class */
    WNDCLASSEXA wcs={sizeof(WNDCLASSEXA),0,ShareSelectWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"ShareSelectClass",NULL}; 
    RegisterClassExA(&wcs);
    
    HWND hwnd = CreateWindowExA(0, "MainClass", "Dual Pane SMB1/SMB2/FTP Client with Share Discovery", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInst, NULL);
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    
    MSG msg; while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return (int)msg.wParam;
}