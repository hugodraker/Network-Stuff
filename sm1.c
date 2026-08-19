/* * Native SMB/FTP Client Implementation - Dual Pane File Manager
 * Implements SMB1 natively and FTP via WinINet based on connection setting.
 * Released into Public Domain
 * Compile: gcc -o sm1.exe sm1.c -luser32 -lgdi32 -lws2_32 -lwininet -mwindows
 */

#define _WIN32_WINNT 0x0600
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <shlwapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma warning(disable: 4996)

/* ==========================================================================
   UI IDENTIFIERS & LIMITS
   ========================================================================== */
#define ID_LIST_LOCAL       1001
#define ID_LIST_REMOTE      1002
#define ID_STATUSBAR        1003
#define ID_COMBO_CONN       1004
#define ID_BTN_CONNECT      1005
#define ID_BTN_EDIT_CONN    1006

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

#define IDB_RENAME_OK       3001
#define IDE_RENAME_NEW      3002
#define IDE_MKDIR_NAME      3003
#define IDB_MKDIR_OK        3004

#define MAX_CONNECTIONS     10
#define MAX_SMB_PATH        1024
#define MAX_SMB_PATH_LEN    4096
#define MAX_ITEMS           500
#define SMB_BUFFER_SIZE     65536
#define PANE_LOCAL          0
#define PANE_REMOTE         1
#define CONN_NONE           0
#define CONN_SMB            1
#define CONN_FTP            2

/* ==========================================================================
   PROTOCOL STRUCTURES
   ========================================================================== */
#pragma pack(push, 1)
typedef struct {
    uint8_t  proto_id[4];
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
} SMBHeader;
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
} ConnectionProfile;

typedef struct {
    HWND hMain, hComboConn, hBtnEdit, hBtnConnect;
    HWND hBtnCopy, hBtnMove, hBtnRename, hBtnDelete, hBtnMkDir;
    HWND hRemoteList, hLocalList, hStatus;
    HWND hLblLocal, hLblRemote;
    
    ConnectionProfile connections[MAX_CONNECTIONS];
    int conn_count, selected_conn_idx;
    RECT original_rect;
    
    char remote_base[MAX_SMB_PATH_LEN];
    char local_base[MAX_SMB_PATH_LEN];
    
    // Networking
    SOCKET sconn;
    HINTERNET hInternet, hFtpSession;
    int conn_type; // 0=None, 1=SMB, 2=FTP
    
    DirectoryItem remote_items[MAX_ITEMS];
    DirectoryItem local_items[MAX_ITEMS];
    int remote_count, local_count;
    
    int active_pane; // 0 = Local, 1 = Remote
    uint16_t tid, uid, mid_counter;
    char g_session_response[8];
} AppContext;

static AppContext g_app;
static HINSTANCE g_hInst;
static char g_ini_path[MAX_PATH];

static char g_ren_base[MAX_SMB_PATH];
static char g_ren_item[MAX_SMB_PATH];

/* ==========================================================================
   UTILITIES & CONFIG
   ========================================================================== */
static void set_status(const char *fmt, ...) {
    char buf[1024]; va_list args;
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    SetWindowTextA(g_app.hStatus, buf);
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
    if (g_app.conn_count <= 0 || g_app.conn_count > MAX_CONNECTIONS) {
        g_app.conn_count = 1;
        strcpy(g_app.connections[0].name, "Default Connection");
        strcpy(g_app.connections[0].server, "192.168.1.100");
        strcpy(g_app.connections[0].port, "");
        strcpy(g_app.connections[0].share, "\\shared");
        g_app.connections[0].is_ftp = 0;
    } else {
        for (int i = 0; i < g_app.conn_count; i++) {
            char key[32];
            sprintf(key, "Name%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].name, 64, g_ini_path);
            sprintf(key, "Server%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].server, 128, g_ini_path);
            sprintf(key, "Port%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].port, 16, g_ini_path);
            sprintf(key, "Share%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].share, 128, g_ini_path);
            sprintf(key, "User%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].user, 64, g_ini_path);
            sprintf(key, "Pass%d", i); GetPrivateProfileStringA("Connections", key, "", g_app.connections[i].pass, 64, g_ini_path);
            sprintf(key, "IsFTP%d", i); g_app.connections[i].is_ftp = GetPrivateProfileIntA("Connections", key, 0, g_ini_path);
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
    }
}

static void disconnect_all(void) {
    if (g_app.sconn) { closesocket(g_app.sconn); g_app.sconn = 0; }
    if (g_app.hFtpSession) { InternetCloseHandle(g_app.hFtpSession); g_app.hFtpSession = NULL; }
    if (g_app.hInternet) { InternetCloseHandle(g_app.hInternet); g_app.hInternet = NULL; }
    g_app.conn_type = CONN_NONE;
}

/* ==========================================================================
   SMB TRANSPORT & CORE PROTOCOL
   ========================================================================== */
static int smb_send_packet(const void *data, size_t len) {
    uint8_t header[4] = {0, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF};
    if (send(g_app.sconn, (const char*)header, 4, 0) != 4) return 0;
    const uint8_t *buf = (const uint8_t*)data; size_t rem = len;
    while (rem > 0) {
        int sent = send(g_app.sconn, (const char*)buf, (int)rem, 0);
        if (sent <= 0) return 0;
        buf += sent; rem -= sent;
    }
    return 1;
}

static int smb_recv_packet(uint8_t *buffer, size_t max_len, size_t *out_len) {
    uint8_t header[4];
    if (recv(g_app.sconn, (char*)header, 4, 0) != 4) return 0;
    size_t expected = ((size_t)header[1] << 16) | ((size_t)header[2] << 8) | header[3];
    if (expected > max_len) expected = max_len;
    size_t received = 0;
    while (received < expected) {
        int rcvd = recv(g_app.sconn, (char*)(buffer + received), (int)(expected - received), 0);
        if (rcvd <= 0) return 0;
        received += rcvd;
    }
    *out_len = received; return 1;
}

static SMBHeader* smb_build_header(uint8_t *packet, uint8_t cmd) {
    SMBHeader *hdr = (SMBHeader*)packet;
    memcpy(hdr->proto_id, "\xFFSMB", 4); hdr->cmd = cmd;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF; hdr->mid = g_app.mid_counter++;
    hdr->flags1 = 0x80; hdr->flags2 = 0x07C7;
    hdr->uid = g_app.uid; hdr->tid = g_app.tid;
    return hdr;
}

static int smb_negotiate(void) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, 0xFF);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 1; *w++ = 0xFF; *w++ = 0; *w++ = 0;
    *(uint32_t*)w = 0x04000000; w+=4; *(uint16_t*)w = 0; w+=2; *(uint32_t*)w = 0; w+=4;
    memcpy(w, "NT LM 0.12\x00", 12); w+=12;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMBHeader*)pkt)->status == 0);
}

static int smb_session(const char *user, const char *pass) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, 0x73);
    uint8_t *w = pkt + sizeof(SMBHeader);
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
    g_app.uid = ((SMBHeader*)pkt)->uid; memcpy(g_app.g_session_response, ((SMBHeader*)pkt)->signature, 8);
    return (((SMBHeader*)pkt)->status == 0);
}

static int smb_tree_connect(const char *share) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt));
    SMBHeader *hdr = smb_build_header(pkt, 0x74);
    memcpy(hdr->signature, g_app.g_session_response, 8);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 4; *w++ = 0xFF; *w++ = 0; *w++ = 0; *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = 0; w+=2;
    *w++ = 0; strcpy((char*)w, share); w+=strlen(share)+1; strcpy((char*)w, "?????"); w+=6;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    g_app.tid = ((SMBHeader*)pkt)->tid;
    return (((SMBHeader*)pkt)->status == 0);
}

static int smb_simple_path_cmd(uint8_t cmd, const char *path) {
    uint8_t pkt[MAX_SMB_PATH+100]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, cmd);
    uint8_t *w = pkt + sizeof(SMBHeader);
    if (cmd == 0x06) { *w++ = 1; *(uint16_t*)w = 0x16; w+=2; } else { *w++ = 0; }
    *(uint16_t*)w = strlen(path)+2; w+=2; *w++ = 0x04; strcpy((char*)w, path); w+=strlen(path)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMBHeader*)pkt)->status == 0);
}

static int smb_rename(const char *oldp, const char *newp) {
    uint8_t pkt[MAX_SMB_PATH*2+100]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, 0x07);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 1; *(uint16_t*)w = 0x16; w+=2;
    *(uint16_t*)w = strlen(oldp) + strlen(newp) + 4; w+=2;
    *w++ = 0x04; strcpy((char*)w, oldp); w+=strlen(oldp)+1;
    *w++ = 0x04; strcpy((char*)w, newp); w+=strlen(newp)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    return (((SMBHeader*)pkt)->status == 0);
}

static int smb_open(const char *path, int for_write, uint16_t *fid) {
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt));
    smb_build_header(pkt, 0xA2); // NT_CREATE_ANDX
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 24; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w+=2; *w++ = 0;
    *(uint16_t*)w = strlen(path); w+=2; *(uint32_t*)w = 0; w+=4; *(uint32_t*)w = 0; w+=4;
    *(uint32_t*)w = for_write ? 0x2019F : 0x20089; w+=4; *(uint64_t*)w = 0; w+=8;
    *(uint32_t*)w = 0x80; w+=4; *(uint32_t*)w = 3; w+=4;
    *(uint32_t*)w = for_write ? 5 : 1; w+=4;
    *(uint32_t*)w = 0; w+=4; *(uint32_t*)w = 0; w+=4; *w++ = 0;
    *(uint16_t*)w = strlen(path)+1; w+=2; strcpy((char*)w, path); w+=strlen(path)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen)) return 0;
    if (((SMBHeader*)pkt)->status != 0) return 0;
    *fid = *(uint16_t*)(pkt + sizeof(SMBHeader) + 5); return 1;
}

static int smb_read(uint16_t fid, uint32_t offset, uint8_t *buf, uint16_t len, uint16_t *read_len) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x2E);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 12; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w+=2;
    *(uint16_t*)w = fid; w+=2; *(uint32_t*)w = offset; w+=4; *(uint16_t*)w = len; w+=2;
    *(uint16_t*)w = len; w+=2; *(uint32_t*)w = 0; w+=8; *(uint16_t*)w = 0; w+=2;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    uint8_t resp[SMB_BUFFER_SIZE]; size_t rlen;
    if (!smb_recv_packet(resp, sizeof(resp), &rlen) || ((SMBHeader*)resp)->status != 0) return 0;
    *read_len = *(uint16_t*)(resp + sizeof(SMBHeader) + 11);
    uint16_t data_off = *(uint16_t*)(resp + sizeof(SMBHeader) + 13);
    memcpy(buf, resp + 4 + data_off, *read_len); return 1;
}

static int smb_write(uint16_t fid, uint32_t offset, uint8_t *buf, uint16_t len) {
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x2F);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 14; *w++ = 0xFF; *w++ = 0; *(uint16_t*)w = 0; w+=2;
    *(uint16_t*)w = fid; w+=2; *(uint32_t*)w = offset; w+=4; *(uint32_t*)w = 0; w+=4;
    *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = len; w+=2;
    *(uint16_t*)w = sizeof(SMBHeader) + 14*2 + 3; w+=2; *(uint32_t*)w = 0; w+=4;
    *(uint16_t*)w = len+1; w+=2; *w++ = 0; memcpy(w, buf, len); w+=len;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    uint8_t resp[1024]; size_t rlen;
    if (!smb_recv_packet(resp, sizeof(resp), &rlen)) return 0;
    return (((SMBHeader*)resp)->status == 0);
}

static int smb_close(uint16_t fid) {
    uint8_t pkt[1024]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x04);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 3; *(uint16_t*)w = fid; w+=2; *(uint32_t*)w = 0; w+=4; *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = 0; w+=2;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    uint8_t resp[1024]; size_t rlen;
    return (smb_recv_packet(resp, sizeof(resp), &rlen) && ((SMBHeader*)resp)->status == 0);
}

static int smb_find_first_file(const char *path, WIN32_FIND_DATAA *fData, uint16_t *search_id) {
    uint8_t pkt[SMB_BUFFER_SIZE]; memset(pkt, 0, sizeof(pkt)); smb_build_header(pkt, 0x11);
    uint8_t *w = pkt + sizeof(SMBHeader);
    *w++ = 11; *w++ = 0; *(uint16_t*)w = 0x16; w+=2; *(uint16_t*)w = 1; w+=2;
    *(uint16_t*)w = 10; w+=2; *(uint16_t*)w = 100; w+=2; *(uint16_t*)w = 0; w+=2; *(uint16_t*)w = 0; w+=2;
    *(uint16_t*)w = strlen(path)+2; w+=2; *w++ = 0x04; strcpy((char*)w, path); w+=strlen(path)+1;
    if (!smb_send_packet(pkt, w - pkt)) return 0;
    size_t rlen; if (!smb_recv_packet(pkt, sizeof(pkt), &rlen) || ((SMBHeader*)pkt)->status != 0) return 0;
    uint8_t *d = pkt + sizeof(SMBHeader) + 2; int num_ent = *(uint16_t*)d; d+=2;
    if (num_ent > 0) {
        d += 16; int name_len = d[14] + (d[15]<<8);
        if (name_len > 0 && name_len < 256) {
            strncpy(fData->cFileName, (char*)(d+22), name_len); fData->cFileName[name_len] = '\0';
            fData->dwFileAttributes = (d[26] & 0x10) ? FILE_ATTRIBUTE_DIRECTORY : 0;
            return 1;
        }
    }
    return 0;
}

/* ==========================================================================
   DIRECTORY ENUMERATION & UI UPDATES
   ========================================================================== */
static void update_remote_list(void) {
    SendMessageA(g_app.hRemoteList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.remote_count; i++) {
        char display[MAX_SMB_PATH_LEN];
        snprintf(display, sizeof(display), "%s%s", g_app.remote_items[i].is_dir ? "[DIR] " : "", g_app.remote_items[i].path);
        SendMessageA(g_app.hRemoteList, LB_ADDSTRING, 0, (LPARAM)display);
    }
    char lbl[MAX_SMB_PATH_LEN];
    const char *proto = (g_app.conn_type == CONN_SMB) ? "SMB" : (g_app.conn_type == CONN_FTP ? "FTP" : "Disconnected");
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
    
    if (g_app.conn_type == CONN_SMB) {
        char spath[MAX_SMB_PATH]; 
        if (g_app.remote_base[strlen(g_app.remote_base)-1] == '\\') {
            snprintf(spath, sizeof(spath), "%s*", g_app.remote_base);
        } else {
            snprintf(spath, sizeof(spath), "%s\\*", g_app.remote_base);
        }
        
        WIN32_FIND_DATAA fd; uint16_t sid;
        if (smb_find_first_file(spath, &fd, &sid)) {
            if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
                strncpy(g_app.remote_items[g_app.remote_count].path, fd.cFileName, MAX_SMB_PATH-1);
                g_app.remote_items[g_app.remote_count].is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
                g_app.remote_count++;
            }
        }
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
    if (g_app.local_base[strlen(g_app.local_base)-1] == '\\') {
        snprintf(spath, sizeof(spath), "%s*", g_app.local_base);
    } else {
        snprintf(spath, sizeof(spath), "%s\\*", g_app.local_base);
    }
    
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
   FILE OPERATIONS & NAVIGATION
   ========================================================================== */
static int copy_l2r_file(const char *lpath, const char *rpath) {
    FILE *f = fopen(lpath, "rb"); if (!f) return 0;
    uint16_t fid; if (!smb_open(rpath, 1, &fid)) { fclose(f); return 0; }
    uint8_t buf[32768]; size_t read_bytes; uint32_t offset = 0;
    while ((read_bytes = fread(buf, 1, sizeof(buf), f)) > 0) {
        smb_write(fid, offset, buf, read_bytes); offset += read_bytes;
    }
    smb_close(fid); fclose(f); return 1;
}

static int copy_r2l_file(const char *rpath, const char *lpath) {
    uint16_t fid; if (!smb_open(rpath, 0, &fid)) return 0;
    FILE *f = fopen(lpath, "wb"); if (!f) { smb_close(fid); return 0; }
    uint8_t buf[32768]; uint16_t rb; uint32_t offset = 0;
    while (smb_read(fid, offset, buf, sizeof(buf), &rb) && rb > 0) {
        fwrite(buf, 1, rb, f); offset += rb;
    }
    smb_close(fid); fclose(f); return 1;
}

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

static void nav_dir(char *base, const char *item, int is_ftp) {
    char sep = is_ftp ? '/' : '\\';
    if (strcmp(item, "..") == 0) {
        char *ls = strrchr(base, sep);
        if (ls && ls != base) *ls = '\0'; 
        else if (ls == base) *(ls+1) = '\0';
    } else if (strcmp(item, ".") != 0) {
        if (base[strlen(base)-1] != sep) {
            char s[2] = {sep, 0}; strcat(base, s);
        }
        strcat(base, item);
    }
}

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
            if (g_app.conn_type == CONN_SMB) copy_r2l_file(rem_path, loc_path);
            else if (g_app.conn_type == CONN_FTP) FtpGetFileA(g_app.hFtpSession, rem_path, loc_path, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY, 0);
        } else {
            if (g_app.conn_type == CONN_SMB) copy_l2r_file(loc_path, rem_path);
            else if (g_app.conn_type == CONN_FTP) FtpPutFileA(g_app.hFtpSession, loc_path, rem_path, FTP_TRANSFER_TYPE_BINARY, 0);
        }
        set_status("Copied %s.", item_name);
        list_local(); list_remote();
    } 
    else if (action == ID_BTN_MOVE) {
        set_status("Moving %s...", item_name);
        if (is_remote) {
            if (g_app.conn_type == CONN_SMB) {
                copy_r2l_file(rem_path, loc_path);
                if (is_dir) smb_simple_path_cmd(0x01, rem_path); else smb_simple_path_cmd(0x06, rem_path);
            } else if (g_app.conn_type == CONN_FTP) {
                FtpGetFileA(g_app.hFtpSession, rem_path, loc_path, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY, 0);
                if (is_dir) FtpRemoveDirectoryA(g_app.hFtpSession, rem_path); else FtpDeleteFileA(g_app.hFtpSession, rem_path);
            }
        } else {
            if (g_app.conn_type == CONN_SMB) copy_l2r_file(loc_path, rem_path);
            else if (g_app.conn_type == CONN_FTP) FtpPutFileA(g_app.hFtpSession, loc_path, rem_path, FTP_TRANSFER_TYPE_BINARY, 0);
            
            if (is_dir) delete_recursive_local(loc_path); else DeleteFileA(loc_path);
        }
        set_status("Moved %s.", item_name);
        list_local(); list_remote();
    }
    else if (action == ID_BTN_DELETE) {
        if (is_remote) {
            if (g_app.conn_type == CONN_SMB) {
                if (is_dir) smb_simple_path_cmd(0x01, rem_path); else smb_simple_path_cmd(0x06, rem_path);
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
}

/* ==========================================================================
   WINDOW PROCEDURES
   ========================================================================== */
BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE); return TRUE;
}

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
                        
                        if (g_app.conn_type == CONN_SMB) {
                            if (smb_simple_path_cmd(0x00, target_path)) set_status("Created remote SMB directory.");
                            else set_status("Failed to create remote SMB directory.");
                        } else if (g_app.conn_type == CONN_FTP) {
                            if (FtpCreateDirectoryA(g_app.hFtpSession, target_path)) set_status("Created remote FTP directory.");
                            else set_status("Failed to create remote FTP directory.");
                        } else {
                            set_status("Not connected to a remote server.");
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
                    if (g_app.conn_type == CONN_SMB) smb_rename(src_full, dst_full);
                    else FtpRenameFileA(g_app.hFtpSession, src_full, dst_full);
                    set_status("Renamed remote item."); list_remote();
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
    static HWND hN, hS, hPrt, hSh, hU, hP, hChkFTP;
    switch (msg) {
        case WM_CREATE: {
            int y = 10;
            CreateWindowA("STATIC", "Name:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hN = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=30;
            CreateWindowA("STATIC", "Server:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hS = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=30;
            CreateWindowA("STATIC", "Port (Blank=Def):", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hPrt = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=30;
            CreateWindowA("STATIC", "Share/Path:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hSh = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=30;
            CreateWindowA("STATIC", "User:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hU = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=30;
            CreateWindowA("STATIC", "Pass:", WS_CHILD|WS_VISIBLE, 10, y, 90, 20, hwnd, NULL, g_hInst, NULL);
            hP = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD, 110, y, 200, 20, hwnd, NULL, g_hInst, NULL); y+=30;
            
            hChkFTP = CreateWindowA("BUTTON", "FTP Protocol Mode", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 110, y, 200, 20, hwnd, (HMENU)IDC_CHK_FTP, g_hInst, NULL); y+=35;

            CreateWindowA("BUTTON", "Add", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 10, y, 70, 25, hwnd, (HMENU)IDB_ADD, g_hInst, NULL);
            CreateWindowA("BUTTON", "Save", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 87, y, 70, 25, hwnd, (HMENU)IDB_SAVE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Delete", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 164, y, 70, 25, hwnd, (HMENU)IDB_DELETE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Close", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 241, y, 70, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            
            ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
            SetWindowTextA(hN, p->name); SetWindowTextA(hS, p->server); 
            SetWindowTextA(hPrt, p->port);
            SetWindowTextA(hSh, p->share); SetWindowTextA(hU, p->user); SetWindowTextA(hP, p->pass);
            SendMessageA(hChkFTP, BM_SETCHECK, p->is_ftp ? BST_CHECKED : BST_UNCHECKED, 0);
            
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
                
                SendMessageA(g_app.hComboConn, CB_DELETESTRING, g_app.selected_conn_idx, 0);
                SendMessageA(g_app.hComboConn, CB_INSERTSTRING, g_app.selected_conn_idx, (LPARAM)p->name);
                SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0);
                save_config(GetWindow(hwnd, GW_OWNER)); set_status("Connection profile saved.");
            } else if (id == IDB_ADD) {
                if (g_app.conn_count < MAX_CONNECTIONS) {
                    int idx = g_app.conn_count++;
                    
                    GetWindowTextA(hN, g_app.connections[idx].name, 64);
                    GetWindowTextA(hS, g_app.connections[idx].server, 128);
                    GetWindowTextA(hPrt, g_app.connections[idx].port, 16);
                    GetWindowTextA(hSh, g_app.connections[idx].share, 128);
                    GetWindowTextA(hU, g_app.connections[idx].user, 64);
                    GetWindowTextA(hP, g_app.connections[idx].pass, 64);
                    g_app.connections[idx].is_ftp = (SendMessageA(hChkFTP, BM_GETCHECK, 0, 0) == BST_CHECKED);
                    
                    if (strlen(g_app.connections[idx].name) == 0) {
                        strcpy(g_app.connections[idx].name, "New Connection");
                        SetWindowTextA(hN, "New Connection");
                    }
                    
                    SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[idx].name);
                    g_app.selected_conn_idx = idx;
                    SendMessageA(g_app.hComboConn, CB_SETCURSEL, idx, 0);
                    
                    save_config(GetWindow(hwnd, GW_OWNER));
                    set_status("New connection profile added.");
                } else {
                    set_status("Maximum connection limit reached.");
                }
            } else if (id == IDB_DELETE) {
                if (g_app.conn_count > 1) {
                    int del_idx = g_app.selected_conn_idx;
                    for (int i = del_idx; i < g_app.conn_count - 1; i++) {
                        g_app.connections[i] = g_app.connections[i + 1];
                    }
                    g_app.conn_count--;
                    if (g_app.selected_conn_idx >= g_app.conn_count) {
                        g_app.selected_conn_idx = g_app.conn_count - 1;
                    }
                    
                    SendMessageA(g_app.hComboConn, CB_RESETCONTENT, 0, 0);
                    for (int i = 0; i < g_app.conn_count; i++) {
                        SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)g_app.connections[i].name);
                    }
                    SendMessageA(g_app.hComboConn, CB_SETCURSEL, g_app.selected_conn_idx, 0);
                    
                    ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
                    SetWindowTextA(hN, p->name); SetWindowTextA(hS, p->server); 
                    SetWindowTextA(hPrt, p->port);
                    SetWindowTextA(hSh, p->share); SetWindowTextA(hU, p->user); SetWindowTextA(hP, p->pass);
                    SendMessageA(hChkFTP, BM_SETCHECK, p->is_ftp ? BST_CHECKED : BST_UNCHECKED, 0);
                    
                    save_config(GetWindow(hwnd, GW_OWNER));
                    set_status("Connection profile deleted.");
                } else {
                    set_status("Cannot delete the last remaining connection profile.");
                }
            } else if (id == IDB_CANCEL) {
                SendMessageA(hwnd, WM_CLOSE, 0, 0);
            }
            break;
        }
        case WM_CLOSE: EnableWindow(GetWindow(hwnd, GW_OWNER), TRUE); DestroyWindow(hwnd); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            init_ini_path(); g_app.hMain = hwnd; g_app.conn_type = CONN_NONE;
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
            g_app.hStatus = CreateWindowExA(0, "STATIC", "Ready", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);
            
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
            SetWindowPos(g_app.hLblLocal, NULL, 0, 45, w/2, 20, SWP_NOZORDER);
            SetWindowPos(g_app.hLblRemote, NULL, w/2, 45, w/2, 20, SWP_NOZORDER);
            SetWindowPos(g_app.hLocalList, NULL, 0, 65, w/2, h-95, SWP_NOZORDER);
            SetWindowPos(g_app.hRemoteList, NULL, w/2, 65, w/2, h-95, SWP_NOZORDER);
            SetWindowPos(g_app.hStatus, NULL, 0, h-30, w, 30, SWP_NOZORDER);
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
                            nav_dir(g_app.remote_base, item, g_app.conn_type == CONN_FTP);
                            list_remote();
                        } else {
                            nav_dir(g_app.local_base, item, 0); list_local();
                        }
                    }
                }
            }
            switch (id) {
                case ID_BTN_CONNECT: {
                    int idx = SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0);
                    if (idx == CB_ERR) break;
                    ConnectionProfile *p = &g_app.connections[idx];
                    disconnect_all();
                    
                    char cserver[128];
                    const char *s = p->server;
                    if (strncmp(s, "ftp://", 6) == 0) s += 6;
                    else if (strncmp(s, "http://", 7) == 0) s += 7;
                    else if (strncmp(s, "\\\\", 2) == 0) s += 2;
                    strncpy(cserver, s, sizeof(cserver)-1); cserver[sizeof(cserver)-1] = '\0';
                    char *slash = strpbrk(cserver, "/\\"); // Cut any path off the hostname 
                    if (slash) *slash = '\0';              // This specifically resolves WinINet Error 120002!
                    trim_str(cserver);

                    char cshare[128];
                    const char *sh = p->share;
                    while (*sh == '\\' || *sh == '/') sh++;
                    strncpy(cshare, sh, sizeof(cshare)-1); cshare[sizeof(cshare)-1] = '\0';

                    if (p->is_ftp) {
                        set_status("Connecting to %s via FTP...", cserver);
                        g_app.hInternet = InternetOpenA("DualPaneClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
                        if (g_app.hInternet) {
                            const char *ftp_user = (p->user[0] != '\0') ? p->user : NULL;
                            const char *ftp_pass = (p->pass[0] != '\0') ? p->pass : NULL;
                            
                            INTERNET_PORT ftp_port = INTERNET_DEFAULT_FTP_PORT;
                            if (p->port[0] != '\0') {
                                int parsed = atoi(p->port);
                                if (parsed > 0) ftp_port = (INTERNET_PORT)parsed;
                            }
                            
                            g_app.hFtpSession = InternetConnectA(g_app.hInternet, cserver, ftp_port, 
                                                                 ftp_user, ftp_pass, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
                            if (g_app.hFtpSession) {
                                g_app.conn_type = CONN_FTP;
                                normalize_path(cshare, 1);
                                
                                char ftp_path[MAX_SMB_PATH_LEN] = "/";
                                if (cshare[0] != '\0') snprintf(ftp_path, sizeof(ftp_path), "/%s", cshare);
                                strncpy(g_app.remote_base, ftp_path, MAX_SMB_PATH_LEN-1);
                                
                                if (strcmp(g_app.remote_base, "/") != 0) {
                                    if (!FtpSetCurrentDirectoryA(g_app.hFtpSession, g_app.remote_base)) {
                                        strcpy(g_app.remote_base, "/");
                                        FtpSetCurrentDirectoryA(g_app.hFtpSession, "/");
                                    }
                                } else {
                                    FtpSetCurrentDirectoryA(g_app.hFtpSession, "/");
                                }
                                
                                list_remote(); 
                                set_status("Connected via FTP successfully.");
                            } else {
                                set_status("FTP connection failed (Error %lu).", GetLastError());
                                InternetCloseHandle(g_app.hInternet); g_app.hInternet = NULL;
                            }
                        } else set_status("WinINet initialization failed.");
                    } else {
                        set_status("Connecting to %s via SMB...", cserver);
                        WSADATA wd; WSAStartup(MAKEWORD(2,2), &wd);
                        struct addrinfo hints={0}, *res; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
                        
                        char *conn_port = (p->port[0] != '\0') ? p->port : "445"; 
                        
                        if (getaddrinfo(cserver, conn_port, &hints, &res) == 0) {
                            g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                            if (connect(g_app.sconn, res->ai_addr, res->ai_addrlen) == 0) {
                                if (smb_negotiate() && smb_session(p->user, p->pass)) {
                                    normalize_path(cshare, 0);
                                    char fsh[MAX_SMB_PATH]; snprintf(fsh, sizeof(fsh), "\\\\%s\\%s", cserver, cshare);
                                    if (smb_tree_connect(fsh)) {
                                        g_app.conn_type = CONN_SMB;
                                        strcpy(g_app.remote_base, "\\"); // Remote base becomes root inside the connected share
                                        list_remote(); set_status("Connected via SMB successfully.");
                                    } else set_status("SMB Tree Connect failed.");
                                } else set_status("SMB Session/Negotiation failed.");
                            } else set_status("Socket connection failed.");
                            freeaddrinfo(res);
                        } else set_status("Host lookup failed.");
                    }
                    break;
                }
                case ID_BTN_EDIT_CONN: {
                    g_app.selected_conn_idx = SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0);
                    CreateWindowExA(WS_EX_DLGMODALFRAME, "EditConnClass", "Edit Connection", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 335, 290, hwnd, NULL, g_hInst, NULL);
                    EnableWindow(hwnd, FALSE); break;
                }
                case ID_BTN_MKDIR: {
                    CreateWindowExA(WS_EX_DLGMODALFRAME, "CreateDirClass", "Create Directory", WS_VISIBLE|WS_POPUP|WS_CAPTION|WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 300, 110, hwnd, NULL, g_hInst, NULL);
                    EnableWindow(hwnd, FALSE); break;
                }
                case ID_BTN_COPY: case ID_BTN_MOVE: case ID_BTN_RENAME: case ID_BTN_DELETE: do_action(id); break;
            }
            break;
        }
        case WM_DESTROY: disconnect_all(); save_config(hwnd); PostQuitMessage(0); break;
        default: return DefWindowProcA(hwnd, msg, wp, lp);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInst; memset(&g_app, 0, sizeof(g_app)); g_app.mid_counter = 1;
    WNDCLASSEXA wc={sizeof(WNDCLASSEXA),CS_HREDRAW|CS_VREDRAW,MainWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"MainClass",NULL}; RegisterClassExA(&wc);
    WNDCLASSEXA wce={sizeof(WNDCLASSEXA),0,EditConnWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"EditConnClass",NULL}; RegisterClassExA(&wce);
    WNDCLASSEXA wcr={sizeof(WNDCLASSEXA),0,RenameWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"RenameClass",NULL}; RegisterClassExA(&wcr);
    WNDCLASSEXA wcm={sizeof(WNDCLASSEXA),0,CreateDirWndProc,0,0,hInst,NULL,LoadCursor(NULL,IDC_ARROW),(HBRUSH)(COLOR_WINDOW+1),NULL,"CreateDirClass",NULL}; RegisterClassExA(&wcm);
    HWND hwnd = CreateWindowExA(0, "MainClass", "Dual Pane SMB/FTP Client", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInst, NULL);
    ShowWindow(hwnd, nCmdShow); UpdateWindow(hwnd);
    MSG msg; while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return (int)msg.wParam;
}