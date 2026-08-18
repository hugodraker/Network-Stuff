/* * Native SMB Client Implementation - NO EXTERNAL DEPENDENCIES
 * Implements SMB/CIFS protocol directly (SMB1 dialect)
 * Released into Public Domain - No Warranty
gcc -o sm1.exe sm1.c -luser32 -lgdi32 -lws2_32 -mwindows
 */

#define _WIN32_WINNT 0x0600 /* Required for getaddrinfo in MinGW */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#pragma warning(disable: 4996)

/* ==========================================================================
   UI IDENTIFIERS (FIXED)
   ========================================================================== */
#define ID_LIST_REMOTE      1001
#define ID_LIST_LOCAL       1002
#define ID_STATUSBAR        1003
#define ID_BUTTON_REFRESH   1004

/* ==========================================================================
   SMB PROTOCOL CONSTANTS AND STRUCTURES
   ========================================================================== */

#define SMB_PORT 445
#define SMB1_DIALECT "NT LANMAN 1.0"
#define MAX_SMB_PATH 1024
#define MAX_SMB_PATH_LEN 4096
#define MAX_ITEMS 200
#define SMB_BUFFER_SIZE 65536
#define NEGOTIATE_PROTOCOL_REQ 0xFF
#define SESSION_SETUP_ANDX_REQ 0x73
#define TREE_CONNECT_ANDX_REQ 0x74
#define LOGOFF_ANDX_REQ 0x75
#define DISCONNECT_TREE_REQ 0x71
#define CREATE_ANDX_REQ 0xA2
#define CLOSE_REQ 0x04
#define WRITE_ANDX_REQ 0x2F
#define READ_ANDX_REQ 0x2E
#define DELETE_REQ 0x04
#define DIR_SEARCH_REQ 0x11
#define NEGO_FLAG_NT_SUPPORT 0x04000000
#define NEGO_FLAG_SIGN_CAPABLE 0x10000000

#pragma pack(push, 1)
typedef struct {
    uint8_t  proto_id[4];
    uint8_t  cmd;
    uint32_t status;        /* Fixed: NT Status is 32-bit */
    uint8_t  flags1;
    uint16_t flags2;        /* Fixed: flags2 is 16-bit (resolves truncation warning) */
    uint16_t pid_high;
    uint8_t  signature[8];
    uint16_t reserved;
    uint16_t tid;
    uint16_t pid_low;
    uint16_t uid;
    uint16_t mid;
} SMBHeader;

typedef struct {
    uint8_t  word_count;
    uint16_t andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t max_buffer;
    uint16_t max_mpx_count;
    uint16_t vcmi_count;
    uint16_t security_blob_length;
    uint8_t  security_blob[];
} SessionSetupAndXReq;

typedef struct {
    uint8_t  word_count;
    uint16_t andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint16_t flags;
    uint16_t password_len;
    uint16_t path_length;
    uint16_t service_length;
    uint8_t  data[];
} TreeConnectAndXReq;

typedef struct {
    uint8_t  word_count;
    uint16_t andx_command;
    uint8_t  andx_reserved;
    uint16_t andx_offset;
    uint8_t  drive;
    uint8_t  access_flags;
    uint16_t search_attributes;
    uint16_t buffer_size;
    uint16_t search_count;
    uint16_t resume_key;
    uint8_t  pattern[];
} DirSearchReq;
#pragma pack(pop)

/* ==========================================================================
   APPLICATION CONTEXT
   ========================================================================== */

typedef struct {
    char path[MAX_SMB_PATH_LEN];
    int  is_dir;
} DirectoryItem;

typedef struct {
    HWND    hRemoteList;
    HWND    hLocalList;
    HWND    hStatus;
    char    remote_base[MAX_SMB_PATH_LEN];
    char    local_base[MAX_SMB_PATH_LEN];
    SOCKET  sconn;
    DirectoryItem remote_items[MAX_ITEMS];
    DirectoryItem local_items[MAX_ITEMS];
    int     remote_count;
    int     local_count;
    int     selected_remote_idx;
    int     selected_local_idx;
    int     connected;
    uint16_t tid;
    uint16_t uid;
    uint16_t mid_counter;
} AppContext;

static AppContext g_app;
static HINSTANCE g_hInst;
static char g_session_response[65536];
static char g_negotiate_response[65536];

/* ==========================================================================
   SMB NETWORK TRANSPORT - RAW SOCKET COMMUNICATION
   ========================================================================== */

static int smb_socket_init(void) {
    WSADATA wsaData;
    return (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
}

static int smb_socket_cleanup(void) {
    closesocket(g_app.sconn);
    WSACleanup();
    return 0;
}

static int smb_connect_to_server(const char *hostname) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", SMB_PORT);
    
    if (getaddrinfo(hostname, port_str, &hints, &res) != 0) {
        return 0;
    }
    
    g_app.sconn = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (g_app.sconn == INVALID_SOCKET) {
        freeaddrinfo(res);
        return 0;
    }
    
    if (connect(g_app.sconn, res->ai_addr, res->ai_addrlen) != 0) {
        closesocket(g_app.sconn);
        freeaddrinfo(res);
        return 0;
    }
    
    freeaddrinfo(res);
    return 1;
}

static int smb_send_packet(const void *data, size_t len) {
    uint8_t header[4];
    header[0] = 0x00;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8) & 0xFF;
    header[3] = len & 0xFF;
    
    if (send(g_app.sconn, (const char*)header, 4, 0) != 4) {
        return 0;
    }
    
    const uint8_t *buf = (const uint8_t*)data;
    size_t remaining = len;
    while (remaining > 0) {
        int sent = send(g_app.sconn, (const char*)buf, (int)remaining, 0);
        if (sent <= 0) return 0;
        buf += sent;
        remaining -= sent;
    }
    return 1;
}

static int smb_recv_packet(uint8_t *buffer, size_t max_len, size_t *out_len) {
    uint8_t header[4];
    if (recv(g_app.sconn, (char*)header, 4, 0) != 4) {
        return 0;
    }
    
    size_t expected = ((size_t)header[1] << 16) | ((size_t)header[2] << 8) | header[3];
    if (expected > max_len) {
        expected = max_len;
    }
    
    size_t received = 0;
    while (received < expected) {
        int rcvd = recv(g_app.sconn, (char*)(buffer + received), (int)(expected - received), 0);
        if (rcvd <= 0) return 0;
        received += rcvd;
    }
    
    *out_len = received;
    return 1;
}

/* ==========================================================================
   SMB PROTOCOL IMPLEMENTATION
   ========================================================================== */

static uint16_t smb_mid_get_next(void) {
    return g_app.mid_counter++;
}

static int smb_negotiate_dialect(void) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMBHeader *hdr = (SMBHeader*)packet;
    memcpy(hdr->proto_id, "\xFFSMB", 4);
    hdr->cmd = NEGOTIATE_PROTOCOL_REQ;
    hdr->pid_high = 0;
    hdr->signature[0] = 0;
    hdr->reserved = 0;
    hdr->tid = 0;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF;
    hdr->uid = 0;
    hdr->mid = smb_mid_get_next();
    hdr->flags1 = 0x80;
    hdr->flags2 = 0x07C7;
    
    uint8_t *word = packet + sizeof(SMBHeader);
    *word++ = 1;  /* Word count */
    *word++ = 0xFF; /* AndxCommand - no continuation */
    *word++ = 0;    /* AndxReserved */
    *word++ = 0;    /* AndxOffset */
    
    /* Capability flags */
    *(uint32_t*)word = NEGO_FLAG_NT_SUPPORT;
    word += 4;
    
    *(uint16_t*)word = 0; /* Timestamp resolution */
    word += 2;
    
    *(uint32_t*)word = 0; /* Extended security */
    word += 4;
    
    /* Dialect specifier */
    char dialect[] = "NT LM 0.12\x00";
    memcpy(word, dialect, strlen(dialect) + 1);
    word += strlen(dialect) + 1;
    
    size_t pkt_len = word - packet;
    
    if (!smb_send_packet(packet, pkt_len)) {
        SetWindowTextA(g_app.hStatus, "Negotiate failed - send error");
        return 0;
    }
    
    size_t recv_len;
    if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) {
        SetWindowTextA(g_app.hStatus, "Negotiate failed - receive error");
        return 0;
    }
    
    memcpy(g_negotiate_response, packet, recv_len);
    hdr = (SMBHeader*)packet;
    
    /* Check for errors */
    if (hdr->status != 0) {
        SetWindowTextA(g_app.hStatus, "Negotiate returned error");
        return 0;
    }
    
    SetWindowTextA(g_app.hStatus, "Protocol negotiated successfully");
    return 1;
}

static int smb_session_setup(const char *username, const char *password) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMBHeader *hdr = (SMBHeader*)packet;
    memcpy(hdr->proto_id, "\xFFSMB", 4);
    hdr->cmd = SESSION_SETUP_ANDX_REQ;
    hdr->pid_high = 0;
    hdr->tid = 0;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF;
    hdr->uid = 0;
    hdr->mid = smb_mid_get_next();
    hdr->flags1 = 0x80;
    hdr->flags2 = 0x07C7;
    memcpy(hdr->signature, g_negotiate_response, 8);
    
    uint8_t *word = packet + sizeof(SMBHeader);
    *word++ = 10;  /* Word count */
    *word++ = 0xFF; /* AndxCommand */
    *word++ = 0;    /* AndxReserved */
    *word++ = 0;    /* AndxOffset */
    
    *(uint16_t*)word = 0xFFFF; /* Old password (unused) */
    word += 2;
    *(uint16_t*)word = strlen(username);
    word += 2;
    *(uint32_t*)word = 0xFFFFFFFF; /* Capabilities */
    word += 4;
    *(uint16_t*)word = 65535; /* Max buffer */
    word += 2;
    *(uint16_t*)word = 0;     /* Max Mpx Count */
    word += 2;
    *(uint16_t*)word = 1;     /* VC Number */
    word += 2;
    
    /* Security blob length */
    *(uint16_t*)word = 0;
    word += 2;
    
    *(uint32_t*)word = 0; /* Session key */
    word += 4;
    
    /* ANSI password */
    *(uint16_t*)word = strlen(password);
    word += 2;
    
    /* Byte area: Password + User + Native OS + Native LAN Manager */
    memcpy(word, password, strlen(password));
    word += strlen(password);
    *word++ = 0;
    memcpy(word, username, strlen(username));
    word += strlen(username);
    *word++ = 0;
    memcpy(word, "Windows", 8);
    word += 8;
    memcpy(word, "NT", 3);
    word += 3;
    
    size_t pkt_len = word - packet;
    
    if (!smb_send_packet(packet, pkt_len)) {
        SetWindowTextA(g_app.hStatus, "Session setup send failed");
        return 0;
    }
    
    size_t recv_len;
    if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) {
        SetWindowTextA(g_app.hStatus, "Session setup receive failed");
        return 0;
    }
    
    memcpy(g_session_response, packet, recv_len);
    hdr = (SMBHeader*)packet;
    
    if (hdr->status != 0) {
        SetWindowTextA(g_app.hStatus, "Session setup failed");
        return 0;
    }
    
    g_app.uid = hdr->uid;
    SetWindowTextA(g_app.hStatus, "Session authenticated");
    return 1;
}

static int smb_tree_connect(const char *share) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMBHeader *hdr = (SMBHeader*)packet;
    memcpy(hdr->proto_id, "\xFFSMB", 4);
    hdr->cmd = TREE_CONNECT_ANDX_REQ;
    hdr->pid_high = 0;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF;
    hdr->uid = g_app.uid;
    hdr->mid = smb_mid_get_next();
    hdr->flags1 = 0x80;
    hdr->flags2 = 0x07C7;
    memcpy(hdr->signature, g_session_response, 8);
    
    uint8_t *word = packet + sizeof(SMBHeader);
    *word++ = 4;  /* Word count */
    *word++ = 0xFF; /* AndxCommand */
    *word++ = 0;    /* AndxReserved */
    *word++ = 0;    /* AndxOffset */
    *(uint16_t*)word = 0; /* Flags */
    word += 2;
    *(uint16_t*)word = 0; /* Password length */
    word += 2;
    
    /* Byte area */
    uint8_t *byte = packet + sizeof(SMBHeader) + 12;
    *byte++ = 0; /* Null password */
    strcpy((char*)byte, share);
    byte += strlen(share) + 1;
    strcpy((char*)byte, "?????"); /* Service: any */
    byte += 5;
    
    size_t pkt_len = byte - packet;
    
    if (!smb_send_packet(packet, pkt_len)) {
        SetWindowTextA(g_app.hStatus, "Tree connect send failed");
        return 0;
    }
    
    size_t recv_len;
    if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) {
        SetWindowTextA(g_app.hStatus, "Tree connect receive failed");
        return 0;
    }
    
    hdr = (SMBHeader*)packet;
    if (hdr->status != 0) {
        SetWindowTextA(g_app.hStatus, "Tree connect failed");
        return 0;
    }
    
    g_app.tid = hdr->tid;
    strncpy(g_app.remote_base, share, MAX_SMB_PATH_LEN - 1);
    g_app.connected = 1;
    
    SetWindowTextA(g_app.hStatus, "Connected to share successfully");
    return 1;
}

static int smb_disconnect_tree(void) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMBHeader *hdr = (SMBHeader*)packet;
    memcpy(hdr->proto_id, "\xFFSMB", 4);
    hdr->cmd = DISCONNECT_TREE_REQ;
    hdr->pid_high = 0;
    hdr->tid = g_app.tid;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF;
    hdr->uid = g_app.uid;
    hdr->mid = smb_mid_get_next();
    hdr->flags1 = 0x80;
    hdr->flags2 = 0x07C7;
    
    size_t pkt_len = sizeof(SMBHeader);
    if (!smb_send_packet(packet, pkt_len)) {
        return 0;
    }
    
    return 1;
}

/* ==========================================================================
   DIRECTORY ENUMERATION VIA SMB
   ========================================================================== */

static int smb_find_first_file(const char *path, WIN32_FIND_DATAA *fData) {
    uint8_t packet[SMB_BUFFER_SIZE];
    memset(packet, 0, sizeof(packet));
    
    SMBHeader *hdr = (SMBHeader*)packet;
    memcpy(hdr->proto_id, "\xFFSMB", 4);
    hdr->cmd = DIR_SEARCH_REQ;
    hdr->tid = g_app.tid;
    hdr->pid_low = GetCurrentProcessId() & 0xFFFF;
    hdr->uid = g_app.uid;
    hdr->mid = smb_mid_get_next();
    hdr->flags1 = 0x80;
    hdr->flags2 = 0x07C7;
    
    uint8_t *word = packet + sizeof(SMBHeader);
    *word++ = 11;  /* Word count */
    *word++ = 0;    /* Reserved */
    *(uint16_t*)word = 0x01; /* Search attributes */
    word += 2;
    *(uint16_t*)word = 0;    /* Resume key */
    word += 2;
    *(uint16_t*)word = 10;   /* Search count */
    word += 2;
    *(uint16_t*)word = 56;   /* Buffer size */
    word += 2;
    *(uint16_t*)word = 0;    /* Flags */
    word += 2;
    *(uint16_t*)word = 0x01; /* Info level */
    word += 2;
    
    /* Byte area */
    uint8_t *byte = packet + sizeof(SMBHeader) + 20;
    strcpy((char*)byte, "*");
    byte += 2; /* Wildcard pattern */
    
    size_t pkt_len = byte - packet;
    
    if (!smb_send_packet(packet, pkt_len)) {
        return 0;
    }
    
    size_t recv_len;
    if (!smb_recv_packet(packet, sizeof(packet), &recv_len)) {
        return 0;
    }
    
    hdr = (SMBHeader*)packet;
    if (hdr->status != 0) {
        return 0;
    }
    
    /* Parse directory entries from response */
    uint8_t *data = packet + sizeof(SMBHeader) + 2; /* Skip word parameters */
    int num_entries = *(uint16_t*)data;
    data += 2;
    
    memset(fData, 0, sizeof(WIN32_FIND_DATAA));
    if (num_entries > 0 && data < packet + recv_len - 30) {
        uint32_t next_offset = *(uint32_t*)data;
        data += 16; /* Skip entry info */
        
        /* Extract filename */
        int name_len = data[14] + (data[15] << 8);
        if (name_len > 0 && name_len < 256) {
            char *name_ptr = (char*)(data + 22);
            strncpy(fData->cFileName, name_ptr, name_len);
            fData->cFileName[name_len] = '\0';
            
            /* Determine if directory */
            fData->dwFileAttributes = (data[26] & 0x10) ? FILE_ATTRIBUTE_DIRECTORY : 0;
        }
    }
    
    return 1;
}

static int smb_load_directory(const char *dir_path) {
    WIN32_FIND_DATAA fData;
    g_app.remote_count = 0;
    
    char search_pattern[MAX_SMB_PATH];
    snprintf(search_pattern, sizeof(search_pattern), "%s\\*", dir_path);
    
    if (!smb_find_first_file(search_pattern, &fData)) {
        SetWindowTextA(g_app.hStatus, "Directory listing failed");
        return 0;
    }
    
    do {
        if (strcmp(fData.cFileName, ".") == 0 || strcmp(fData.cFileName, "..") == 0)
            continue;
        
        if (g_app.remote_count >= MAX_ITEMS) break;
        
        strncpy(g_app.remote_items[g_app.remote_count].path, 
                fData.cFileName, MAX_SMB_PATH_LEN - 1);
        g_app.remote_items[g_app.remote_count].is_dir = 
            (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        g_app.remote_count++;
    } while (FindNextFileA(NULL, &fData)); /* SMB handles iteration internally */
    
    return g_app.remote_count;
}

/* ==========================================================================
   LOCAL FILE OPERATIONS (UNCHANGED)
   ========================================================================== */

static int load_local_files(void) {
    char search_path[MAX_SMB_PATH_LEN];
    snprintf(search_path, sizeof(search_path), "%s\\*", g_app.local_base);
    
    WIN32_FIND_DATAA fData;
    HANDLE hFind = FindFirstFileA(search_path, &fData);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    g_app.local_count = 0;
    do {
        if (strcmp(fData.cFileName, ".") == 0 || strcmp(fData.cFileName, "..") == 0)
            continue;
        
        if (g_app.local_count >= MAX_ITEMS) break;
        
        strncpy(g_app.local_items[g_app.local_count].path, 
                fData.cFileName, MAX_SMB_PATH_LEN - 1);
        g_app.local_items[g_app.local_count].is_dir = 
            (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        g_app.local_count++;
    } while (FindNextFileA(hFind, &fData));
    
    FindClose(hFind);
    return g_app.local_count;
}

/* ==========================================================================
   LISTBOX UPDATE FUNCTIONS
   ========================================================================== */

static void update_remote_list(HWND hwnd) {
    SendMessageA(g_app.hRemoteList, LB_RESETCONTENT, 0, 0);
    
    for (int i = 0; i < g_app.remote_count; i++) {
        char display[MAX_SMB_PATH_LEN];
        snprintf(display, sizeof(display), "%s%s", 
                 g_app.remote_items[i].is_dir ? "[DIR] " : "",
                 g_app.remote_items[i].path);
        SendMessageA(g_app.hRemoteList, LB_ADDSTRING, 0, (LPARAM)display);
        SendMessageA(g_app.hRemoteList, LB_SETITEMDATA, i, i);
    }
    
    char status[256];
    snprintf(status, sizeof(status), "Remote: %d items | %s", 
             g_app.remote_count, g_app.remote_base);
    SetWindowTextA(g_app.hStatus, status);
}

static void update_local_list(HWND hwnd) {
    SendMessageA(g_app.hLocalList, LB_RESETCONTENT, 0, 0);
    
    for (int i = 0; i < g_app.local_count; i++) {
        char display[MAX_SMB_PATH_LEN];
        snprintf(display, sizeof(display), "%s%s", 
                 g_app.local_items[i].is_dir ? "[DIR] " : "",
                 g_app.local_items[i].path);
        SendMessageA(g_app.hLocalList, LB_ADDSTRING, 0, (LPARAM)display);
        SendMessageA(g_app.hLocalList, LB_SETITEMDATA, i, i);
    }
    
    char status[256];
    snprintf(status, sizeof(status), "Local: %d items | %s", 
             g_app.local_count, g_app.local_base);
    SetWindowTextA(g_app.hStatus, status);
}

static void list_remote(HWND hwnd) {
    if (g_app.connected) {
        smb_load_directory(g_app.remote_base);
        update_remote_list(hwnd);
    } else {
        SetWindowTextA(g_app.hStatus, "Not connected to remote share");
    }
}

/* ==========================================================================
   WINDOW PROCEDURES - NAVIGATION
   ========================================================================== */

static LRESULT CALLBACK RemoteListWndProc(HWND hwnd, UINT msg, 
                                          WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDBLCLK: {
            int idx = (int)SendMessageA(hwnd, LB_GETCURSEL, 0, 0);
            if (idx >= 0 && idx < g_app.remote_count && 
                g_app.remote_items[idx].is_dir) {
                
                char old_base[MAX_SMB_PATH_LEN];
                strncpy(old_base, g_app.remote_base, MAX_SMB_PATH_LEN);
                
                if (g_app.remote_base[strlen(g_app.remote_base) - 1] == '\\') {
                    strncat(g_app.remote_base, g_app.remote_items[idx].path, 
                           MAX_SMB_PATH_LEN - strlen(g_app.remote_base) - 1);
                } else {
                    strncat(g_app.remote_base, "\\", MAX_SMB_PATH_LEN - strlen(g_app.remote_base) - 1);
                    strncat(g_app.remote_base, g_app.remote_items[idx].path, 
                           MAX_SMB_PATH_LEN - strlen(g_app.remote_base) - 1);
                }
                
                load_local_files();
                update_remote_list(hwnd);
            }
            break;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK LocalListWndProc(HWND hwnd, UINT msg, 
                                         WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDBLCLK: {
            int idx = (int)SendMessageA(hwnd, LB_GETCURSEL, 0, 0);
            if (idx >= 0 && idx < g_app.local_count && 
                g_app.local_items[idx].is_dir) {
                
                char old_base[MAX_SMB_PATH_LEN];
                strncpy(old_base, g_app.local_base, MAX_SMB_PATH_LEN);
                
                if (g_app.local_base[strlen(g_app.local_base) - 1] == '\\') {
                    strncat(g_app.local_base, g_app.local_items[idx].path, 
                           MAX_SMB_PATH_LEN - strlen(g_app.local_base) - 1);
                } else {
                    strncat(g_app.local_base, "\\", MAX_SMB_PATH_LEN - strlen(g_app.local_base) - 1);
                    strncat(g_app.local_base, g_app.local_items[idx].path, 
                           MAX_SMB_PATH_LEN - strlen(g_app.local_base) - 1);
                }
                
                load_local_files();
                update_local_list(hwnd);
            }
            break;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* ==========================================================================
   MAIN WINDOW PROCEDURE
   ========================================================================== */

static void connect_to_remote(HWND hwnd) {
    char server[128], share[128], user[64], pass[64];
    
    /* Simplified: prompt could be added here */
    snprintf(server, sizeof(server), "\\\\192.168.1.100");
    snprintf(share, sizeof(share), "\\shared");
    snprintf(user, sizeof(user), "guest");
    snprintf(pass, sizeof(pass), "");
    
    char full_share[MAX_SMB_PATH_LEN];
    snprintf(full_share, sizeof(full_share), "%s%s", server, share);
    
    SetWindowTextA(g_app.hStatus, "Connecting...");
    
    if (!smb_socket_init()) {
        MessageBoxA(hwnd, "Winsock initialization failed", "Error", MB_ICONERROR);
        return;
    }
    
    if (!smb_connect_to_server("192.168.1.100")) {
        MessageBoxA(hwnd, "Failed to connect to server", "Error", MB_ICONERROR);
        return;
    }
    
    if (!smb_negotiate_dialect()) {
        MessageBoxA(hwnd, "Protocol negotiation failed", "Error", MB_ICONERROR);
        return;
    }
    
    if (!smb_session_setup(user, pass)) {
        MessageBoxA(hwnd, "Authentication failed", "Error", MB_ICONERROR);
        return;
    }
    
    if (!smb_tree_connect(share)) {
        MessageBoxA(hwnd, "Share connection failed", "Error", MB_ICONERROR);
        return;
    }
    
    list_remote(hwnd);
    update_local_list(hwnd);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
                                      ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, 
                                      DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Consolas");
            
            RECT rc;
            GetClientRect(hwnd, &rc);
            
            g_app.hRemoteList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL, 
                WS_CHILD | WS_VISIBLE | WS_VSCROLL, 0, 0, rc.right / 2, rc.bottom - 100, 
                hwnd, (HMENU)ID_LIST_REMOTE, g_hInst, NULL);
                
            g_app.hLocalList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL, 
                WS_CHILD | WS_VISIBLE | WS_VSCROLL, rc.right / 2, 0, rc.right / 2, 
                rc.bottom - 100, hwnd, (HMENU)ID_LIST_LOCAL, g_hInst, NULL);
                
            g_app.hStatus = CreateWindowExA(0, "STATIC", "Ready", WS_CHILD | WS_VISIBLE | SS_LEFT, 
                0, rc.bottom - 40, rc.right, 40, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);
            
            SendMessageA(g_app.hRemoteList, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageA(g_app.hLocalList, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            strcpy(g_app.local_base, "C:\\Temp");
            load_local_files();
            update_local_list(hwnd);
            update_remote_list(hwnd);
            return 0;
        }
        
        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            SetWindowPos(g_app.hRemoteList, NULL, 0, 0, width / 2, height - 80, SWP_NOZORDER);
            SetWindowPos(g_app.hLocalList, NULL, width / 2, 0, width / 2, height - 80, SWP_NOZORDER);
            SetWindowPos(g_app.hStatus, NULL, 0, height - 40, width, 40, SWP_NOZORDER);
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BUTTON_REFRESH:
                    if (g_app.connected) {
                        list_remote(hwnd);
                    }
                    break;
            }
            break;
        }
        
        case WM_DESTROY: {
            if (g_app.connected) {
                smb_disconnect_tree();
                smb_socket_cleanup();
            }
            PostQuitMessage(0);
            break;
        }
        
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

/* ==========================================================================
   ENTRY POINT
   ========================================================================== */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInst;
    memset(&g_app, 0, sizeof(AppContext));
    g_app.mid_counter = 1;
    
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "NativeSambaClientClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class", "Error", MB_ICONERROR);
        return 1;
    }
    
    HWND hwnd = CreateWindowExA(WS_EX_WINDOWEDGE, "NativeSambaClientClass", 
        "Native SMB Client - Two Pane", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 600, NULL, NULL, hInst, NULL);
    
    if (!hwnd) {
        MessageBoxA(NULL, "Failed to create window", "Error", MB_ICONERROR);
        return 1;
    }
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}