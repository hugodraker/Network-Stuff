/* ============================================================================
 * IMAP Email Server - C Implementation with Encryption, Caching, & Storage
 *
 * COMPILATION INSTRUCTIONS:
 *   gcc -Os -s -Wl,--subsystem,windows -mwindows -o imapd.exe imapd.c -lgdi32 -lole32 -limm32 -lcomdlg32 -lcomctl32 -lws2_32 -lwinmm -lshlwapi -ladvapi32
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <shlwapi.h>

// Resource IDs
#define ID_TRAY_ICON 1
#define ID_MENU_START_STOP 101
#define ID_MENU_EXIT 102
#define ID_MENU_SETTINGS 103
#define ID_EDIT_PORT 1001
#define ID_BTN_STARTSTOP 1002
#define ID_EDIT_TIMEOUT 1003
#define ID_BTN_CLOSE 1004
#define ID_LIST_USERS 1005
#define ID_EDIT_NEWUSER 1006
#define ID_EDIT_OLDPASS 1007
#define ID_EDIT_NEWPASS 1008
#define ID_CHK_ENCRYPT 1009
#define ID_BTN_ADDUSER 1010
#define WM_TRAYICON (WM_USER + 1)
#define WM_PORT_UPDATE (WM_USER + 2)
#define WM_PROGRESS_DONE (WM_USER + 3)
#define TIMER_PORT_DELAY 1000
#define TIMER_PROG_CLOSE 1001
#define TIMER_CSV_SYNC 1002

// ----------------------------------------------------------------------------
// GLOBAL STATE & STRUCTURES
// ----------------------------------------------------------------------------
typedef struct {
    int port;
    int timeout_ms;
    int csv_sync_ms;
    BOOL running;
    BOOL encrypt_data;
    SOCKET listen_socket;
    HANDLE worker_thread;
    HWND settings_hwnd;
    HWND progress_hwnd;
    HWND prog_label;
    HWND edit_port;
    HWND edit_timeout;
    HWND btn_startstop;
    HWND btn_close;
    HWND list_users;
    HWND edit_username;
    HWND edit_oldpass;
    HWND edit_password;
    HWND chk_encrypt;
    HWND btn_adduser;
    NOTIFYICONDATAA nid;
    HBRUSH green_brush;
    HBRUSH gray_brush;
    HFONT font_ui;
} GlobalState;

typedef struct {
    SOCKET sock;
    char user[256];
    char plain_pass[256];
    char mailbox[256];
    BOOL authenticated;
} ClientSession;

typedef struct {
    char user[256];
    char old_pass[256];
    char new_pass[256];
} ReencryptParams;

typedef struct CachedCSV {
    char path[MAX_PATH];
    char* data;
    size_t len;
    size_t cap;
    BOOL dirty;
    char pass[256];
    struct CachedCSV* next;
} CachedCSV;

static GlobalState g_state = {0};
static WCHAR g_ini_path[MAX_PATH];
static CachedCSV* g_csv_cache = NULL;
static CRITICAL_SECTION g_csv_cs;

// ----------------------------------------------------------------------------
// UTILITIES & CRYPTOGRAPHY
// ----------------------------------------------------------------------------
static void TrimString(char* str) {
    char* start;
    char* end;
    if (!str) return;
    start = str;
    while (*start == ' ' || *start == '\t') start++;
    if (start != str) memmove(str, start, strlen(start) + 1);
    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) *end-- = '\0';
}

static void SanitizePath(char* path) {
    char* p = path;
    while (*p) {
        if (*p == '/' || *p == '\\' || *p == ':') *p = '_';
        p++;
    }
    if (strstr(path, "..")) {
        p = path;
        while (*p) { if (*p == '.') *p = '_'; p++; }
    }
}

static int CaseInsensitiveCompare(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return *a - *b;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static char* DuplicateString(const char* s) {
    char* d;
    if (!s) return NULL;
    d = (char*)malloc(strlen(s) + 1);
    if (d) strcpy(d, s);
    return d;
}

static void ComputeSaltedHash(const char* pass, const char* salt, char* out_hex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    out_hex[0] = '\0';
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE hash_bytes[32];
            DWORD hash_len = 32;
            DWORD i;
            CryptHashData(hHash, (const BYTE*)salt, (DWORD)strlen(salt), 0);
            CryptHashData(hHash, (const BYTE*)pass, (DWORD)strlen(pass), 0);
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash_bytes, &hash_len, 0)) {
                for (i = 0; i < hash_len; i++) sprintf(out_hex + (i * 2), "%02x", hash_bytes[i]);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

static void FastXorCipherChunk(BYTE* data, size_t len, const char* pass, size_t offset) {
    char key[128];
    size_t key_len;
    size_t i;
    if (!pass || !pass[0]) return;
    ComputeSaltedHash(pass, "salty", key);
    key_len = strlen(key);
    for(i = 0; i < len; i++) data[i] ^= key[(offset + i) % key_len];
}

static char* ReadEntireFile(const char* path, const char* pass, BOOL encrypted) {
    FILE* f = fopen(path, "rb");
    long size;
    char* buf;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char*)malloc(size + 1);
    fread(buf, 1, size, f);
    fclose(f);
    if (encrypted && pass) FastXorCipherChunk((BYTE*)buf, size, pass, 0);
    buf[size] = '\0';
    return buf;
}

// ----------------------------------------------------------------------------
// IN-MEMORY CSV CACHE MANAGER (Thread-Safe)
// ----------------------------------------------------------------------------
static void InitCSVCache(void) {
    InitializeCriticalSection(&g_csv_cs);
}

static void FlushCSVCache(BOOL free_memory) {
    CachedCSV* curr;
    EnterCriticalSection(&g_csv_cs);
    curr = g_csv_cache;
    while (curr) {
        if (curr->dirty) {
            FILE* f = fopen(curr->path, "wb");
            if (f) {
                if (g_state.encrypt_data) {
                    char* enc = (char*)malloc(curr->len);
                    memcpy(enc, curr->data, curr->len);
                    FastXorCipherChunk((BYTE*)enc, curr->len, curr->pass, 0);
                    fwrite(enc, 1, curr->len, f);
                    free(enc);
                } else {
                    fwrite(curr->data, 1, curr->len, f);
                }
                fclose(f);
            }
            curr->dirty = FALSE;
        }
        if (free_memory) {
            CachedCSV* next = curr->next;
            free(curr->data);
            free(curr);
            curr = next;
        } else {
            curr = curr->next;
        }
    }
    if (free_memory) g_csv_cache = NULL;
    LeaveCriticalSection(&g_csv_cs);
}

static char* ReadCSVCached(const char* path, const char* pass, BOOL encrypted) {
    char* result = NULL;
    CachedCSV* curr;
    
    EnterCriticalSection(&g_csv_cs);
    curr = g_csv_cache;
    while (curr) {
        if (CaseInsensitiveCompare(curr->path, path) == 0) break;
        curr = curr->next;
    }
    
    if (!curr) {
        FILE* f = fopen(path, "rb");
        char* buf = NULL;
        long size = 0;
        if (f) {
            fseek(f, 0, SEEK_END);
            size = ftell(f);
            fseek(f, 0, SEEK_SET);
            buf = (char*)malloc(size + 1);
            fread(buf, 1, size, f);
            fclose(f);
            if (encrypted && pass) FastXorCipherChunk((BYTE*)buf, size, pass, 0);
            buf[size] = '\0';
        }
        
        curr = (CachedCSV*)calloc(1, sizeof(CachedCSV));
        strcpy(curr->path, path);
        if (pass) strcpy(curr->pass, pass);
        if (buf) {
            curr->len = size;
            curr->cap = size + 1;
            curr->data = buf;
        } else {
            curr->len = 0;
            curr->cap = 256;
            curr->data = (char*)malloc(curr->cap);
            curr->data[0] = '\0';
        }
        curr->dirty = FALSE;
        curr->next = g_csv_cache;
        g_csv_cache = curr;
    }
    
    if (curr && curr->data) result = DuplicateString(curr->data);
    LeaveCriticalSection(&g_csv_cs);
    return result;
}

static void AppendCSVCached(const char* path, const char* pass, BOOL encrypted, const char* line) {
    CachedCSV* curr;
    char* temp;
    
    EnterCriticalSection(&g_csv_cs);
    // Ensure loaded
    temp = ReadCSVCached(path, pass, encrypted);
    if (temp) free(temp);
    
    curr = g_csv_cache;
    while (curr) {
        if (CaseInsensitiveCompare(curr->path, path) == 0) {
            size_t line_len = strlen(line);
            if (curr->len + line_len + 1 > curr->cap) {
                curr->cap = (curr->len + line_len) * 2 + 256;
                curr->data = (char*)realloc(curr->data, curr->cap);
            }
            memcpy(curr->data + curr->len, line, line_len);
            curr->len += line_len;
            curr->data[curr->len] = '\0';
            curr->dirty = TRUE;
            break;
        }
        curr = curr->next;
    }
    LeaveCriticalSection(&g_csv_cs);
}

// ----------------------------------------------------------------------------
// AST PARSER
// ----------------------------------------------------------------------------
typedef enum { NODE_COMMAND, NODE_STRING, NODE_ATOM } ASTNodeType;

typedef struct ASTNode {
    ASTNodeType type;
    char* value;
    struct ASTNode* child;
    struct ASTNode* next;
} ASTNode;

static ASTNode* CreateNode(ASTNodeType type, const char* value) {
    ASTNode* node = (ASTNode*)calloc(1, sizeof(ASTNode));
    node->type = type;
    if (value) node->value = DuplicateString(value);
    return node;
}

static void FreeAST(ASTNode* node) {
    while (node) {
        ASTNode* next = node->next;
        if (node->child) FreeAST(node->child);
        if (node->value) free(node->value);
        free(node);
        node = next;
    }
}

static ASTNode* ParseIMAPCommand(char* line) {
    char* start;
    char tag[64] = {0};
    char cmd[64] = {0};
    ASTNode* root;
    ASTNode* current_arg;

    while (*line == ' ' || *line == '\t') line++;
    if (!*line) return NULL;

    start = line;
    while (*line && *line != ' ' && *line != '\t') line++;
    snprintf(tag, sizeof(tag), "%.*s", (int)(line - start), start);
    root = CreateNode(NODE_COMMAND, tag);
    
    while (*line == ' ' || *line == '\t') line++;
    if (!*line) return root;

    start = line;
    while (*line && *line != ' ' && *line != '\t') line++;
    snprintf(cmd, sizeof(cmd), "%.*s", (int)(line - start), start);
    root->child = CreateNode(NODE_ATOM, cmd);
    current_arg = root->child;

    while (*line) {
        while (*line == ' ' || *line == '\t') line++;
        if (!*line) break;

        if (*line == '"') {
            char* str;
            line++;
            start = line;
            while (*line && *line != '"') line++;
            str = (char*)malloc(line - start + 1);
            memcpy(str, start, line - start);
            str[line - start] = '\0';
            current_arg->next = CreateNode(NODE_STRING, str);
            current_arg = current_arg->next;
            free(str);
            if (*line == '"') line++;
        } else {
            char* atom;
            start = line;
            while (*line && *line != ' ' && *line != '\t') line++;
            atom = (char*)malloc(line - start + 1);
            memcpy(atom, start, line - start);
            atom[line - start] = '\0';
            current_arg->next = CreateNode(NODE_ATOM, atom);
            current_arg = current_arg->next;
            free(atom);
        }
    }
    return root;
}

// ----------------------------------------------------------------------------
// CONFIGURATION & INITIALIZATION
// ----------------------------------------------------------------------------
static BOOL GetINIPath(void) {
    if (GetModuleFileNameW(NULL, g_ini_path, MAX_PATH) > 0) {
        PathRemoveFileSpecW(g_ini_path);
        wcscat_s(g_ini_path, MAX_PATH, L"\\imapd.ini");
        return TRUE;
    }
    return FALSE;
}

static void LoadSettings(void) {
    g_state.port = 143;
    g_state.timeout_ms = 2000;
    g_state.csv_sync_ms = 1200000; // 20 mins default
    g_state.encrypt_data = TRUE;
    
    if (GetINIPath()) {
        WCHAR check_user[256];
        int sync_mins;
        g_state.port = GetPrivateProfileIntW(L"Server", L"Port", 143, g_ini_path);
        if (g_state.port < 1 || g_state.port > 65535) g_state.port = 143;
        
        g_state.timeout_ms = GetPrivateProfileIntW(L"Server", L"Timeout", 2000, g_ini_path);
        if (g_state.timeout_ms <= 0) g_state.timeout_ms = 2000;
        
        sync_mins = GetPrivateProfileIntW(L"Server", L"CsvSyncMins", 20, g_ini_path);
        if (sync_mins < 1) sync_mins = 1;
        g_state.csv_sync_ms = sync_mins * 60000;
        
        g_state.encrypt_data = GetPrivateProfileIntW(L"Server", L"EncryptData", 1, g_ini_path);
        
        GetPrivateProfileStringW(L"Users", L"admin", L"", check_user, 256, g_ini_path);
        if (wcslen(check_user) == 0) {
            char hash[128];
            WCHAR w_val[256];
            ComputeSaltedHash("password", "salty", hash);
            swprintf_s(w_val, 256, L"salty:%hs", hash);
            WritePrivateProfileStringW(L"Users", L"admin", w_val, g_ini_path);
        }
    }
}

static void SaveSettings(void) {
    if (GetINIPath()) {
        wchar_t val_str[32];
        swprintf_s(val_str, 32, L"%d", g_state.port);
        WritePrivateProfileStringW(L"Server", L"Port", val_str, g_ini_path);
        swprintf_s(val_str, 32, L"%d", g_state.timeout_ms);
        WritePrivateProfileStringW(L"Server", L"Timeout", val_str, g_ini_path);
        swprintf_s(val_str, 32, L"%d", g_state.encrypt_data);
        WritePrivateProfileStringW(L"Server", L"EncryptData", val_str, g_ini_path);
    }
}

static void InitUserMailbox(const char* user, const char* mbox, char* out_mbox_dir, char* out_csv_path) {
    char path[MAX_PATH];
    char user_dir[MAX_PATH];
    char safe_user[256] = {0};
    char clean_mbox[256] = {0};
    char mbox_dir[MAX_PATH];
    char csv_path[MAX_PATH];
    
    GetModuleFileNameA(NULL, path, MAX_PATH);
    PathRemoveFileSpecA(path);
    
    strncpy(safe_user, user, 255);
    SanitizePath(safe_user);
    if (strlen(safe_user) == 0) strcpy(safe_user, "Unknown");
    
    sprintf(user_dir, "%s\\%s", path, safe_user);
    CreateDirectoryA(user_dir, NULL);
    
    strncpy(clean_mbox, mbox, 255);
    SanitizePath(clean_mbox);
    if (strlen(clean_mbox) == 0) strcpy(clean_mbox, "INBOX");
    
    sprintf(mbox_dir, "%s\\%s", user_dir, clean_mbox);
    CreateDirectoryA(mbox_dir, NULL);
    
    sprintf(csv_path, "%s\\%s.csv", user_dir, clean_mbox);
    
    if (out_mbox_dir) strcpy(out_mbox_dir, mbox_dir);
    if (out_csv_path) strcpy(out_csv_path, csv_path);
}

static int GetMessageCount(const char* user, const char* mbox, const char* plain_pass) {
    char csv_path[MAX_PATH];
    char* csv_data;
    int count = 0;
    
    InitUserMailbox(user, mbox, NULL, csv_path);
    csv_data = ReadCSVCached(csv_path, plain_pass, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) count++;
            if (!nl) break;
            p = nl + 1;
        }
        free(csv_data);
    }
    return count;
}

// ----------------------------------------------------------------------------
// IMAP COMMANDS
// ----------------------------------------------------------------------------
static void SendSocketData(SOCKET sock, const char* data) {
    send(sock, data, strlen(data), 0);
}
static void SendResponse(SOCKET sock, const char* response) {
    SendSocketData(sock, response);
    SendSocketData(sock, "\r\n");
}
static void SendTaggedResponse(SOCKET sock, const char* tag, const char* code, const char* message) {
    char response[512];
    snprintf(response, sizeof(response), "%s %s %s\r\n", tag, code, message);
    SendSocketData(sock, response);
}

static void CmdCapability(ClientSession* session, const char* tag) {
    SendResponse(session->sock, "* CAPABILITY IMAP4rev1");
    SendTaggedResponse(session->sock, tag, "OK", "CAPABILITY completed");
}

static void CmdLogin(ClientSession* session, const char* tag, ASTNode* args) {
    const char* user;
    const char* pass;
    if (!args || !args->next) { SendTaggedResponse(session->sock, tag, "BAD", "Missing args"); return; }
    
    user = args->value;
    pass = args->next->value;
    
    if (GetINIPath()) {
        WCHAR w_user[256], w_val[512];
        MultiByteToWideChar(CP_UTF8, 0, user, -1, w_user, 256);
        GetPrivateProfileStringW(L"Users", w_user, L"", w_val, 512, g_ini_path);
        
        if (wcslen(w_val) > 0) {
            char val[512];
            char* colon;
            WideCharToMultiByte(CP_UTF8, 0, w_val, -1, val, 512, NULL, NULL);
            colon = strchr(val, ':');
            if (colon) {
                char computed_hash[128];
                *colon = '\0';
                ComputeSaltedHash(pass, val, computed_hash);
                if (CaseInsensitiveCompare(computed_hash, colon + 1) == 0) {
                    session->authenticated = TRUE;
                    strncpy(session->user, user, 255);
                    strncpy(session->plain_pass, pass, 255);
                    InitUserMailbox(session->user, "INBOX", NULL, NULL);
                    SendTaggedResponse(session->sock, tag, "OK", "LOGIN completed");
                    return;
                }
            }
        }
    }
    SendTaggedResponse(session->sock, tag, "NO", "Invalid credentials");
}

static void CmdCreate(ClientSession* session, const char* tag, ASTNode* args) {
    if (!args) { SendTaggedResponse(session->sock, tag, "BAD", "Missing folder name"); return; }
    InitUserMailbox(session->user, args->value, NULL, NULL);
    SendTaggedResponse(session->sock, tag, "OK", "CREATE completed");
}

static void CmdSelect(ClientSession* session, const char* tag, ASTNode* args) {
    int count;
    char response[256];
    if (!args) { SendTaggedResponse(session->sock, tag, "BAD", "Missing mailbox"); return; }
    
    strncpy(session->mailbox, args->value, 255);
    InitUserMailbox(session->user, session->mailbox, NULL, NULL);
    count = GetMessageCount(session->user, session->mailbox, session->plain_pass);
    
    sprintf(response, "* %d EXISTS", count); SendResponse(session->sock, response);
    sprintf(response, "* %d RECENT", count); SendResponse(session->sock, response);
    SendResponse(session->sock, "* OK [UIDVALIDITY 1] UIDs valid");
    SendResponse(session->sock, "* OK [UIDNEXT 1000] Predicted next UID");
    SendTaggedResponse(session->sock, tag, "OK", "SELECT completed");
}

static void CmdList(ClientSession* session, const char* tag) {
    SendResponse(session->sock, "* LIST (\\HasNoChildren) \".\" \"INBOX\"");
    SendResponse(session->sock, "* LIST (\\HasNoChildren \\Drafts) \".\" \"Drafts\"");
    SendResponse(session->sock, "* LIST (\\HasNoChildren \\Sent) \".\" \"Sent\"");
    SendResponse(session->sock, "* LIST (\\HasNoChildren \\Trash) \".\" \"Trash\"");
    SendTaggedResponse(session->sock, tag, "OK", "LIST completed");
}

static void CmdStatus(ClientSession* session, const char* tag, ASTNode* args) {
    int count;
    char response[256];
    const char* mbox = (args && args->value) ? args->value : "INBOX";
    count = GetMessageCount(session->user, mbox, session->plain_pass);
    sprintf(response, "* STATUS \"%s\" (MESSAGES %d UNSEEN 0 RECENT 0)", mbox, count);
    SendResponse(session->sock, response);
    SendTaggedResponse(session->sock, tag, "OK", "STATUS completed");
}

static void CmdNoop(ClientSession* session, const char* tag) {
    SendTaggedResponse(session->sock, tag, "OK", "NOOP completed");
}

static void CmdLogout(ClientSession* session, const char* tag) {
    SendResponse(session->sock, "* BYE Logging out");
    SendTaggedResponse(session->sock, tag, "OK", "LOGOUT completed");
}

static BOOL MatchesSequence(int id, int max_id, const char* seq) {
    int start = 0, end = 0;
    if (!seq || CaseInsensitiveCompare(seq, "ALL") == 0) return TRUE;
    if (strcmp(seq, "*") == 0) return id == max_id;
    if (strchr(seq, ':')) {
        if (sscanf(seq, "%d:%d", &start, &end) == 2) return (id >= start && id <= end);
        else if (sscanf(seq, "%d:*", &start) == 1) return (id >= start && id <= max_id);
    } else {
        start = atoi(seq);
        if (start > 0) return id == start;
    }
    return TRUE; 
}

static void FetchMessage(ClientSession* session, int seq_num, int uid, const char* flags, const char* filename, ASTNode* fetch_args) {
    char mbox_dir[MAX_PATH];
    char eml_path[MAX_PATH];
    FILE* f;
    int file_size = 0;
    char response_head[1024] = {0};
    char attr_buf[256] = {0};
    BOOL need_body = FALSE, need_size = FALSE;
    ASTNode* curr = fetch_args;
    
    InitUserMailbox(session->user, session->mailbox, mbox_dir, NULL);
    sprintf(eml_path, "%s\\%s", mbox_dir, filename);
    
    f = fopen(eml_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        file_size = ftell(f);
        fseek(f, 0, SEEK_SET);
    }
    
    while(curr) {
        if (strstr(curr->value, "BODY") != NULL || strstr(curr->value, "RFC822") != NULL) {
            if (strstr(curr->value, "SIZE") != NULL) need_size = TRUE;
            else need_body = TRUE;
        }
        curr = curr->next;
    }
    
    sprintf(response_head, "* %d FETCH (UID %d FLAGS (%s)", seq_num, uid, flags);
    if (need_size) {
        sprintf(attr_buf, " RFC822.SIZE %d", file_size);
        strcat(response_head, attr_buf);
    }
    
    if (need_body && f) {
        sprintf(attr_buf, " BODY[] {%d}\r\n", file_size);
        strcat(response_head, attr_buf);
        SendSocketData(session->sock, response_head);
        
        char chunk[4096];
        int bytes;
        size_t offset = 0;
        while ((bytes = fread(chunk, 1, sizeof(chunk), f)) > 0) {
            if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)chunk, bytes, session->plain_pass, offset);
            send(session->sock, chunk, bytes, 0);
            offset += bytes;
        }
        SendResponse(session->sock, ")"); 
    } else {
        strcat(response_head, ")");
        SendResponse(session->sock, response_head);
    }
    if (f) fclose(f);
}

static void CmdSearch(ClientSession* session, const char* tag, ASTNode* args, BOOL is_uid) {
    char csv_path[MAX_PATH];
    char search_result[4096] = "* SEARCH";
    char* csv_data;
    
    InitUserMailbox(session->user, session->mailbox, NULL, csv_path);
    csv_data = ReadCSVCached(csv_path, session->plain_pass, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                int seq_num, uid;
                if (sscanf(p, "%d,%d,", &seq_num, &uid) == 2) {
                    char id_str[32];
                    sprintf(id_str, " %d", is_uid ? uid : seq_num);
                    if (strlen(search_result) + strlen(id_str) < sizeof(search_result) - 2) {
                        strcat(search_result, id_str);
                    }
                }
            }
            if (!nl) break;
            p = nl + 1;
        }
        free(csv_data);
    }
    SendResponse(session->sock, search_result);
    SendTaggedResponse(session->sock, tag, "OK", "SEARCH completed");
}

static void CmdFetchEx(ClientSession* session, const char* tag, ASTNode* args, BOOL is_uid) {
    char csv_path[MAX_PATH];
    int max_id = 0;
    const char* sequence_set;
    ASTNode* fetch_items;
    char* csv_data;
    
    if (!args || !args->next) { SendTaggedResponse(session->sock, tag, "BAD", "Missing args"); return; }
    sequence_set = args->value;
    fetch_items = args->next;
    
    InitUserMailbox(session->user, session->mailbox, NULL, csv_path);
    csv_data = ReadCSVCached(csv_path, session->plain_pass, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) max_id++;
            if (!nl) break;
            p = nl + 1;
        }
        
        p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                int seq_num, uid;
                char flags[128], filename[MAX_PATH];
                if (sscanf(p, "%d,%d,%127[^,],%255s", &seq_num, &uid, flags, filename) == 4) {
                    int compare_id = is_uid ? uid : seq_num;
                    if (MatchesSequence(compare_id, max_id, sequence_set)) {
                        FetchMessage(session, seq_num, uid, flags, filename, fetch_items);
                    }
                }
            }
            if (!nl) break;
            p = nl + 1;
        }
        free(csv_data);
    }
    SendTaggedResponse(session->sock, tag, "OK", "FETCH completed");
}

static void CmdFetch(ClientSession* session, const char* tag, ASTNode* args) { CmdFetchEx(session, tag, args, FALSE); }

static void CmdUid(ClientSession* session, const char* tag, ASTNode* args) {
    if (args) {
        if (CaseInsensitiveCompare(args->value, "FETCH") == 0) CmdFetchEx(session, tag, args->next, TRUE);
        else if (CaseInsensitiveCompare(args->value, "SEARCH") == 0) CmdSearch(session, tag, args->next, TRUE);
        else SendTaggedResponse(session->sock, tag, "BAD", "Unsupported UID command");
    } else SendTaggedResponse(session->sock, tag, "BAD", "Missing UID argument");
}

static void SaveAppendData(ClientSession* session, const char* tag, const char* mbox, int literal_size, char* buffer_ptr, int buffer_avail, int* consumed) {
    char mbox_dir[MAX_PATH], csv_path[MAX_PATH], eml_path[MAX_PATH];
    int next_id = 1;
    char* csv_data;
    FILE* feml;
    int remaining, chunk;
    size_t file_offset = 0;
    
    InitUserMailbox(session->user, mbox, mbox_dir, csv_path);
    csv_data = ReadCSVCached(csv_path, session->plain_pass, g_state.encrypt_data);
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) next_id++;
            if (!nl) break;
            p = nl + 1;
        }
        free(csv_data);
    }
    
    sprintf(eml_path, "%s\\%08d.txt", mbox_dir, next_id);
    feml = fopen(eml_path, "wb");
    
    remaining = literal_size;
    chunk = buffer_avail > remaining ? remaining : buffer_avail;
    
    if (chunk > 0 && feml) {
        if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)buffer_ptr, chunk, session->plain_pass, file_offset);
        fwrite(buffer_ptr, 1, chunk, feml);
        remaining -= chunk;
        file_offset += chunk;
        *consumed = chunk;
    } else *consumed = 0;
    
    {
        char tmp[2048];
        while (remaining > 0) {
            int to_read = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
            int r = recv(session->sock, tmp, to_read, 0);
            if (r <= 0) break;
            if (feml) {
                if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)tmp, r, session->plain_pass, file_offset);
                fwrite(tmp, 1, r, feml);
                file_offset += r;
            }
            remaining -= r;
        }
    }
    if (feml) fclose(feml);
    
    {
        char line[256];
        sprintf(line, "%d,%d,\\Draft,%08d.txt\n", next_id, next_id, next_id);
        AppendCSVCached(csv_path, session->plain_pass, g_state.encrypt_data, line);
    }
    SendTaggedResponse(session->sock, tag, "OK", "APPEND completed");
}

static void ProcessCommand(ClientSession* session, char* line) {
    ASTNode* ast;
    TrimString(line);
    ast = ParseIMAPCommand(line);
    if (!ast) return;
    if (ast->type == NODE_COMMAND && ast->child) {
        const char* tag = ast->value;
        ASTNode* cmd_node = ast->child;
        const char* cmd = cmd_node->value;
        ASTNode* args = cmd_node->next;
        
        if (CaseInsensitiveCompare(cmd, "CAPABILITY") == 0) CmdCapability(session, tag);
        else if (CaseInsensitiveCompare(cmd, "NOOP") == 0) CmdNoop(session, tag);
        else if (CaseInsensitiveCompare(cmd, "LOGOUT") == 0) CmdLogout(session, tag);
        else if (CaseInsensitiveCompare(cmd, "LOGIN") == 0) CmdLogin(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "CREATE") == 0) CmdCreate(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "SELECT") == 0 || CaseInsensitiveCompare(cmd, "EXAMINE") == 0) CmdSelect(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "LIST") == 0) CmdList(session, tag);
        else if (CaseInsensitiveCompare(cmd, "STATUS") == 0) CmdStatus(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "FETCH") == 0) CmdFetch(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "SEARCH") == 0) CmdSearch(session, tag, args, FALSE);
        else if (CaseInsensitiveCompare(cmd, "UID") == 0) CmdUid(session, tag, args);
        else SendTaggedResponse(session->sock, tag, "BAD", "Unknown command");
    }
    FreeAST(ast);
}

// ----------------------------------------------------------------------------
// SERVER CORE & NETWORKING
// ----------------------------------------------------------------------------
static void HandleClient(SOCKET client) {
    ClientSession session = {0};
    char buffer[4096];
    int buf_len = 0;
    int timeout = g_state.timeout_ms;
    
    session.sock = client;
    if (timeout <= 0) timeout = 2000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    SendResponse(client, "* OK IMAP4rev1 Service Ready");
    
    while (1) {
        char* line_start;
        char* nl;
        int r = recv(client, buffer + buf_len, sizeof(buffer) - 1 - buf_len, 0);
        if (r <= 0) break;
        buf_len += r;
        buffer[buf_len] = '\0';
        line_start = buffer;
        
        while ((nl = strchr(line_start, '\n')) != NULL) {
            char* line;
            char* lbrace;
            char* rbrace;
            int literal_size = 0;
            *nl = '\0';
            if (nl > line_start && *(nl-1) == '\r') *(nl-1) = '\0';
            line = line_start;
            line_start = nl + 1;
            if (strlen(line) == 0) continue;
            
            lbrace = strrchr(line, '{');
            rbrace = strrchr(line, '}');
            if (lbrace && rbrace && rbrace > lbrace && *(rbrace+1) == '\0') {
                literal_size = atoi(lbrace + 1);
                *lbrace = '\0';
            }
            if (literal_size > 0) {
                ASTNode* ast = ParseIMAPCommand(line);
                if (ast && ast->type == NODE_COMMAND && ast->child) {
                    const char* tag = ast->value;
                    const char* cmd = ast->child->value;
                    if (CaseInsensitiveCompare(cmd, "APPEND") == 0) {
                        if (!session.authenticated) SendTaggedResponse(client, tag, "NO", "Authenticate first");
                        else {
                            ASTNode* args = ast->child->next;
                            const char* mbox = args ? args->value : "Drafts";
                            int consumed = 0;
                            int avail = buf_len - (line_start - buffer);
                            SendSocketData(client, "+ Ready for literal data\r\n");
                            SaveAppendData(&session, tag, mbox, literal_size, line_start, avail, &consumed);
                            line_start += consumed;
                        }
                    } else SendTaggedResponse(client, tag, "BAD", "Command does not support literals");
                }
                if (ast) FreeAST(ast);
            } else ProcessCommand(&session, line);
        }
        if (line_start < buffer + buf_len) {
            int rem = (buffer + buf_len) - line_start;
            memmove(buffer, line_start, rem);
            buf_len = rem;
        } else buf_len = 0;
    }
    closesocket(client);
}

static DWORD WINAPI ServerWorker(LPVOID lpParam) {
    WSADATA wsa;
    struct sockaddr_in serv = {0};
    int opt = 1;
    (void)lpParam;
    
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) goto fail;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons(g_state.port);
    g_state.listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_state.listen_socket == INVALID_SOCKET) goto fail_wsa;
    
    setsockopt(g_state.listen_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (bind(g_state.listen_socket, (struct sockaddr*)&serv, sizeof(serv)) == SOCKET_ERROR) goto fail_close;
    if (listen(g_state.listen_socket, SOMAXCONN) == SOCKET_ERROR) goto fail_close;
    
    while (g_state.running) {
        struct sockaddr_in cli;
        int csize = sizeof(cli);
        SOCKET client = accept(g_state.listen_socket, (struct sockaddr*)&cli, &csize);
        if (client != INVALID_SOCKET) {
            HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HandleClient, (LPVOID)(SIZE_T)(UINT_PTR)client, 0, NULL);
            if (th) CloseHandle(th);
        } else if (g_state.running) Sleep(100);
    }
fail_close:
    if (g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
fail_wsa:
    WSACleanup();
fail:
    g_state.running = FALSE;
    if (g_state.settings_hwnd) PostMessage(g_state.settings_hwnd, WM_PORT_UPDATE, 0, 0);
    return 0;
}

// ----------------------------------------------------------------------------
// RE-ENCRYPTION THREAD (Password Resets)
// ----------------------------------------------------------------------------
static DWORD WINAPI ReencryptThread(LPVOID lpParam) {
    ReencryptParams* params = (ReencryptParams*)lpParam;
    char path[MAX_PATH];
    char user_dir[MAX_PATH];
    char search_path[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    
    GetModuleFileNameA(NULL, path, MAX_PATH);
    PathRemoveFileSpecA(path);
    sprintf(user_dir, "%s\\%s", path, params->user);
    sprintf(search_path, "%s\\*", user_dir);
    
    hFind = FindFirstFileA(search_path, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (strcmp(fd.cFileName, ".") != 0 && strcmp(fd.cFileName, "..") != 0) {
                    char mbox_path[MAX_PATH];
                    char file_search[MAX_PATH];
                    WIN32_FIND_DATAA fd_file;
                    HANDLE hFindFile;
                    
                    sprintf(mbox_path, "%s\\%s", user_dir, fd.cFileName);
                    sprintf(file_search, "%s\\*.*", mbox_path);
                    
                    hFindFile = FindFirstFileA(file_search, &fd_file);
                    if (hFindFile != INVALID_HANDLE_VALUE) {
                        do {
                            if (!(fd_file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                char filepath[MAX_PATH];
                                char* buf;
                                sprintf(filepath, "%s\\%s", mbox_path, fd_file.cFileName);
                                
                                buf = ReadEntireFile(filepath, params->old_pass, TRUE);
                                if (buf) {
                                    FILE* out = fopen(filepath, "wb");
                                    if (out) {
                                        long size = strlen(buf);
                                        if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)buf, size, params->new_pass, 0);
                                        fwrite(buf, 1, size, out);
                                        fclose(out);
                                    }
                                    free(buf);
                                }
                            }
                        } while (FindNextFileA(hFindFile, &fd_file));
                        FindClose(hFindFile);
                    }
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
    PostMessage(g_state.settings_hwnd, WM_PROGRESS_DONE, 0, 0);
    free(params);
    return 0;
}

// ----------------------------------------------------------------------------
// GUI & SYSTEM TRAY MANAGEMENT
// ----------------------------------------------------------------------------
static void PopulateUserList(HWND listbox) {
    WCHAR keys[4096] = {0};
    WCHAR* p;
    SendMessage(listbox, LB_RESETCONTENT, 0, 0);
    if (!GetINIPath()) return;
    GetPrivateProfileStringW(L"Users", NULL, L"", keys, 4096, g_ini_path);
    p = keys;
    while (*p) { SendMessageW(listbox, LB_ADDSTRING, 0, (LPARAM)p); p += wcslen(p) + 1; }
}

static void InitSystemTray(HWND hwnd) {
    g_state.nid.cbSize = sizeof(NOTIFYICONDATAA);
    g_state.nid.hWnd = hwnd;
    g_state.nid.uID = ID_TRAY_ICON;
    g_state.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_state.nid.uCallbackMessage = WM_TRAYICON;
    g_state.nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    strcpy(g_state.nid.szTip, "IMAP Server - Click for menu");
    Shell_NotifyIconA(NIM_ADD, &g_state.nid);
}

static void RemoveSystemTray(void) {
    Shell_NotifyIconA(NIM_DELETE, &g_state.nid);
}

static void CreateSettingsWindow(HINSTANCE hinst, HWND parent) {
    char port_str[16], timeout_str[16];
    
    if (g_state.settings_hwnd) {
        ShowWindow(g_state.settings_hwnd, SW_SHOW);
        SetForegroundWindow(g_state.settings_hwnd);
        return;
    }

    g_state.settings_hwnd = CreateWindowExW(0, L"ImapdSettingsClass", L"IMAP Server Settings",
        WS_CAPTION | WS_SYSMENU | WS_POPUP, 100, 100, 300, 420, parent, NULL, hinst, NULL);
    if (!g_state.settings_hwnd) return;
    
    CreateWindowExW(0, L"STATIC", L"Port Number:", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 20, 100, 25, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_port = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL, 130, 17, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_PORT, hinst, NULL);
        
    CreateWindowExW(0, L"STATIC", L"Timeout (ms):", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 50, 100, 25, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_timeout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL, 130, 47, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_TIMEOUT, hinst, NULL);
    
    g_state.btn_startstop = CreateWindowExW(0, L"BUTTON", g_state.running ? L"Running" : L"Stopped", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 20, 85, 110, 40, g_state.settings_hwnd, (HMENU)ID_BTN_STARTSTOP, hinst, NULL);
    g_state.btn_close = CreateWindowExW(0, L"BUTTON", L"Close", WS_VISIBLE | WS_CHILD, 150, 85, 100, 40, g_state.settings_hwnd, (HMENU)ID_BTN_CLOSE, hinst, NULL);

    CreateWindowExW(0, L"STATIC", L"Users:", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 140, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.list_users = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL, WS_VISIBLE | WS_CHILD | LBS_NOTIFY | WS_VSCROLL | WS_BORDER, 20, 160, 110, 180, g_state.settings_hwnd, (HMENU)ID_LIST_USERS, hinst, NULL);
        
    CreateWindowExW(0, L"STATIC", L"Username:", WS_VISIBLE | WS_CHILD | SS_LEFT, 140, 140, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_username = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 140, 160, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_NEWUSER, hinst, NULL);
        
    CreateWindowExW(0, L"STATIC", L"Old Password:", WS_VISIBLE | WS_CHILD | SS_LEFT, 140, 190, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_oldpass = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_PASSWORD, 140, 210, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_OLDPASS, hinst, NULL);

    CreateWindowExW(0, L"STATIC", L"New Password:", WS_VISIBLE | WS_CHILD | SS_LEFT, 140, 240, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_password = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_PASSWORD, 140, 260, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_NEWPASS, hinst, NULL);
    
    g_state.chk_encrypt = CreateWindowExW(0, L"BUTTON", L"Encrypt Data", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 140, 295, 120, 20, g_state.settings_hwnd, (HMENU)ID_CHK_ENCRYPT, hinst, NULL);
    SendMessage(g_state.chk_encrypt, BM_SETCHECK, g_state.encrypt_data ? BST_CHECKED : BST_UNCHECKED, 0);

    g_state.btn_adduser = CreateWindowExW(0, L"BUTTON", L"Save / Reset", WS_VISIBLE | WS_CHILD, 140, 320, 120, 30, g_state.settings_hwnd, (HMENU)ID_BTN_ADDUSER, hinst, NULL);
    
    sprintf_s(port_str, 16, "%d", g_state.port);
    sprintf_s(timeout_str, 16, "%d", g_state.timeout_ms);
    SetWindowTextA(g_state.edit_port, port_str);
    SetWindowTextA(g_state.edit_timeout, timeout_str);
    
    PopulateUserList(g_state.list_users);
    ShowWindow(g_state.settings_hwnd, SW_SHOW);
    UpdateWindow(g_state.settings_hwnd);
}

static void CreateProgressWindow(HINSTANCE hinst, HWND parent) {
    if (!g_state.progress_hwnd) {
        g_state.progress_hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"ImapdProgressClass", L"Progress",
            WS_POPUP | WS_BORDER | WS_CAPTION, CW_USEDEFAULT, CW_USEDEFAULT, 250, 80, parent, NULL, hinst, NULL);
        g_state.prog_label = CreateWindowExW(0, L"STATIC", L"Updating files...", WS_VISIBLE | WS_CHILD | SS_CENTER,
            10, 20, 230, 20, g_state.progress_hwnd, NULL, hinst, NULL);
    }
    SetWindowTextW(g_state.prog_label, L"Updating files...");
    ShowWindow(g_state.progress_hwnd, SW_SHOW);
    UpdateWindow(g_state.progress_hwnd);
}

// ----------------------------------------------------------------------------
// WINDOW PROCEDURES
// ----------------------------------------------------------------------------
static LRESULT CALLBACK ProgressWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CTLCOLORSTATIC:
            SetBkMode((HDC)wp, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            InitCSVCache();
            g_state.green_brush = CreateSolidBrush(RGB(0, 200, 0));
            g_state.gray_brush = CreateSolidBrush(RGB(200, 200, 200));
            g_state.font_ui = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
            InitSystemTray(hwnd);
            LoadSettings();
            SetTimer(hwnd, TIMER_CSV_SYNC, g_state.csv_sync_ms, NULL);
            g_state.running = TRUE;
            g_state.worker_thread = CreateThread(NULL, 0, ServerWorker, NULL, 0, NULL);
            break;
        case WM_TRAYICON:
            if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP) {
                POINT pt; HMENU hmenu;
                GetCursorPos(&pt); SetForegroundWindow(hwnd);
                hmenu = CreatePopupMenu();
                AppendMenuA(hmenu, MF_STRING | (g_state.running ? MF_CHECKED : MF_UNCHECKED), ID_MENU_START_STOP, g_state.running ? "Stop Server" : "Start Server");
                AppendMenuA(hmenu, MF_STRING, ID_MENU_SETTINGS, "Settings");
                AppendMenuA(hmenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hmenu, MF_STRING, ID_MENU_EXIT, "Exit");
                TrackPopupMenu(hmenu, TPM_RIGHTALIGN, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hmenu);
                PostMessage(hwnd, WM_NULL, 0, 0);
            }
            break;
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case ID_MENU_START_STOP:
                    g_state.running = !g_state.running;
                    if (!g_state.running && g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
                    if (g_state.running) {
                        LoadSettings();
                        g_state.worker_thread = CreateThread(NULL, 0, ServerWorker, NULL, 0, NULL);
                    }
                    if (g_state.settings_hwnd) {
                        SetWindowTextA(g_state.btn_startstop, g_state.running ? "Running" : "Stopped");
                        InvalidateRect(g_state.btn_startstop, NULL, TRUE);
                    }
                    break;
                case ID_MENU_SETTINGS: CreateSettingsWindow(GetModuleHandle(NULL), hwnd); break;
                case ID_MENU_EXIT:
                    g_state.running = FALSE;
                    if (g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
                    if (g_state.worker_thread) WaitForSingleObject(g_state.worker_thread, 5000);
                    RemoveSystemTray(); DestroyWindow(hwnd); break;
            }
            break;
        case WM_TIMER:
            if (wp == TIMER_CSV_SYNC) FlushCSVCache(FALSE);
            break;
        case WM_DESTROY:
            FlushCSVCache(TRUE);
            DeleteCriticalSection(&g_csv_cs);
            if (g_state.green_brush) DeleteObject(g_state.green_brush);
            if (g_state.gray_brush) DeleteObject(g_state.gray_brush);
            if (g_state.font_ui) DeleteObject(g_state.font_ui);
            RemoveSystemTray(); PostQuitMessage(0); break;
        default: return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

static LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CTLCOLORLISTBOX:
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
            if ((HWND)lp == g_state.chk_encrypt || (HWND)lp == g_state.btn_adduser) {
                SetBkMode((HDC)wp, TRANSPARENT); return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
            }
            if ((HWND)lp == g_state.edit_port || (HWND)lp == g_state.edit_timeout ||
                (HWND)lp == g_state.edit_username || (HWND)lp == g_state.edit_password ||
                (HWND)lp == g_state.edit_oldpass || (HWND)lp == g_state.list_users) {
                SetBkColor((HDC)wp, RGB(255,255,255)); SetTextColor((HDC)wp, RGB(0,0,0)); return (LRESULT)GetStockObject(WHITE_BRUSH);
            }
            SetBkMode((HDC)wp, TRANSPARENT); return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
            
        case WM_COMMAND:
            if ((LOWORD(wp) == ID_EDIT_PORT || LOWORD(wp) == ID_EDIT_TIMEOUT) && HIWORD(wp) == EN_CHANGE) {
                KillTimer(hwnd, TIMER_PORT_DELAY); SetTimer(hwnd, TIMER_PORT_DELAY, 1000, NULL);
            } else if (LOWORD(wp) == ID_CHK_ENCRYPT && HIWORD(wp) == BN_CLICKED) {
                g_state.encrypt_data = (SendMessage(g_state.chk_encrypt, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SaveSettings();
            } else if (LOWORD(wp) == ID_BTN_STARTSTOP && HIWORD(wp) == BN_CLICKED) {
                SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_START_STOP, 0);
            } else if (LOWORD(wp) == ID_BTN_CLOSE && HIWORD(wp) == BN_CLICKED) { ShowWindow(hwnd, SW_HIDE);
            } else if (LOWORD(wp) == ID_BTN_ADDUSER && HIWORD(wp) == BN_CLICKED) {
                char user[256] = {0}, oldp[256] = {0}, newp[256] = {0};
                GetWindowTextA(g_state.edit_username, user, 256);
                GetWindowTextA(g_state.edit_oldpass, oldp, 256);
                GetWindowTextA(g_state.edit_password, newp, 256);
                
                if (strlen(user) > 0 && strlen(newp) > 0) {
                    WCHAR w_user[256], w_val[512];
                    char val[512], hash[128];
                    BOOL user_exists = FALSE;
                    
                    MultiByteToWideChar(CP_UTF8, 0, user, -1, w_user, 256);
                    GetPrivateProfileStringW(L"Users", w_user, L"", w_val, 512, g_ini_path);
                    
                    if (wcslen(w_val) > 0) {
                        char* colon;
                        user_exists = TRUE;
                        WideCharToMultiByte(CP_UTF8, 0, w_val, -1, val, 512, NULL, NULL);
                        colon = strchr(val, ':');
                        if (colon) {
                            char comp[128];
                            *colon = '\0';
                            ComputeSaltedHash(oldp, val, comp);
                            if (CaseInsensitiveCompare(comp, colon + 1) != 0) {
                                MessageBoxW(hwnd, L"Old password incorrect.", L"Error", MB_OK | MB_ICONWARNING);
                                return 0;
                            }
                        }
                    }
                    
                    if (user_exists) {
                        if (MessageBoxW(hwnd, L"Are you sure you want to change the password?\nThis will re-encrypt all files and may take time.", L"Confirm", MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
                        FlushCSVCache(TRUE); // Ensure memory is synced to disk before re-encryption
                        ReencryptParams* params = (ReencryptParams*)malloc(sizeof(ReencryptParams));
                        strcpy(params->user, user); strcpy(params->old_pass, oldp); strcpy(params->new_pass, newp);
                        CreateProgressWindow(GetModuleHandle(NULL), hwnd);
                        CreateThread(NULL, 0, ReencryptThread, params, 0, NULL);
                    }
                    
                    ComputeSaltedHash(newp, "salty", hash);
                    swprintf_s(w_val, 512, L"salty:%hs", hash);
                    WritePrivateProfileStringW(L"Users", w_user, w_val, g_ini_path);
                    PopulateUserList(g_state.list_users);
                    if (!user_exists) {
                        SetWindowTextA(g_state.edit_username, ""); SetWindowTextA(g_state.edit_oldpass, ""); SetWindowTextA(g_state.edit_password, "");
                        MessageBoxW(hwnd, L"New user added.", L"Success", MB_OK | MB_ICONINFORMATION);
                    }
                } else MessageBoxW(hwnd, L"Please enter username and new password.", L"Error", MB_OK | MB_ICONWARNING);
            } else if (LOWORD(wp) == ID_LIST_USERS && HIWORD(wp) == LBN_SELCHANGE) {
                int idx = (int)SendMessage(g_state.list_users, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    WCHAR w_user[256];
                    SendMessageW(g_state.list_users, LB_GETTEXT, idx, (LPARAM)w_user);
                    SetWindowTextW(g_state.edit_username, w_user);
                    SetWindowTextA(g_state.edit_oldpass, "");
                }
            }
            break;
            
        case WM_PROGRESS_DONE:
            if (g_state.progress_hwnd) {
                SetWindowTextW(g_state.prog_label, L"Done!");
                SetTimer(hwnd, TIMER_PROG_CLOSE, 2000, NULL);
            }
            SetWindowTextA(g_state.edit_username, "");
            SetWindowTextA(g_state.edit_oldpass, "");
            SetWindowTextA(g_state.edit_password, "");
            break;
            
        case WM_TIMER:
            if (wp == TIMER_PORT_DELAY) {
                char buf[16]; BOOL changed = FALSE; int np, nt;
                GetWindowTextA(g_state.edit_port, buf, sizeof(buf)); np = atoi(buf);
                if (np >= 1 && np <= 65535 && np != g_state.port) { g_state.port = np; changed = TRUE; }
                GetWindowTextA(g_state.edit_timeout, buf, sizeof(buf)); nt = atoi(buf);
                if (nt > 0 && nt != g_state.timeout_ms) { g_state.timeout_ms = nt; changed = TRUE; }
                if (changed) SaveSettings();
                KillTimer(hwnd, TIMER_PORT_DELAY);
            } else if (wp == TIMER_PROG_CLOSE) {
                KillTimer(hwnd, TIMER_PROG_CLOSE);
                if (g_state.progress_hwnd) ShowWindow(g_state.progress_hwnd, SW_HIDE);
            }
            break;
            
        case WM_DRAWITEM:
            {
                DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
                if (dis && dis->CtlID == ID_BTN_STARTSTOP) {
                    HBRUSH bg; HPEN pen; HGDIOBJ oldp, oldb, oldf; RECT trc, *rc = &dis->rcItem;
                    bg = g_state.running ? g_state.green_brush : g_state.gray_brush;
                    pen = CreatePen(PS_SOLID, 2, g_state.running ? RGB(0,150,0) : RGB(150,150,150));
                    
                    oldp = SelectObject(dis->hDC, pen);
                    oldb = SelectObject(dis->hDC, bg);
                    RoundRect(dis->hDC, rc->left, rc->top, rc->right, rc->bottom, 8, 8);
                    
                    SelectObject(dis->hDC, oldb);
                    SelectObject(dis->hDC, oldp);
                    DeleteObject(pen);
                    
                    oldf = SelectObject(dis->hDC, g_state.font_ui);
                    SetBkMode(dis->hDC, TRANSPARENT);
                    trc = *rc; InflateRect(&trc, -15, -8);
                    DrawTextA(dis->hDC, g_state.running ? "Running" : "Stopped", -1, &trc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
                    SelectObject(dis->hDC, oldf); return TRUE;
                }
            }
            break;
        case WM_CLOSE: ShowWindow(hwnd, SW_HIDE); return 0;
        case WM_DESTROY: KillTimer(hwnd, TIMER_PORT_DELAY); g_state.settings_hwnd = NULL; return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hinst, HINSTANCE hprev, LPSTR lpcmd, int nshow) {
    WNDCLASSEXW wc = {0}, wc2 = {0}, wc3 = {0};
    HWND hwnd; MSG msg;
    (void)hprev; (void)lpcmd; (void)nshow;
    
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hinst;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.lpszClassName = L"ImapdMainClass";
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassExW(&wc);
    
    wc2.cbSize = sizeof(WNDCLASSEXW);
    wc2.lpfnWndProc = SettingsWndProc;
    wc2.hInstance = hinst;
    wc2.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc2.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc2.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc2.lpszClassName = L"ImapdSettingsClass";
    RegisterClassExW(&wc2);

    wc3.cbSize = sizeof(WNDCLASSEXW);
    wc3.lpfnWndProc = ProgressWndProc;
    wc3.hInstance = hinst;
    wc3.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc3.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc3.lpszClassName = L"ImapdProgressClass";
    RegisterClassExW(&wc3);
    
    hwnd = CreateWindowExW(0, L"ImapdMainClass", L"IMAP Server", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, NULL, NULL, hinst, NULL);
    if (!hwnd) { MessageBoxW(NULL, L"Failed to create main window", L"Error", MB_OK|MB_ICONERROR); return 1; }
    
    ShowWindow(hwnd, SW_HIDE);
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return (int)msg.wParam;
}