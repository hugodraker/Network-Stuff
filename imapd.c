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
#define ID_CHK_LOGGING 1011
#define ID_CHK_HOSTSONLY 1012
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
    BOOL logging_enabled;
    BOOL hosts_only;
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
    HWND chk_logging;
    HWND chk_hostsonly;
    HWND btn_adduser;
    NOTIFYICONDATAA nid;
    HBRUSH green_brush;
    HBRUSH gray_brush;
    HFONT font_ui;
} GlobalState;

typedef struct {
    SOCKET sock;
    char user[256];
    char crypt_key[128]; // REPLACED: plain_pass
    char mailbox[256];
    char client_ip[64];
    BOOL authenticated;
    BOOL append_only;
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
    char crypt_key[128]; // REPLACED: pass
    struct CachedCSV* next;
} CachedCSV;
static GlobalState g_state = {0};
static WCHAR g_ini_path[MAX_PATH];
static CachedCSV* g_csv_cache = NULL;
static CRITICAL_SECTION g_csv_cs;

static WNDPROC OriginalListBoxProc = NULL;

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

static int CaseInsensitiveCompare(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return *a - *b;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static BOOL MatchesSequence(int id, int max_id, const char* seq) {
    char buf[512];
    char* p;
    char* token;
    
    if (!seq || CaseInsensitiveCompare(seq, "ALL") == 0) return TRUE;
    
    strncpy(buf, seq, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    
    p = buf;
    while (*p) {
        token = p;
        while (*p && *p != ',') p++;
        if (*p == ',') {
            *p = '\0';
            p++;
        }
        
        if (strcmp(token, "*") == 0) {
            if (id >= max_id) return TRUE;
        } else if (strchr(token, ':')) {
            int start = 0, end = 0;
            if (sscanf(token, "%d:%d", &start, &end) == 2) {
                if (id >= start && id <= end) return TRUE;
            } else if (sscanf(token, "%d:*", &start) == 1) {
                if (id >= start) return TRUE;
            }
        } else {
            int start = atoi(token);
            if (start > 0 && id == start) return TRUE;
        }
    }
    return FALSE;
}
static BOOL ParseCSVLine(char* line, int* seq_num, int* uid, char* flags, char* filename) {
    char* p = line; char* comma;
    if (!p || !*p) return FALSE;
    
    *seq_num = atoi(p);
    p = strchr(p, ','); if (!p) return FALSE; p++;
    
    *uid = atoi(p);
    p = strchr(p, ','); if (!p) return FALSE; p++;
    
    comma = strchr(p, ','); if (!comma) return FALSE;
    *comma = '\0';
    strncpy(flags, p, 127); flags[127] = '\0';
    *comma = ','; p = comma + 1;
    
    strncpy(filename, p, MAX_PATH - 1); filename[MAX_PATH - 1] = '\0';
    TrimString(filename);
    return TRUE;
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

static LRESULT CALLBACK ListBoxSubclassProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_KEYDOWN && wp == VK_DELETE) {
        int idx = (int)SendMessage(hwnd, LB_GETCURSEL, 0, 0);
        if (idx != LB_ERR) {
            WCHAR w_user[256];
            SendMessageW(hwnd, LB_GETTEXT, idx, (LPARAM)w_user);
            
            if (MessageBoxW(GetParent(hwnd), L"Are you sure you want to delete this user and all their files?", L"Confirm Delete", MB_YESNO | MB_ICONWARNING) == IDYES) {
                char user_utf8[256];
                char path[MAX_PATH], user_dir[MAX_PATH], safe_user[256];
                char doubleNullPath[MAX_PATH + 2] = {0};
                SHFILEOPSTRUCTA shfo = {0};
                
                WideCharToMultiByte(CP_UTF8, 0, w_user, -1, user_utf8, 256, NULL, NULL);
                WritePrivateProfileStringW(L"Users", w_user, NULL, g_ini_path);
                
                GetModuleFileNameA(NULL, path, MAX_PATH);
                PathRemoveFileSpecA(path);
                
                strncpy(safe_user, user_utf8, 255);
                SanitizePath(safe_user);
                sprintf(user_dir, "%s\\%s", path, safe_user);
                
                strcpy(doubleNullPath, user_dir);
                shfo.hwnd = GetParent(hwnd);
                shfo.wFunc = FO_DELETE;
                shfo.pFrom = doubleNullPath;
                shfo.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION | FOF_SILENT;
                SHFileOperationA(&shfo);
                
                SendMessage(hwnd, LB_DELETESTRING, idx, 0);
                SetWindowTextW(g_state.edit_username, L"");
                SetWindowTextW(g_state.edit_oldpass, L"");
                SetWindowTextW(g_state.edit_password, L"");
            }
        }
        return 0; // Prevent further processing
    }
    return CallWindowProc(OriginalListBoxProc, hwnd, msg, wp, lp);
}
// ----------------------------------------------------------------------------
// LOGGING UTILITIES
// ----------------------------------------------------------------------------
static void ServerLog(const char* fmt, ...) {
    if (!g_state.logging_enabled) return;
    {
        char log_path[MAX_PATH];
        FILE* f;
        va_list args;
        time_t now;
        struct tm* timeinfo;
        char timestamp[64];
        
        GetModuleFileNameA(NULL, log_path, MAX_PATH);
        PathRemoveFileSpecA(log_path);
        strcat_s(log_path, MAX_PATH, "\\imapd.log");
        
        f = fopen(log_path, "a");
        if (!f) return;
        
        time(&now);
        timeinfo = localtime(&now);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);
        
        fprintf(f, "[%s] ", timestamp);
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
}

static void LogSent(SOCKET sock, const char* fmt, ...) {
    char buf[1024];
    va_list args;
    size_t len;
    
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    len = strlen(buf);
    while(len > 0 && (buf[len-1] == '\r' || buf[len-1] == '\n')) {
        buf[len-1] = '\0';
        len--;
    }
    ServerLog("[Socket %u] S: %s", (unsigned int)(UINT_PTR)sock, buf);
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

static void FastXorCipherChunk(BYTE* data, size_t len, const char* crypt_key, size_t offset) {
    size_t key_len;
    size_t i;
    if (!crypt_key || !crypt_key[0]) return;
    key_len = strlen(crypt_key);
    for(i = 0; i < len; i++) data[i] ^= crypt_key[(offset + i) % key_len];
}
static char* ReadEntireFile(const char* path, const char* crypt_key, BOOL encrypted) {
    FILE* f = fopen(path, "rb");
    long size;
    char* buf;
    if (!f) {
        ServerLog("Failed to read file: %s", path);
        return NULL;
    }
    ServerLog("Reading file: %s (Encrypted: %d)", path, encrypted);
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = (char*)malloc(size + 1);
    fread(buf, 1, size, f);
    fclose(f);
    if (encrypted && crypt_key) FastXorCipherChunk((BYTE*)buf, size, crypt_key, 0);
    buf[size] = '\0';
    return buf;
}
// ----------------------------------------------------------------------------
// IN-MEMORY CSV CACHE MANAGER (Thread-Safe)
// ----------------------------------------------------------------------------
static void InitCSVCache(void) {
    InitializeCriticalSection(&g_csv_cs);
    ServerLog("CSV Memory Cache Initialized");
}

static void FlushCSVCache(BOOL free_memory) {
    CachedCSV* curr;
    ServerLog("Flushing CSV Cache to disk... (free_memory=%d)", free_memory);
    EnterCriticalSection(&g_csv_cs);
    curr = g_csv_cache;
    while (curr) {
        if (curr->dirty) {
            FILE* f = fopen(curr->path, "wb");
            if (f) {
                if (g_state.encrypt_data) {
                    char* enc = (char*)malloc(curr->len);
                    memcpy(enc, curr->data, curr->len);
                    FastXorCipherChunk((BYTE*)enc, curr->len, curr->crypt_key, 0);
                    fwrite(enc, 1, curr->len, f);
                    free(enc);
                } else {
                    fwrite(curr->data, 1, curr->len, f);
                }
                fclose(f);
                ServerLog("Flushed to disk: %s", curr->path);
            } else {
                ServerLog("Error: Could not flush to disk: %s", curr->path);
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

static char* ReadCSVCached(const char* path, const char* crypt_key, BOOL encrypted) {
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
        ServerLog("Cache miss for CSV. Loading from disk: %s", path);
        if (f) {
            fseek(f, 0, SEEK_END);
            size = ftell(f);
            fseek(f, 0, SEEK_SET);
            buf = (char*)malloc(size + 1);
            fread(buf, 1, size, f);
            fclose(f);
            if (encrypted && crypt_key) FastXorCipherChunk((BYTE*)buf, size, crypt_key, 0);
            buf[size] = '\0';
        } else {
            ServerLog("File not found on disk, creating new cache entry: %s", path);
        }
        
        curr = (CachedCSV*)calloc(1, sizeof(CachedCSV));
        strcpy(curr->path, path);
        if (crypt_key) strcpy(curr->crypt_key, crypt_key);
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

static void AppendCSVCached(const char* path, const char* crypt_key, BOOL encrypted, const char* line) {
    CachedCSV* curr;
    char* temp;
    
    ServerLog("Appending to CSV cache: %s (Dirty Flag Set)", path);
    EnterCriticalSection(&g_csv_cs);
    temp = ReadCSVCached(path, crypt_key, encrypted);
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

static void SaveSettings(void) {
    if (GetINIPath()) {
        wchar_t val_str[32];
        swprintf_s(val_str, 32, L"%d", g_state.port);
        WritePrivateProfileStringW(L"Server", L"Port", val_str, g_ini_path);
        swprintf_s(val_str, 32, L"%d", g_state.timeout_ms);
        WritePrivateProfileStringW(L"Server", L"Timeout", val_str, g_ini_path);
        swprintf_s(val_str, 32, L"%d", g_state.encrypt_data);
        WritePrivateProfileStringW(L"Server", L"EncryptData", val_str, g_ini_path);
        swprintf_s(val_str, 32, L"%d", g_state.logging_enabled);
        WritePrivateProfileStringW(L"Server", L"Logging", val_str, g_ini_path);
        swprintf_s(val_str, 32, L"%d", g_state.hosts_only);
        WritePrivateProfileStringW(L"Server", L"HostsOnly", val_str, g_ini_path);
        ServerLog("Settings successfully saved to INI file.");
    }
}

static void LoadSettings(void) {
    g_state.port = 143;
    g_state.timeout_ms = 1800000;
    g_state.csv_sync_ms = 1200000; // 20 mins default
    g_state.encrypt_data = TRUE;
    g_state.logging_enabled = TRUE;
    g_state.hosts_only = TRUE;
    
    if (GetINIPath()) {
        WCHAR check_user[256];
        int sync_mins;
        BOOL ini_exists = PathFileExistsW(g_ini_path);
        
        if (!ini_exists) {
            SaveSettings();
        }
        
        g_state.port = GetPrivateProfileIntW(L"Server", L"Port", 143, g_ini_path);
        if (g_state.port < 1 || g_state.port > 65535) g_state.port = 143;
        
        g_state.timeout_ms = GetPrivateProfileIntW(L"Server", L"Timeout", 1800000, g_ini_path);
        if (g_state.timeout_ms <= 0) g_state.timeout_ms = 1800000;
        
        sync_mins = GetPrivateProfileIntW(L"Server", L"CsvSyncMins", 20, g_ini_path);
        if (sync_mins < 1) sync_mins = 1;
        g_state.csv_sync_ms = sync_mins * 60000;
        
        g_state.encrypt_data = GetPrivateProfileIntW(L"Server", L"EncryptData", 1, g_ini_path);
        g_state.logging_enabled = GetPrivateProfileIntW(L"Server", L"Logging", 1, g_ini_path);
        g_state.hosts_only = GetPrivateProfileIntW(L"Server", L"HostsOnly", 1, g_ini_path);
        
        GetPrivateProfileStringW(L"Users", L"admin", L"", check_user, 256, g_ini_path);
        if (wcslen(check_user) == 0) {
            char hash[128];
            WCHAR w_val[256];
            ComputeSaltedHash("password", "salty", hash);
            swprintf_s(w_val, 256, L"salty:%hs", hash);
            WritePrivateProfileStringW(L"Users", L"admin", w_val, g_ini_path);
        }
        ServerLog("Settings loaded. Port: %d, Timeout: %dms, Encrypt: %d, Logging: %d, HostsOnly: %d", 
                  g_state.port, g_state.timeout_ms, g_state.encrypt_data, g_state.logging_enabled, g_state.hosts_only);
    }
}
static BOOL IsHostAllowed(const char* client_ip) {
    WCHAR smtpd_ini[MAX_PATH];
    WCHAR keys[4096] = {0};
    WCHAR* p;
    
    if (GetModuleFileNameW(NULL, smtpd_ini, MAX_PATH) > 0) {
        PathRemoveFileSpecW(smtpd_ini);
        wcscat_s(smtpd_ini, MAX_PATH, L"\\smtpd.ini");
    } else {
        return FALSE;
    }
    
    if (!PathFileExistsW(smtpd_ini)) {
        return FALSE;
    }
    
    GetPrivateProfileStringW(L"Hosts", NULL, L"", keys, 4096, smtpd_ini);
    p = keys;
    while (*p) {
        WCHAR w_val[1024];
        char val[1024];
        GetPrivateProfileStringW(L"Hosts", p, L"", w_val, 1024, smtpd_ini);
        WideCharToMultiByte(CP_UTF8, 0, w_val, -1, val, 1024, NULL, NULL);
        
        char* tokens[20] = {0};
        int t_count = 0;
        char* cur = val;
        
        tokens[t_count++] = cur;
        while (*cur && t_count < 20) {
            if (*cur == '|') {
                *cur = '\0';
                tokens[t_count++] = cur + 1;
            }
            cur++;
        }
        
        if (t_count >= 3) {
            TrimString(tokens[2]);
            if (t_count >= 4) TrimString(tokens[3]);
            
            if (strcmp(tokens[2], client_ip) == 0 || (t_count >= 4 && strcmp(tokens[3], client_ip) == 0)) {
                return TRUE;
            }
        }
        p += wcslen(p) + 1;
    }
    return FALSE;
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
    
    ServerLog("Initialized mailbox directories for user '%s', folder '%s'", safe_user, clean_mbox);
}

static int GetMessageCount(const char* user, const char* mbox, const char* crypt_key) {
    char csv_path[MAX_PATH];
    char* csv_data;
    int count = 0;
    
    InitUserMailbox(user, mbox, NULL, csv_path);
    csv_data = ReadCSVCached(csv_path, crypt_key, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) count++;
            if (nl) *nl = '\n'; 
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
    send(sock, data, (int)strlen(data), 0);
}
static void SendResponse(SOCKET sock, const char* response) {
    LogSent(sock, "%s", response);
    SendSocketData(sock, response);
    SendSocketData(sock, "\r\n");
}
static void SendTaggedResponse(SOCKET sock, const char* tag, const char* code, const char* message) {
    char response[512];
    LogSent(sock, "%s %s %s", tag, code, message);
    snprintf(response, sizeof(response), "%s %s %s\r\n", tag, code, message);
    SendSocketData(sock, response);
}

static void CmdStore(ClientSession* session, const char* tag, ASTNode* args, BOOL is_uid) {
    char csv_path[MAX_PATH];
    const char* sequence_set;
    ASTNode* op_node;
    char* csv_data;
    int max_id = 0;
    BOOL silent = FALSE, add = TRUE;
    BOOL set_deleted = FALSE, set_seen = FALSE, remove_deleted = FALSE, remove_seen = FALSE;
    
    if (!args || !args->next) { SendTaggedResponse(session->sock, tag, "BAD", "Missing args"); return; }
    sequence_set = args->value;
    op_node = args->next;
    
    char op_upper[64];
    strncpy(op_upper, op_node->value, 63); op_upper[63] = '\0';
    for(int i = 0; op_upper[i]; i++) op_upper[i] = (char)toupper((unsigned char)op_upper[i]);
    
    if (strstr(op_upper, "SILENT")) silent = TRUE;
    if (op_upper[0] == '-') add = FALSE;
    
    ASTNode* flag_node = op_node->next;
    while (flag_node) {
        char f_up[128];
        strncpy(f_up, flag_node->value, 127); f_up[127] = '\0';
        for(int i = 0; f_up[i]; i++) f_up[i] = (char)toupper((unsigned char)f_up[i]);
        
        if (strstr(f_up, "DELETED")) { if (add) set_deleted = TRUE; else remove_deleted = TRUE; }
        if (strstr(f_up, "SEEN")) { if (add) set_seen = TRUE; else remove_seen = TRUE; }
        flag_node = flag_node->next;
    }
    
    InitUserMailbox(session->user, session->mailbox, NULL, csv_path);
    csv_data = ReadCSVCached(csv_path, session->crypt_key, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) { 
            char* nl = strchr(p, '\n'); 
            if (nl) *nl = '\0'; 
            if (strlen(p) > 2) max_id++; 
            if (nl) *nl = '\n'; 
            if (!nl) break; 
            p = nl + 1; 
        }
        
        char* new_csv = (char*)malloc(max_id * 512 + 1);
        new_csv[0] = '\0';
        
        p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                int seq_num, uid;
                char flags[256], filename[MAX_PATH];
                if (ParseCSVLine(p, &seq_num, &uid, flags, filename)) {
                    if (MatchesSequence(is_uid ? uid : seq_num, max_id, sequence_set)) {
                        if (set_deleted && !strstr(flags, "\\Deleted")) strcat(flags, " \\Deleted");
                        if (remove_deleted) { char* pos = strstr(flags, "\\Deleted"); if (pos) memmove(pos, pos + 8, strlen(pos + 8) + 1); }
                        
                        if (set_seen && !strstr(flags, "\\Seen")) strcat(flags, " \\Seen");
                        if (remove_seen) { char* pos = strstr(flags, "\\Seen"); if (pos) memmove(pos, pos + 5, strlen(pos + 5) + 1); }
                        
                        TrimString(flags);
                        
                        if (!silent) {
                            char resp[512];
                            sprintf(resp, "* %d FETCH (UID %d FLAGS (%s))", seq_num, uid, flags);
                            SendResponse(session->sock, resp);
                        }
                    }
                    char line[512];
                    sprintf(line, "%d,%d,%s,%s\n", seq_num, uid, flags, filename);
                    strcat(new_csv, line);
                }
            }
            if (nl) *nl = '\n'; 
            if (!nl) break;
            p = nl + 1;
        }
        
        EnterCriticalSection(&g_csv_cs);
        CachedCSV* curr = g_csv_cache;
        while (curr) {
            if (CaseInsensitiveCompare(curr->path, csv_path) == 0) {
                free(curr->data);
                curr->len = strlen(new_csv);
                curr->cap = curr->len + 256;
                curr->data = new_csv; 
                curr->dirty = TRUE;
                break;
            }
            curr = curr->next;
        }
        LeaveCriticalSection(&g_csv_cs);
        if (!curr) free(new_csv);
        free(csv_data);
    }
    FlushCSVCache(FALSE);
    SendTaggedResponse(session->sock, tag, "OK", "STORE completed");
}

static void CmdCapability(ClientSession* session, const char* tag) {
    SendResponse(session->sock, "* CAPABILITY IMAP4rev1");
    SendTaggedResponse(session->sock, tag, "OK", "CAPABILITY completed");
}

static BOOL CheckSmtpdAuth(const char* client_ip, const char* username, const char* password) {
    WCHAR smtpd_ini[MAX_PATH];
    WCHAR keys[4096] = {0};
    WCHAR* p;
    
    if (GetModuleFileNameW(NULL, smtpd_ini, MAX_PATH) > 0) {
        PathRemoveFileSpecW(smtpd_ini);
        wcscat_s(smtpd_ini, MAX_PATH, L"\\smtpd.ini");
    } else {
        return FALSE;
    }
    
    if (!PathFileExistsW(smtpd_ini)) {
        return FALSE;
    }
    
    GetPrivateProfileStringW(L"Hosts", NULL, L"", keys, 4096, smtpd_ini);
    p = keys;
    while (*p) {
        WCHAR w_val[1024];
        char val[1024];
        GetPrivateProfileStringW(L"Hosts", p, L"", w_val, 1024, smtpd_ini);
        WideCharToMultiByte(CP_UTF8, 0, w_val, -1, val, 1024, NULL, NULL);
        
        char* tokens[20] = {0};
        int t_count = 0;
        char* cur = val;
        
        tokens[t_count++] = cur;
        while (*cur && t_count < 20) {
            if (*cur == '|') {
                *cur = '\0';
                tokens[t_count++] = cur + 1;
            }
            cur++;
        }
        
        if (t_count >= 12) {
            TrimString(tokens[2]);
            TrimString(tokens[3]);
            TrimString(tokens[11]);
            
            // Master password bypass: Ignore tokens[10] (username) so the proxy can impersonate the recipient
            if ((strcmp(tokens[2], client_ip) == 0 || strcmp(tokens[3], client_ip) == 0) &&
                strcmp(tokens[11], password) == 0) {
                return TRUE;
            }
        }
        
        p += wcslen(p) + 1;
    }
    return FALSE;
}
static void CmdLogin(ClientSession* session, const char* tag, ASTNode* args) {
    char user[256];
    const char* pass;
    char* at_sign;
    char real_user_hash[128] = {0};
    char salt[128] = "salty";
    BOOL valid_user = FALSE;
    BOOL valid_pass = FALSE;

    if (!args || !args->next) { SendTaggedResponse(session->sock, tag, "BAD", "Missing args"); return; }
    
    strncpy(user, args->value, sizeof(user) - 1);
    user[sizeof(user) - 1] = '\0';
    
    at_sign = strchr(user, '@');
    if (at_sign) {
        *at_sign = '\0';
    }

    pass = args->next->value;
    
    ServerLog("[Socket %u] Attempting login for user '%s' from IP %s", (unsigned int)(UINT_PTR)session->sock, user, session->client_ip);
    
    // Extract the user's real hash from imapd.ini so we can encrypt files properly
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
                valid_user = TRUE;
                *colon = '\0';
                strncpy(salt, val, 127);
                strncpy(real_user_hash, colon + 1, 127);
                
                char computed_hash[128];
                ComputeSaltedHash(pass, salt, computed_hash);
                if (CaseInsensitiveCompare(computed_hash, real_user_hash) == 0) {
                    valid_pass = TRUE;
                }
            }
        }
    }

    if (CheckSmtpdAuth(session->client_ip, user, pass)) {
        if (!valid_user) {
            ServerLog("[Socket %u] Append-Only login failed: target user '%s' does not exist in imapd.ini", (unsigned int)(UINT_PTR)session->sock, user);
            SendTaggedResponse(session->sock, tag, "NO", "Recipient mailbox does not exist");
            return;
        }
        session->authenticated = TRUE;
        session->append_only = TRUE;
        strncpy(session->user, user, 255);
        strncpy(session->crypt_key, real_user_hash, 127); // Binds the recipient's encryption key
        InitUserMailbox(session->user, "INBOX", NULL, NULL);
        ServerLog("[Socket %u] Login success (SMTP Append-Only): user '%s'", (unsigned int)(UINT_PTR)session->sock, user);
        SendTaggedResponse(session->sock, tag, "OK", "LOGIN completed");
        return;
    }

    if (valid_pass) {
        session->authenticated = TRUE;
        session->append_only = FALSE;
        strncpy(session->user, user, 255);
        strncpy(session->crypt_key, real_user_hash, 127); // Binds the recipient's encryption key
        InitUserMailbox(session->user, "INBOX", NULL, NULL);
        ServerLog("[Socket %u] Login success: user '%s'", (unsigned int)(UINT_PTR)session->sock, user);
        SendTaggedResponse(session->sock, tag, "OK", "LOGIN completed");
        return;
    }

    ServerLog("[Socket %u] Login failed: user '%s'", (unsigned int)(UINT_PTR)session->sock, user);
    SendTaggedResponse(session->sock, tag, "NO", "Invalid credentials");
}
static void CmdCreate(ClientSession* session, const char* tag, ASTNode* args) {
    if (!args) { SendTaggedResponse(session->sock, tag, "BAD", "Missing folder name"); return; }
    ServerLog("[Socket %u] Creating mailbox '%s'", (unsigned int)(UINT_PTR)session->sock, args->value);
    InitUserMailbox(session->user, args->value, NULL, NULL);
    SendTaggedResponse(session->sock, tag, "OK", "CREATE completed");
}

static void CmdSelect(ClientSession* session, const char* tag, ASTNode* args) {
    int count;
    char response[256];
    if (!args) { SendTaggedResponse(session->sock, tag, "BAD", "Missing mailbox"); return; }
    
    strncpy(session->mailbox, args->value, 255);
    InitUserMailbox(session->user, session->mailbox, NULL, NULL);
    count = GetMessageCount(session->user, session->mailbox, session->crypt_key);
    
    ServerLog("[Socket %u] Selected mailbox '%s', %d messages present", (unsigned int)(UINT_PTR)session->sock, session->mailbox, count);
    
    sprintf(response, "* %d EXISTS", count); SendResponse(session->sock, response);
    sprintf(response, "* %d RECENT", count); SendResponse(session->sock, response);
    SendResponse(session->sock, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
    SendResponse(session->sock, "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.");
    SendResponse(session->sock, "* OK [UIDVALIDITY 1] UIDs valid");
    SendResponse(session->sock, "* OK [UIDNEXT 1000] Predicted next UID");
    SendTaggedResponse(session->sock, tag, "OK", "SELECT completed");
}

static void CmdLsub(ClientSession* session, const char* tag) {
    ServerLog("[Socket %u] Listing subscribed mailboxes", (unsigned int)(UINT_PTR)session->sock);
    SendResponse(session->sock, "* LSUB (\\HasNoChildren) \".\" \"INBOX\"");
    SendResponse(session->sock, "* LSUB (\\HasNoChildren \\Drafts) \".\" \"Drafts\"");
    SendResponse(session->sock, "* LSUB (\\HasNoChildren \\Sent) \".\" \"Sent\"");
    SendResponse(session->sock, "* LSUB (\\HasNoChildren \\Trash) \".\" \"Trash\"");
    SendTaggedResponse(session->sock, tag, "OK", "LSUB completed");
}
static void CmdList(ClientSession* session, const char* tag) {
    ServerLog("[Socket %u] Listing mailboxes", (unsigned int)(UINT_PTR)session->sock);
    SendResponse(session->sock, "* LIST (\\HasNoChildren) \".\" \"INBOX\"");
    SendResponse(session->sock, "* LIST (\\HasNoChildren \\Drafts) \".\" \"Drafts\"");
    SendResponse(session->sock, "* LIST (\\HasNoChildren \\Sent) \".\" \"Sent\"");
    SendResponse(session->sock, "* LIST (\\HasNoChildren \\Trash) \".\" \"Trash\"");
    SendTaggedResponse(session->sock, tag, "OK", "LIST completed");
}

static void CmdStatus(ClientSession* session, const char* tag, ASTNode* args) {
    int count;
    char response[1024];
    char status_items[512] = "";
    const char* mbox = (args && args->value) ? args->value : "INBOX";
    ASTNode* curr;
    
    count = GetMessageCount(session->user, mbox, session->crypt_key);
    ServerLog("[Socket %u] Reporting status for mailbox '%s', count %d", (unsigned int)(UINT_PTR)session->sock, mbox, count);
    
    curr = args ? args->next : NULL;
    while (curr) {
        char upper_val[128];
        int i = 0;
        while (curr->value[i] && i < 127) { upper_val[i] = toupper(curr->value[i]); i++; }
        upper_val[i] = '\0';
        
        if (strstr(upper_val, "MESSAGES")) { char buf[32]; sprintf(buf, "MESSAGES %d ", count); strcat(status_items, buf); }
        if (strstr(upper_val, "RECENT")) { char buf[32]; sprintf(buf, "RECENT %d ", count); strcat(status_items, buf); }
        if (strstr(upper_val, "UIDNEXT")) { strcat(status_items, "UIDNEXT 1000 "); }
        if (strstr(upper_val, "UIDVALIDITY")) { strcat(status_items, "UIDVALIDITY 1 "); }
        if (strstr(upper_val, "UNSEEN")) { strcat(status_items, "UNSEEN 0 "); }
        curr = curr->next;
    }
    
    if (strlen(status_items) > 0 && status_items[strlen(status_items)-1] == ' ') status_items[strlen(status_items)-1] = '\0';
    if (strlen(status_items) == 0) sprintf(status_items, "MESSAGES %d RECENT %d UIDNEXT 1000 UIDVALIDITY 1 UNSEEN 0", count, count);
    
    sprintf(response, "* STATUS \"%s\" (%s)", mbox, status_items);
    SendResponse(session->sock, response);
    SendTaggedResponse(session->sock, tag, "OK", "STATUS completed");
}

static void CmdNoop(ClientSession* session, const char* tag) {
    if (session->mailbox[0] != '\0') {
        int count = GetMessageCount(session->user, session->mailbox, session->crypt_key);
        char response[256];
        
        sprintf(response, "* %d EXISTS", count);
        SendResponse(session->sock, response);
        
        sprintf(response, "* %d RECENT", count);
        SendResponse(session->sock, response);
    }
    
    SendTaggedResponse(session->sock, tag, "OK", "NOOP completed");
}
static void CmdLogout(ClientSession* session, const char* tag) {
    ServerLog("[Socket %u] Client requested logout", (unsigned int)(UINT_PTR)session->sock);
    SendResponse(session->sock, "* BYE Logging out");
    SendTaggedResponse(session->sock, tag, "OK", "LOGOUT completed");
}

static void FetchMessage(ClientSession* session, int seq_num, int uid, const char* flags, const char* filename, ASTNode* fetch_args) {
    char mbox_dir[MAX_PATH], eml_path[MAX_PATH], response_head[2048] = {0}, attr_buf[1024] = {0}, req_body_attr[1024] = "BODY[]";
    FILE* f;
    int file_size = 0;
    BOOL need_body = FALSE, need_size = FALSE, need_headers_only = FALSE;
    ASTNode* curr = fetch_args;
    
    ServerLog("[Socket %u] Fetching message Sequence %d (UID %d) from '%s'", (unsigned int)(UINT_PTR)session->sock, seq_num, uid, filename);
    
    InitUserMailbox(session->user, session->mailbox, mbox_dir, NULL);
    sprintf(eml_path, "%s\\%s", mbox_dir, filename);
    
    f = fopen(eml_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        file_size = (int)ftell(f);
        fseek(f, 0, SEEK_SET);
    } else {
        ServerLog("Warning: Could not open file for FETCH: %s", eml_path);
    }
    
    while(curr) {
        char upper_val[128];
        int i = 0;
        while (curr->value[i] && i < 127) { upper_val[i] = toupper(curr->value[i]); i++; }
        upper_val[i] = '\0';

        if (strstr(upper_val, "RFC822.SIZE")) {
            need_size = TRUE;
        } else if (strstr(upper_val, "BODY") || strstr(upper_val, "RFC822")) {
            need_body = TRUE;
            if (strstr(upper_val, "HEADER")) need_headers_only = TRUE;
            
            if (CaseInsensitiveCompare(curr->value, "RFC822") == 0) {
                strcpy(req_body_attr, "RFC822");
            } else if (strncmp(upper_val, "BODY", 4) == 0) {
                char* peek;
                char* right_bracket;
                ASTNode* p;
                
                strncpy(req_body_attr, curr->value, sizeof(req_body_attr) - 1);
                req_body_attr[sizeof(req_body_attr) - 1] = '\0';
                
                p = curr->next;
                if (strchr(req_body_attr, '[')) {
                    while (p && !strchr(req_body_attr, ']')) {
                        char upper_p[128];
                        int j = 0;
                        while (p->value[j] && j < 127) { upper_p[j] = toupper(p->value[j]); j++; }
                        upper_p[j] = '\0';
                        if (strstr(upper_p, "HEADER")) need_headers_only = TRUE;
                        
                        if (strlen(req_body_attr) + strlen(p->value) + 2 < sizeof(req_body_attr)) {
                            strcat(req_body_attr, " ");
                            strcat(req_body_attr, p->value);
                        }
                        p = p->next;
                    }
                }
                
                peek = strstr(req_body_attr, ".PEEK");
                if (peek) memmove(peek, peek + 5, strlen(peek + 5) + 1);
                
                right_bracket = strrchr(req_body_attr, ']');
                if (right_bracket) {
                    *(right_bracket + 1) = '\0';
                }
            }
        }
        curr = curr->next;
    }
    
    sprintf(response_head, "* %d FETCH (UID %d FLAGS (%s)", seq_num, uid, flags);
    if (need_size) {
        sprintf(attr_buf, " RFC822.SIZE %d", file_size);
        strcat(response_head, attr_buf);
    }
    
    if (need_body) {
        if (f) {
            char* file_buf = (char*)malloc(file_size + 1);
            int literal_size = file_size;
            
            if (file_buf) {
                fread(file_buf, 1, file_size, f);
                file_buf[file_size] = '\0';
                if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)file_buf, file_size, session->crypt_key, 0);

                if (need_headers_only) {
                    char* body_start = strstr(file_buf, "\r\n\r\n");
                    if (!body_start) body_start = strstr(file_buf, "\n\n");
                    if (body_start) {
                        literal_size = (int)(body_start - file_buf) + (body_start[0] == '\r' ? 4 : 2);
                    }
                }
                
                sprintf(attr_buf, " %s {%d}\r\n", req_body_attr, literal_size);
                strcat(response_head, attr_buf);
                LogSent(session->sock, "%s", response_head);
                SendSocketData(session->sock, response_head);
                
                send(session->sock, file_buf, literal_size, 0);
                SendResponse(session->sock, ")");
                free(file_buf);
            }
        } else {
            sprintf(attr_buf, " %s {0}\r\n", req_body_attr);
            strcat(response_head, attr_buf);
            LogSent(session->sock, "%s", response_head);
            SendSocketData(session->sock, response_head);
            SendResponse(session->sock, ")");
        }
    } else {
        strcat(response_head, ")");
        SendResponse(session->sock, response_head);
    }
    if (f) fclose(f);
}

static void CmdSearch(ClientSession* session, const char* tag, ASTNode* args, BOOL is_uid) {
    char csv_path[MAX_PATH], mbox_dir[MAX_PATH];
    char search_result[4096] = "* SEARCH";
    char* csv_data;
    BOOL filter_undeleted = FALSE;
    char target_msg_id[256] = {0};
    char target_text[256] = {0};
    
    ASTNode* arg = args;
    while(arg) {
        char upper_val[128];
        int i = 0;
        while (arg->value[i] && i < 127) { upper_val[i] = (char)toupper((unsigned char)arg->value[i]); i++; }
        upper_val[i] = '\0';
        
        if (strstr(upper_val, "UNDELETED")) {
            filter_undeleted = TRUE;
        }
        else if (strstr(upper_val, "HEADER") && arg->next && arg->next->next) {
            char header_name[128];
            i = 0;
            while (arg->next->value[i] && i < 127) { header_name[i] = (char)toupper((unsigned char)arg->next->value[i]); i++; }
            header_name[i] = '\0';
            if (strstr(header_name, "MESSAGE-ID")) {
                strncpy(target_msg_id, arg->next->next->value, 255);
                target_msg_id[255] = '\0';
            }
            arg = arg->next->next;
        }
        else if ((strstr(upper_val, "TEXT") || strstr(upper_val, "BODY") || strstr(upper_val, "SUBJECT") || strstr(upper_val, "FROM") || strstr(upper_val, "TO")) && arg->next) {
            strncpy(target_text, arg->next->value, 255);
            target_text[255] = '\0';
            arg = arg->next;
        }
        else if (arg->type == NODE_STRING || arg->type == NODE_ATOM) {
            if (target_text[0] == '\0' && strcmp(upper_val, "ALL") != 0 && strcmp(upper_val, "SEARCH") != 0) {
                strncpy(target_text, arg->value, 255);
                target_text[255] = '\0';
            }
        }
        arg = arg->next;
    }
    
    InitUserMailbox(session->user, session->mailbox, mbox_dir, csv_path);
    FlushCSVCache(FALSE);
    csv_data = ReadCSVCached(csv_path, session->crypt_key, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                int seq_num, uid;
                char flags[256], filename[MAX_PATH];
                if (ParseCSVLine(p, &seq_num, &uid, flags, filename)) {
                    if (!filter_undeleted || !strstr(flags, "\\Deleted")) {
                        BOOL match = TRUE;
                        
                        if (target_msg_id[0] != '\0' || target_text[0] != '\0') {
                            char filepath[MAX_PATH];
                            sprintf(filepath, "%s\\%s", mbox_dir, filename);
                            
                            char* file_content = ReadEntireFile(filepath, session->crypt_key, g_state.encrypt_data);
                            if (file_content) {
                                if (target_msg_id[0] != '\0' && !StrStrIA(file_content, target_msg_id)) {
                                    match = FALSE;
                                }
                                if (target_text[0] != '\0' && !StrStrIA(file_content, target_text)) {
                                    match = FALSE;
                                }
                                free(file_content);
                            } else {
                                match = FALSE;
                            }
                        }
                        
                        if (match) {
                            char id_str[32];
                            sprintf(id_str, " %d", is_uid ? uid : seq_num);
                            if (strlen(search_result) + strlen(id_str) < sizeof(search_result) - 2) {
                                strcat(search_result, id_str);
                            }
                        }
                    }
                }
            }
            if (nl) *nl = '\n'; 
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
    
    ServerLog("[Socket %u] Executing FETCH for sequence '%s' (is_uid=%d)", (unsigned int)(UINT_PTR)session->sock, sequence_set, is_uid);
    
    InitUserMailbox(session->user, session->mailbox, NULL, csv_path);
    csv_data = ReadCSVCached(csv_path, session->crypt_key, g_state.encrypt_data);
    
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) max_id++;
            if (nl) *nl = '\n'; 
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
                if (ParseCSVLine(p, &seq_num, &uid, flags, filename)) {
                    int compare_id = is_uid ? uid : seq_num;
                    if (MatchesSequence(compare_id, max_id, sequence_set)) {
                        FetchMessage(session, seq_num, uid, flags, filename, fetch_items);
                    }
                }
            }
            if (nl) *nl = '\n'; 
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

static void SaveAppendData(ClientSession* session, const char* tag, const char* mbox, const char* flags, int literal_size, char* buffer_ptr, int buffer_avail, int* consumed) {
    char mbox_dir[MAX_PATH], csv_path[MAX_PATH], eml_path[MAX_PATH];
    int next_id = 1;
    int next_seq = 1;
    char* csv_data;
    FILE* feml;
    int remaining, chunk;
    size_t file_offset = 0;
    
    InitUserMailbox(session->user, mbox, mbox_dir, csv_path);
    csv_data = ReadCSVCached(csv_path, session->crypt_key, g_state.encrypt_data);
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                next_seq++; 
                int seq_num, uid;
                if (sscanf(p, "%d,%d,", &seq_num, &uid) == 2) {
                    if (uid >= next_id) next_id = uid + 1;
                }
            }
            if (nl) *nl = '\n';
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
        if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)buffer_ptr, chunk, session->crypt_key, file_offset);
        fwrite(buffer_ptr, 1, chunk, feml);
        remaining -= chunk;
        file_offset += chunk;
        *consumed = chunk;
    } else *consumed = 0;
    
    {
        char tmp[2048];
        while (remaining > 0) {
            int to_read = remaining > (int)sizeof(tmp) ? (int)sizeof(tmp) : remaining;
            int r = recv(session->sock, tmp, to_read, 0);
            if (r <= 0) break;
            if (feml) {
                if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)tmp, r, session->crypt_key, file_offset);
                fwrite(tmp, 1, r, feml);
                file_offset += r;
            }
            remaining -= r;
        }
    }
    if (feml) fclose(feml);
    {
        char line[256];
        sprintf(line, "%d,%d,%s,%08d.txt\n", next_seq, next_id, flags ? flags : "", next_id);
        AppendCSVCached(csv_path, session->crypt_key, g_state.encrypt_data, line);
    }
    
    FlushCSVCache(FALSE);
    SendTaggedResponse(session->sock, tag, "OK", "APPEND completed");
}

static void CmdCopy(ClientSession* session, const char* tag, ASTNode* args, BOOL is_uid) {
    char src_csv[MAX_PATH], src_dir[MAX_PATH], dest_dir[MAX_PATH], dest_csv[MAX_PATH];
    const char *sequence_set, *dest_mbox;
    char* csv_data;
    int max_id = 0;
    
    if (!args || !args->next) { SendTaggedResponse(session->sock, tag, "BAD", "Missing args"); return; }
    sequence_set = args->value;
    dest_mbox = args->next->value;
    
    InitUserMailbox(session->user, session->mailbox, src_dir, src_csv);
    InitUserMailbox(session->user, dest_mbox, dest_dir, dest_csv);
    
    csv_data = ReadCSVCached(src_csv, session->crypt_key, g_state.encrypt_data);
    if (csv_data) {
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                int seq_num, uid;
                if (sscanf(p, "%d,%d,", &seq_num, &uid) == 2) {
                    int current_id = is_uid ? uid : seq_num;
                    if (current_id > max_id) max_id = current_id;
                }
            }
            if (nl) *nl = '\n';
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
                if (ParseCSVLine(p, &seq_num, &uid, flags, filename)) {
                    if (MatchesSequence(is_uid ? uid : seq_num, max_id, sequence_set)) {
                        int next_dest_id = 1;
                        int next_dest_seq = 1;
                        char* d_csv = ReadCSVCached(dest_csv, session->crypt_key, g_state.encrypt_data);
                        if (d_csv) {
                            char* dp = d_csv;
                            while (*dp) {
                                char* dnl = strchr(dp, '\n');
                                if (dnl) *dnl = '\0';
                                if (strlen(dp) > 2) {
                                    next_dest_seq++; 
                                    int d_seq, d_uid;
                                    if (sscanf(dp, "%d,%d,", &d_seq, &d_uid) == 2) {
                                        if (d_uid >= next_dest_id) next_dest_id = d_uid + 1;
                                    }
                                }
                                if (dnl) *dnl = '\n';
                                if (!dnl) break;
                                dp = dnl + 1;
                            }
                            free(d_csv);
                        }
                        
                        char src_file[MAX_PATH], dst_file[MAX_PATH], line[256];
                        sprintf(src_file, "%s\\%s", src_dir, filename);
                        sprintf(dst_file, "%s\\%08d.txt", dest_dir, next_dest_id);
                        
                        CopyFileA(src_file, dst_file, FALSE);
                        
                        sprintf(line, "%d,%d,%s,%08d.txt\n", next_dest_seq, next_dest_id, flags, next_dest_id);
                        AppendCSVCached(dest_csv, session->crypt_key, g_state.encrypt_data, line);
                    }
                }
            }
            if (nl) *nl = '\n';
            if (!nl) break;
            p = nl + 1;
        }
        free(csv_data);
    }
    FlushCSVCache(FALSE);
    SendTaggedResponse(session->sock, tag, "OK", "COPY completed");
}

static void CmdExpunge(ClientSession* session, const char* tag) {
    char csv_path[MAX_PATH], mbox_dir[MAX_PATH];
    char* csv_data;
    
    InitUserMailbox(session->user, session->mailbox, mbox_dir, csv_path);
    csv_data = ReadCSVCached(csv_path, session->crypt_key, g_state.encrypt_data);
    
    if (csv_data) {
        char* new_csv = (char*)malloc(strlen(csv_data) + 1);
        new_csv[0] = '\0';
        int new_seq = 1;
        int deleted_count = 0;
        
        char* p = csv_data;
        while (*p) {
            char* nl = strchr(p, '\n');
            if (nl) *nl = '\0';
            if (strlen(p) > 2) {
                int seq_num, uid;
                char flags[256], filename[MAX_PATH];
                if (ParseCSVLine(p, &seq_num, &uid, flags, filename)) {
                    if (strstr(flags, "\\Deleted")) {
                        char filepath[MAX_PATH];
                        char resp[64];
                        
                        sprintf(filepath, "%s\\%s", mbox_dir, filename);
                        DeleteFileA(filepath);
                        
                        sprintf(resp, "* %d EXPUNGE", seq_num - deleted_count);
                        SendResponse(session->sock, resp);
                        deleted_count++;
                    } else {
                        char line[512];
                        sprintf(line, "%d,%d,%s,%s\n", new_seq++, uid, flags, filename);
                        strcat(new_csv, line);
                    }
                }
            }
            if (nl) *nl = '\n'; 
            if (!nl) break;
            p = nl + 1;
        }
        
        EnterCriticalSection(&g_csv_cs);
        CachedCSV* curr = g_csv_cache;
        while (curr) {
            if (CaseInsensitiveCompare(curr->path, csv_path) == 0) {
                free(curr->data);
                curr->len = strlen(new_csv);
                curr->cap = curr->len + 256;
                curr->data = new_csv;
                curr->dirty = TRUE;
                break;
            }
            curr = curr->next;
        }
        LeaveCriticalSection(&g_csv_cs);
        if (!curr) free(new_csv);
        free(csv_data);
    }
    
    FlushCSVCache(FALSE);
    SendTaggedResponse(session->sock, tag, "OK", "EXPUNGE completed");
}
static void CmdCheck(ClientSession* session, const char* tag) {
    ServerLog("[Socket %u] Stubbed CHECK command received", (unsigned int)(UINT_PTR)session->sock);
    SendTaggedResponse(session->sock, tag, "OK", "CHECK completed");
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
        
        ServerLog("[Socket %u] Executing command: %s", (unsigned int)(UINT_PTR)session->sock, cmd);
        
        if (session->append_only) {
            if (CaseInsensitiveCompare(cmd, "CAPABILITY") != 0 &&
                CaseInsensitiveCompare(cmd, "NOOP") != 0 &&
                CaseInsensitiveCompare(cmd, "LOGOUT") != 0 &&
                CaseInsensitiveCompare(cmd, "LOGIN") != 0 &&
                CaseInsensitiveCompare(cmd, "APPEND") != 0) {
                
                ServerLog("[Socket %u] Command %s rejected: Append-only mode", (unsigned int)(UINT_PTR)session->sock, cmd);
                SendTaggedResponse(session->sock, tag, "NO", "Permission denied for append-only user");
                FreeAST(ast);
                return;
            }
        }
        
        if (CaseInsensitiveCompare(cmd, "CAPABILITY") == 0) CmdCapability(session, tag);
        else if (CaseInsensitiveCompare(cmd, "NOOP") == 0) CmdNoop(session, tag);
        else if (CaseInsensitiveCompare(cmd, "LOGOUT") == 0) CmdLogout(session, tag);
        else if (CaseInsensitiveCompare(cmd, "LOGIN") == 0) CmdLogin(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "CREATE") == 0) CmdCreate(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "SELECT") == 0 || CaseInsensitiveCompare(cmd, "EXAMINE") == 0) CmdSelect(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "LIST") == 0) CmdList(session, tag);
        else if (CaseInsensitiveCompare(cmd, "LSUB") == 0) CmdLsub(session, tag);
        else if (CaseInsensitiveCompare(cmd, "STATUS") == 0) CmdStatus(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "COPY") == 0) CmdCopy(session, tag, args, FALSE);
        else if (CaseInsensitiveCompare(cmd, "EXPUNGE") == 0) CmdExpunge(session, tag);
        else if (CaseInsensitiveCompare(cmd, "FETCH") == 0) CmdFetch(session, tag, args);
        else if (CaseInsensitiveCompare(cmd, "SEARCH") == 0) CmdSearch(session, tag, args, FALSE);
        else if (CaseInsensitiveCompare(cmd, "STORE") == 0) CmdStore(session, tag, args, FALSE);
else if (CaseInsensitiveCompare(cmd, "CHECK") == 0) CmdCheck(session, tag);
        else if (CaseInsensitiveCompare(cmd, "UID") == 0) {
            if (args) {
                if (CaseInsensitiveCompare(args->value, "FETCH") == 0) CmdFetchEx(session, tag, args->next, TRUE);
                else if (CaseInsensitiveCompare(args->value, "SEARCH") == 0) CmdSearch(session, tag, args->next, TRUE);
                else if (CaseInsensitiveCompare(args->value, "STORE") == 0) CmdStore(session, tag, args->next, TRUE);
                else if (CaseInsensitiveCompare(args->value, "COPY") == 0) CmdCopy(session, tag, args->next, TRUE);
                else SendTaggedResponse(session->sock, tag, "BAD", "Unsupported UID command");
            } else {
                SendTaggedResponse(session->sock, tag, "BAD", "Missing UID argument");
            }
        }
        else {
            ServerLog("[Socket %u] Unknown command: %s", (unsigned int)(UINT_PTR)session->sock, cmd);
            SendTaggedResponse(session->sock, tag, "BAD", "Unknown command");
        }
    }
    FreeAST(ast);
}
static void LogReceivedLine(SOCKET sock, const char* line) {
    char log_line[4096];
    char* upper_line;
    char* p;
    size_t len = strlen(line);
    if (len >= sizeof(log_line)) len = sizeof(log_line) - 1;
    memcpy(log_line, line, len);
    log_line[len] = '\0';

    upper_line = DuplicateString(log_line);
    if (upper_line) {
        for (p = upper_line; *p; ++p) *p = (char)toupper((unsigned char)*p);
        p = strstr(upper_line, " LOGIN ");
        if (p) {
            size_t offset = p - upper_line + 7;
            char* orig_p = log_line + offset;
            BOOL in_quotes = FALSE;
            while (*orig_p) {
                if (*orig_p == '"') in_quotes = !in_quotes;
                else if (!in_quotes && (*orig_p == ' ' || *orig_p == '\t')) break;
                orig_p++;
            }
            while (*orig_p == ' ' || *orig_p == '\t') orig_p++;
            
            if (*orig_p) {
                *orig_p = '\0';
                strcat_s(log_line, sizeof(log_line), "*****");
            }
        }
        free(upper_line);
    }
    ServerLog("[Socket %u] C: %s", (unsigned int)(UINT_PTR)sock, log_line);
}

static void HandleClient(SOCKET client) {
    ClientSession session = {0};
    char buffer[4096];
    int buf_len = 0;
    int timeout = g_state.timeout_ms;
    struct sockaddr_in peer;
    int peer_len = sizeof(peer);
    
    session.sock = client;
    if (getpeername(client, (struct sockaddr*)&peer, &peer_len) == 0) {
        strcpy(session.client_ip, inet_ntoa(peer.sin_addr));
    } else {
        strcpy(session.client_ip, "Unknown");
    }

    if (g_state.hosts_only) {
        if (!IsHostAllowed(session.client_ip)) {
            ServerLog("[Socket %u] Connection from %s blocked by Hosts Only mode", (unsigned int)(UINT_PTR)client, session.client_ip);
            closesocket(client);
            return;
        }
    }

    if (timeout <= 0) timeout = 1800000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    ServerLog("[Socket %u] Client connected from %s", (unsigned int)(UINT_PTR)client, session.client_ip);
    SendResponse(client, "* OK IMAP4rev1 Service Ready");
    
    while (1) {
        char* line_start;
        char* nl;
        int r = recv(client, buffer + buf_len, (int)(sizeof(buffer) - 1 - buf_len), 0);
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
            
            LogReceivedLine(client, line);
            
            if (literal_size > 0) {
                ASTNode* ast = ParseIMAPCommand(line);
                if (ast && ast->type == NODE_COMMAND && ast->child) {
                    const char* tag = ast->value;
                    const char* cmd = ast->child->value;
                    if (CaseInsensitiveCompare(cmd, "APPEND") == 0) {
                        if (!session.authenticated) {
                            ServerLog("[Socket %u] APPEND rejected, not authenticated", (unsigned int)(UINT_PTR)client);
                            SendTaggedResponse(client, tag, "NO", "Authenticate first");
                        } else {
                            ASTNode* args = ast->child->next;
                            const char* mbox = args ? args->value : "Drafts";
                            
                            char append_flags[128] = "";
                            if (args && args->next && args->next->value && args->next->value[0] == '(') {
                                strncpy(append_flags, args->next->value + 1, sizeof(append_flags) - 1);
                                append_flags[sizeof(append_flags) - 1] = '\0';
                                char* rparen = strchr(append_flags, ')');
                                if (rparen) *rparen = '\0';
                            }
                            
                            int consumed = 0;
                            int avail = buf_len - (int)(line_start - buffer);
                            LogSent(client, "+ Ready for literal data");
                            SendSocketData(client, "+ Ready for literal data\r\n");
                            SaveAppendData(&session, tag, mbox, append_flags, literal_size, line_start, avail, &consumed);
                            line_start += consumed;
                        }
                    } else {
                        ServerLog("[Socket %u] Command %s rejected, literates not supported here", (unsigned int)(UINT_PTR)client, cmd);
                        SendTaggedResponse(client, tag, "BAD", "Command does not support literals");
                    }
                }
                if (ast) FreeAST(ast);
            } else ProcessCommand(&session, line);
        }
        if (line_start < buffer + buf_len) {
            int rem = (int)((buffer + buf_len) - line_start);
            memmove(buffer, line_start, rem);
            buf_len = rem;
        } else buf_len = 0;
    }
    closesocket(client);
    ServerLog("[Socket %u] Client disconnected", (unsigned int)(UINT_PTR)client);
}
static DWORD WINAPI ServerWorker(LPVOID lpParam) {
    WSADATA wsa;
    struct sockaddr_in serv = {0};
    int opt = 1;
    (void)lpParam;
    
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) goto fail;
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons((u_short)g_state.port);
    g_state.listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_state.listen_socket == INVALID_SOCKET) goto fail_wsa;
    
    setsockopt(g_state.listen_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (bind(g_state.listen_socket, (struct sockaddr*)&serv, sizeof(serv)) == SOCKET_ERROR) {
        ServerLog("Failed to bind socket on port %d", g_state.port);
        goto fail_close;
    }
    if (listen(g_state.listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        ServerLog("Failed to listen on socket");
        goto fail_close;
    }
    
    ServerLog("Server started on port %d", g_state.port);
    
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
    ServerLog("Server stopped.");
    if (g_state.settings_hwnd) PostMessage(g_state.settings_hwnd, WM_PORT_UPDATE, 0, 0);
    return 0;
}

static DWORD WINAPI ReencryptThread(LPVOID lpParam) {
    ReencryptParams* params = (ReencryptParams*)lpParam;
    char path[MAX_PATH], user_dir[MAX_PATH], search_path[MAX_PATH];
    char old_key[128], new_key[128];
    WIN32_FIND_DATAA fd;
    HANDLE hFind;
    
    ComputeSaltedHash(params->old_pass, "salty", old_key);
    ComputeSaltedHash(params->new_pass, "salty", new_key);

    ServerLog("Starting background file re-encryption for user '%s'...", params->user);
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
                                
                                buf = ReadEntireFile(filepath, old_key, TRUE);
                                if (buf) {
                                    FILE* out = fopen(filepath, "wb");
                                    if (out) {
                                        long size = (long)strlen(buf);
                                        if (g_state.encrypt_data) FastXorCipherChunk((BYTE*)buf, size, new_key, 0);
                                        fwrite(buf, 1, size, out);
                                        fclose(out);
                                        ServerLog("Re-encrypted: %s", filepath);
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
    ServerLog("Finished re-encryption for user '%s'.", params->user);
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
        WS_CAPTION | WS_SYSMENU | WS_POPUP, 100, 100, 300, 440, parent, NULL, hinst, NULL);
    if (!g_state.settings_hwnd) return;
    
    CreateWindowExW(0, L"STATIC", L"Port Number:", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 20, 100, 25, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_port = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL, 130, 17, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_PORT, hinst, NULL);
        
    CreateWindowExW(0, L"STATIC", L"Timeout (ms):", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 50, 100, 25, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_timeout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL, 130, 47, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_TIMEOUT, hinst, NULL);
    
    g_state.btn_startstop = CreateWindowExW(0, L"BUTTON", g_state.running ? L"Running" : L"Stopped", WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, 20, 85, 110, 40, g_state.settings_hwnd, (HMENU)ID_BTN_STARTSTOP, hinst, NULL);
    g_state.btn_close = CreateWindowExW(0, L"BUTTON", L"Close", WS_VISIBLE | WS_CHILD, 150, 85, 100, 40, g_state.settings_hwnd, (HMENU)ID_BTN_CLOSE, hinst, NULL);

    CreateWindowExW(0, L"STATIC", L"Users (Select and press Del):", WS_VISIBLE | WS_CHILD | SS_LEFT, 20, 140, 200, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.list_users = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL, WS_VISIBLE | WS_CHILD | LBS_NOTIFY | WS_VSCROLL | WS_BORDER, 20, 160, 110, 180, g_state.settings_hwnd, (HMENU)ID_LIST_USERS, hinst, NULL);
    
    // Subclass the listbox to intercept the Delete key
    OriginalListBoxProc = (WNDPROC)SetWindowLongPtr(g_state.list_users, GWLP_WNDPROC, (LONG_PTR)ListBoxSubclassProc);
        
    CreateWindowExW(0, L"STATIC", L"Username:", WS_VISIBLE | WS_CHILD | SS_LEFT, 140, 160, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_username = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, 140, 180, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_NEWUSER, hinst, NULL);
        
    CreateWindowExW(0, L"STATIC", L"Old Password:", WS_VISIBLE | WS_CHILD | SS_LEFT, 140, 210, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_oldpass = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_PASSWORD, 140, 230, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_OLDPASS, hinst, NULL);

    CreateWindowExW(0, L"STATIC", L"New Password:", WS_VISIBLE | WS_CHILD | SS_LEFT, 140, 260, 100, 20, g_state.settings_hwnd, NULL, hinst, NULL);
    g_state.edit_password = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_PASSWORD, 140, 280, 120, 25, g_state.settings_hwnd, (HMENU)ID_EDIT_NEWPASS, hinst, NULL);
    
    g_state.chk_encrypt = CreateWindowExW(0, L"BUTTON", L"Encrypt Data", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 140, 310, 120, 18, g_state.settings_hwnd, (HMENU)ID_CHK_ENCRYPT, hinst, NULL);
    SendMessage(g_state.chk_encrypt, BM_SETCHECK, g_state.encrypt_data ? BST_CHECKED : BST_UNCHECKED, 0);

    g_state.chk_logging = CreateWindowExW(0, L"BUTTON", L"Enable Logging", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 140, 330, 120, 18, g_state.settings_hwnd, (HMENU)ID_CHK_LOGGING, hinst, NULL);
    SendMessage(g_state.chk_logging, BM_SETCHECK, g_state.logging_enabled ? BST_CHECKED : BST_UNCHECKED, 0);

    g_state.chk_hostsonly = CreateWindowExW(0, L"BUTTON", L"Hosts Only Mode", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 140, 350, 120, 18, g_state.settings_hwnd, (HMENU)ID_CHK_HOSTSONLY, hinst, NULL);
    SendMessage(g_state.chk_hostsonly, BM_SETCHECK, g_state.hosts_only ? BST_CHECKED : BST_UNCHECKED, 0);

    g_state.btn_adduser = CreateWindowExW(0, L"BUTTON", L"Save / Reset", WS_VISIBLE | WS_CHILD, 140, 375, 120, 30, g_state.settings_hwnd, (HMENU)ID_BTN_ADDUSER, hinst, NULL);
    
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
            if ((HWND)lp == g_state.chk_encrypt || (HWND)lp == g_state.chk_logging || 
                (HWND)lp == g_state.chk_hostsonly || (HWND)lp == g_state.btn_adduser) {
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
            } else if (LOWORD(wp) == ID_CHK_LOGGING && HIWORD(wp) == BN_CLICKED) {
                g_state.logging_enabled = (SendMessage(g_state.chk_logging, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SaveSettings();
            } else if (LOWORD(wp) == ID_CHK_HOSTSONLY && HIWORD(wp) == BN_CLICKED) {
                g_state.hosts_only = (SendMessage(g_state.chk_hostsonly, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SaveSettings();
            } else if (LOWORD(wp) == ID_BTN_STARTSTOP && HIWORD(wp) == BN_CLICKED) {
                SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_START_STOP, 0);
            } else if (LOWORD(wp) == ID_BTN_CLOSE && HIWORD(wp) == BN_CLICKED) { ShowWindow(hwnd, SW_HIDE);
            } else if (LOWORD(wp) == ID_BTN_ADDUSER && HIWORD(wp) == BN_CLICKED) {
                char user[256] = {0}, oldp[256] = {0}, newp[256] = {0};
                char* at_sign;

                GetWindowTextA(g_state.edit_username, user, 256);
                
                at_sign = strchr(user, '@');
                if (at_sign) {
                    *at_sign = '\0';
                }
                
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
                        FlushCSVCache(TRUE);
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
