/* ============================================================================
 * Enterprise Chat Server - Win32 UI + XMPP / Binary Chat Protocol
 *
 * COMPILATION INSTRUCTIONS (64-bit GCC/MinGW):
 *   gcc -Os -s -Wl,--subsystem,windows -mwindows -o chatd.exe chatd.c -lgdi32 -lole32 -limm32 -lcomdlg32 -lcomctl32 -lws2_32 -lwinmm -lshlwapi -ladvapi32
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <ctype.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#define WM_PORT_UPDATE     (WM_USER + 101)
#define ID_BTN_STARTSTOP   1001
#define ID_BTN_CLOSE       1002
#define ID_BTN_ADDUSER     1003
#define ID_LIST_USERS      1004
#define ID_EDIT_PORT       1005
#define ID_EDIT_USER       1006
#define ID_EDIT_PASS       1007
#define ID_EDIT_FULLNAME   1008
#define ID_EDIT_EMAIL      1009
#define ID_CHK_MOD         1010
#define ID_BTN_DELUSER     1011
#define TIMER_PORT_DELAY   2001
#define WM_TRAYICON        (WM_USER + 102)
#define ID_TRAY_APP_ICON   5000
#define ID_TRAY_SHOW       5001
#define ID_TRAY_EXIT       5002
#define ID_TRAY_TOGGLE_RUN 5003
#define ST_UNKNOWN         0
#define ST_AUTH            1
#define ST_MESSAGE         2
#define ST_PRESENCE        3
#define ST_JOIN_ROOM       4
#define ST_MUTATE          5
#define ST_FILE_CHUNK      6
#define ST_FILE_GET        7
#define ST_SEARCH          8
#define ST_INVITE          9
#define ST_VIEWED          11
#define ST_VCARD           12
#define ST_KICK            13
typedef enum {
    PRESENCE_OFFLINE = 0,
    PRESENCE_ONLINE = 1,
    PRESENCE_AWAY = 2
} UserPresenceState;

typedef enum {
    STANZA_UNKNOWN = 0,
    STANZA_AUTH,
    STANZA_MESSAGE,
    STANZA_PRESENCE,
    STANZA_JOIN_ROOM,
    STANZA_MUTATE,
    STANZA_FILE_CHUNK,
    STANZA_FILE_GET,
    STANZA_SEARCH,
    STANZA_INVITE,
    STANZA_VIEWED,
    STANZA_VCARD,
    STANZA_KICK,
    STANZA_DESTROY
} StanzaType;

typedef struct {
    StanzaType type;
    char from[256];
    char to[256];
    char id[64];
    char body[4096];
    char extra[256];
    UserPresenceState presence;
    int int_val;
} XMPPStanza;

typedef struct ClientSession {
    SOCKET sock;
    char user[256];
    BOOL authenticated;
    UserPresenceState presence;
    struct ClientSession* next;
} ClientSession;

typedef struct {
    char room_jid[256];
    SOCKET member_socks[64];
    char member_names[64][256];
    int member_count;
} ChatRoom;

typedef struct {
    HWND main_hwnd;
    HWND settings_hwnd;
    HWND edit_port;
    HWND edit_username;
    HWND edit_password;
    HWND edit_fullname;
    HWND edit_email;
    HWND chk_moderator;
    HWND list_users;
    HWND btn_startstop;
    HBRUSH green_brush;
    HBRUSH gray_brush;
    HFONT font_ui;
    int port;
    BOOL running;
    SOCKET listen_socket;
} ServerState;

static ServerState g_state = {0};
static ClientSession* g_clients = NULL;
static CRITICAL_SECTION g_clients_cs;
static ChatRoom g_rooms[64];  
static int g_room_count = 0;
static CRITICAL_SECTION g_rooms_cs;
static WCHAR g_ini_path[MAX_PATH] = {0};

// Forward Declarations
static DWORD WINAPI ServerWorker(LPVOID lpParam);
LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
static BOOL GetINIPath(void);
static void EnsureDirectoryExists(const char* path);
static void GetChatFolder(const char* user1, const char* user2, char* out_folder);
static void SanitizeMessageBody(char* body);
static void SendAll(SOCKET s, const char* data, int len);
static BOOL IsUserModerator(const char* username);
static void SaveRoomToINI(ChatRoom* room);
static void BroadcastRawToRoom(const char* room_jid, const char* data, int len, SOCKET exclude_sock);

static int CaseInsensitiveCompare(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return *a - *b;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static BOOL IsUserModerator(const char* username) {
    if (!username || username[0] == '\0') return FALSE;
    if (CaseInsensitiveCompare(username, "admin") == 0) return TRUE;
    if (GetINIPath()) {
        WCHAR w_user[256], w_perm[64];
        MultiByteToWideChar(CP_UTF8, 0, username, -1, w_user, 256);
        GetPrivateProfileStringW(L"Permissions", w_user, L"user", w_perm, 64, g_ini_path);
        if (_wcsicmp(w_perm, L"moderator") == 0) return TRUE;
    }
    return FALSE;
}

static void SaveRoomToINI(ChatRoom* room) {
    if (!room || room->room_jid[0] == '\0') return;
    if (GetINIPath()) {
        WCHAR w_room[256];
        MultiByteToWideChar(CP_UTF8, 0, room->room_jid, -1, w_room, 256);
        char members_buf[2048] = "";
        for (int i = 0; i < room->member_count; i++) {
            if (room->member_names[i][0] != '\0') {
                if (strlen(members_buf) > 0) strcat(members_buf, ",");
                strcat(members_buf, room->member_names[i]);
            }
        }
        WCHAR w_mem[2048];
        MultiByteToWideChar(CP_UTF8, 0, members_buf, -1, w_mem, 2048);
        WritePrivateProfileStringW(L"Rooms", w_room, w_mem, g_ini_path);
    }
}

static void BroadcastRawToRoom(const char* room_jid, const char* data, int len, SOCKET exclude_sock) {
    EnterCriticalSection(&g_rooms_cs);
    for (int i = 0; i < g_room_count; i++) {
        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_jid) == 0) {
            for (int j = 0; j < g_rooms[i].member_count; j++) {
                if (g_rooms[i].member_socks[j] != exclude_sock && g_rooms[i].member_socks[j] != INVALID_SOCKET) {
                    send(g_rooms[i].member_socks[j], data, len, 0);
                }
            }
            break;
        }
    }
    LeaveCriticalSection(&g_rooms_cs);
}

static BOOL IsUserRoomMember(const char* username, const char* room_jid) {
    if (IsUserModerator(username)) return TRUE;
    BOOL is_member = FALSE;
    EnterCriticalSection(&g_rooms_cs);
    for (int i = 0; i < g_room_count; i++) {
        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_jid) == 0) {
            for (int j = 0; j < g_rooms[i].member_count; j++) {
                if (CaseInsensitiveCompare(g_rooms[i].member_names[j], username) == 0) {
                    is_member = TRUE;
                    break;
                }
            }
            break;
        }
    }
    LeaveCriticalSection(&g_rooms_cs);
    return is_member;
}

static void EnsureDirectoryExists(const char* path) {
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '\\' || *p == '/') {
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(tmp, NULL);
}

static void GetChatFolder(const char* user1, const char* user2, char* out_folder) {
    char base[MAX_PATH];
    GetModuleFileNameA(NULL, base, MAX_PATH);
    char* slash = strrchr(base, '\\');
    if (slash) *slash = '\0';
    
    char sorted_dir[512];
    if (user2[0] == '#') {
        snprintf(sorted_dir, sizeof(sorted_dir), "rooms\\%s", user2);
    } else {
        if (CaseInsensitiveCompare(user1, user2) < 0) {
            snprintf(sorted_dir, sizeof(sorted_dir), "chats\\%s_%s", user1, user2);
        } else {
            snprintf(sorted_dir, sizeof(sorted_dir), "chats\\%s_%s", user2, user1);
        }
    }
    snprintf(out_folder, MAX_PATH, "%s\\%s", base, sorted_dir);
    EnsureDirectoryExists(out_folder);
}

static void SanitizeMessageBody(char* body) {
    if (!body) return;
    for (char* p = body; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }
    char* bad_tag;
    while ((bad_tag = strstr(body, "</body>")) != NULL) {
        memcpy(bad_tag, "[/body]", 7);
    }
}

static void SendAll(SOCKET s, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, data + sent, len - sent, 0);
        if (r <= 0) break;
        sent += r;
    }
}

static void QueueOfflinePacket(const char* target_user, const char* pkt) {
    BOOL online = FALSE;
    EnterCriticalSection(&g_clients_cs);
    ClientSession* curr = g_clients;
    while (curr) {
        if (curr->authenticated && CaseInsensitiveCompare(curr->user, target_user) == 0) {
            online = TRUE;
            break;
        }
        curr = curr->next;
    }
    LeaveCriticalSection(&g_clients_cs);
    if (online) return;

    char base[MAX_PATH], off_dir[MAX_PATH], qfile[MAX_PATH];
    GetModuleFileNameA(NULL, base, MAX_PATH);
    char* slash = strrchr(base, '\\');
    if (slash) *slash = '\0';
    snprintf(off_dir, sizeof(off_dir), "%s\\offline", base);
    EnsureDirectoryExists(off_dir);
    snprintf(qfile, sizeof(qfile), "%s\\%s.txt", off_dir, target_user);

    FILE* f = fopen(qfile, "ab");
    if (f) {
        fputs(pkt, f);
        fclose(f);
    }
}

static BOOL RewriteHistoryMessage(const char* sender, const char* target, const char* msg_id, int action, const char* new_body, char* out_final_body, int max_out) {
    char folder[MAX_PATH], file_path[MAX_PATH], tmp_path[MAX_PATH];
    GetChatFolder(sender, target, folder);
    snprintf(file_path, sizeof(file_path), "%s\\history.txt", folder);
    snprintf(tmp_path, sizeof(tmp_path), "%s\\history.tmp", folder);

    FILE* f = fopen(file_path, "rb");
    if (!f) return FALSE;
    FILE* out = fopen(tmp_path, "wb");
    if (!out) { fclose(f); return FALSE; }

    BOOL modified = FALSE;
    char line[8192];
    char id_pat[128];
    snprintf(id_pat, sizeof(id_pat), "id=\"%s\"", msg_id);

    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, id_pat)) {
            char orig_from[256] = "", orig_to[256] = "", orig_body[4096] = "";
            int orig_status = 1;
            char* fp = strstr(line, "from=\"");
            if (fp) sscanf(fp, "from=\"%255[^\"]\"", orig_from);
            char* tp = strstr(line, "to=\"");
            if (tp) sscanf(tp, "to=\"%255[^\"]\"", orig_to);
            char* sp = strstr(line, "status=\"");
            if (sp) sscanf(sp, "status=\"%d\"", &orig_status);
            char* bs = strstr(line, "<body>");
            char* be = strstr(line, "</body>");
            if (bs && be && be > bs + 6) {
                int blen = (int)(be - (bs + 6));
                if (blen >= (int)sizeof(orig_body)) blen = sizeof(orig_body) - 1;
                memcpy(orig_body, bs + 6, blen);
                orig_body[blen] = '\0';
            }

            if (action == 1) {
                if (CaseInsensitiveCompare(orig_from, sender) == 0 || IsUserModerator(sender)) {
                    char clean_edit[4096];
                    strncpy(clean_edit, new_body ? new_body : "", sizeof(clean_edit) - 1);
                    clean_edit[sizeof(clean_edit) - 1] = '\0';
                    SanitizeMessageBody(clean_edit);
                    if (strstr(clean_edit, "(edited)") == NULL) {
                        snprintf(out_final_body, max_out, "%s (edited)", clean_edit);
                    } else {
                        snprintf(out_final_body, max_out, "%s", clean_edit);
                    }
                    fprintf(out, "<message from=\"%s\" to=\"%s\" id=\"%s\" status=\"%d\"><body>%s</body></message>\n",
                            orig_from, orig_to, msg_id, orig_status, out_final_body);
                    modified = TRUE;
                    continue;
                }
            } else if (action == 3) {
                if (CaseInsensitiveCompare(orig_from, sender) == 0 || IsUserModerator(sender)) {
                    modified = TRUE;
                    continue;
                }
            } else if (action == 4) {
                char react_tag[256];
                snprintf(react_tag, sizeof(react_tag), " [%s:%s]", new_body ? new_body : "", sender);
                SanitizeMessageBody(react_tag);

                char* existing_react = strstr(orig_body, react_tag);
                if (existing_react) {
                    memmove(existing_react, existing_react + strlen(react_tag), strlen(existing_react + strlen(react_tag)) + 1);
                    snprintf(out_final_body, max_out, "%s", orig_body);
                } else {
                    snprintf(out_final_body, max_out, "%s%s", orig_body, react_tag);
                }
                fprintf(out, "<message from=\"%s\" to=\"%s\" id=\"%s\" status=\"%d\"><body>%s</body></message>\n",
                        orig_from, orig_to, msg_id, orig_status, out_final_body);
                modified = TRUE;
                continue;
            } else if (action == 5) {
                fprintf(out, "<message from=\"%s\" to=\"%s\" id=\"%s\" status=\"2\"><body>%s</body></message>\n",
                        orig_from, orig_to, msg_id, orig_body);
                modified = TRUE;
                continue;
            }
        }
        fputs(line, out);
    }
    fclose(f);
    fclose(out);

    if (modified) {
        MoveFileExA(tmp_path, file_path, MOVEFILE_REPLACE_EXISTING);
    } else {
        DeleteFileA(tmp_path);
    }
    return modified;
}

// ============================================================================
// SERVER SIDE: chatd.c 
// ============================================================================

static void SendUserRoomsOnLogin(ClientSession* session) {
    EnterCriticalSection(&g_rooms_cs);
    for (int i = 0; i < g_room_count; i++) {
        ChatRoom* r = &g_rooms[i];
        BOOL is_member = IsUserModerator(session->user);
        for (int j = 0; j < r->member_count; j++) {
            if (CaseInsensitiveCompare(r->member_names[j], session->user) == 0) {
                r->member_socks[j] = session->sock;
                is_member = TRUE;
                break;
            }
        }
        if (is_member) {
            char pkt[512];
            int plen = snprintf(pkt, sizeof(pkt),
                "<message from=\"Server\" to=\"%s\" id=\"room_sync\" room=\"%s\"><body>Synced room %s</body></message>\n",
                session->user, r->room_jid, r->room_jid);
            SendAll(session->sock, pkt, plen);
        }
    }
    LeaveCriticalSection(&g_rooms_cs);

    char base[MAX_PATH], search_pat[MAX_PATH];
    GetModuleFileNameA(NULL, base, MAX_PATH);
    char* slash = strrchr(base, '\\');
    if (slash) *slash = '\0';
    snprintf(search_pat, sizeof(search_pat), "%s\\chats\\*_*", base);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_pat, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        size_t ulen = strlen(session->user);
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                const char* dname = fd.cFileName;
                const char* peer = NULL;
                char peer_buf[256] = "";

                if (_strnicmp(dname, session->user, ulen) == 0 && dname[ulen] == '_') {
                    peer = dname + ulen + 1;
                } else {
                    const char* under = strrchr(dname, '_');
                    if (under && CaseInsensitiveCompare(under + 1, session->user) == 0) {
                        size_t plen = (size_t)(under - dname);
                        if (plen < sizeof(peer_buf)) {
                            memcpy(peer_buf, dname, plen);
                            peer_buf[plen] = '\0';
                            peer = peer_buf;
                        }
                    }
                }
                if (peer && peer[0] != '\0') {
                    char pkt[512];
                    // Prefix the peer with "@ " so the client treats it as a Direct Message
                    int plen = snprintf(pkt, sizeof(pkt),
                        "<message from=\"Server\" to=\"%s\" id=\"room_sync\" room=\"@ %s\"><body>Synced DM %s</body></message>\n",
                        session->user, peer, peer);
                    SendAll(session->sock, pkt, plen);
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
}

static void TrimString(char* s) {
    char* p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
}

static BOOL GetINIPath(void) {
    if (g_ini_path[0] != L'\0') return TRUE;
    GetModuleFileNameW(NULL, g_ini_path, MAX_PATH);
    wchar_t* slash = wcsrchr(g_ini_path, L'\\');
    if (slash) *(slash + 1) = L'\0';
    wcscat_s(g_ini_path, MAX_PATH, L"chatd.ini");
    return TRUE;
}

static void ComputeSaltedHash(const char* password, const char* salt, char* out_hex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 32;
    char combined[512];

    snprintf(combined, sizeof(combined), "%s%s", salt, password);

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (BYTE*)combined, (DWORD)strlen(combined), 0);
            if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                for (DWORD i = 0; i < cbHash; i++) {
                    sprintf(out_hex + (i * 2), "%02x", rgbHash[i]);
                }
                out_hex[64] = '\0';
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

static void SaveSettings(void) {
    if (GetINIPath()) {
        wchar_t buf[32];
        swprintf_s(buf, 32, L"%d", g_state.port);
        WritePrivateProfileStringW(L"Server", L"Port", buf, g_ini_path);
    }
}

static void LoadSettings(void) {
    g_state.port = 5222;
    if (GetINIPath()) {
        BOOL ini_exists = PathFileExistsW(g_ini_path);
        if (!ini_exists) SaveSettings();

        g_state.port = GetPrivateProfileIntW(L"Server", L"Port", 5222, g_ini_path);
        if (g_state.port < 1 || g_state.port > 65535) g_state.port = 5222;

        WCHAR check_user[256];
        GetPrivateProfileStringW(L"Users", L"admin", L"", check_user, 256, g_ini_path);
        if (wcslen(check_user) == 0) {
            char hash[128];
            WCHAR w_val[256];
            ComputeSaltedHash("password", "salty", hash);
            swprintf_s(w_val, 256, L"salty:%hs", hash);
            WritePrivateProfileStringW(L"Users", L"admin", w_val, g_ini_path);
            WritePrivateProfileStringW(L"Permissions", L"admin", L"moderator", g_ini_path);
        }

        WCHAR keys[8192] = {0};
        GetPrivateProfileStringW(L"Rooms", NULL, L"", keys, 8192, g_ini_path);
        WCHAR* p = keys;
        EnterCriticalSection(&g_rooms_cs);
        g_room_count = 0;
        while (*p && g_room_count < 64) {
            char room_name[256];
            WideCharToMultiByte(CP_UTF8, 0, p, -1, room_name, 256, NULL, NULL);
            
            WCHAR mems[2048] = {0};
            GetPrivateProfileStringW(L"Rooms", p, L"", mems, 2048, g_ini_path);
            char mems_mb[2048];
            WideCharToMultiByte(CP_UTF8, 0, mems, -1, mems_mb, 2048, NULL, NULL);

            ChatRoom* r = &g_rooms[g_room_count++];
            memset(r, 0, sizeof(ChatRoom));
            strncpy(r->room_jid, room_name, 255);
            
            char* token = strtok(mems_mb, ",");
            while (token && r->member_count < 64) {
                TrimString(token);
                if (strlen(token) > 0) {
                    strncpy(r->member_names[r->member_count], token, 255);
                    r->member_socks[r->member_count] = INVALID_SOCKET;
                    r->member_count++;
                }
                token = strtok(NULL, ",");
            }
            p += wcslen(p) + 1;
        }
        
        if (g_room_count == 0) {
            strcpy(g_rooms[0].room_jid, "#general"); g_rooms[0].member_count = 0; SaveRoomToINI(&g_rooms[0]);
            strcpy(g_rooms[1].room_jid, "#developers"); g_rooms[1].member_count = 0; SaveRoomToINI(&g_rooms[1]);
            strcpy(g_rooms[2].room_jid, "#announcements"); g_rooms[2].member_count = 0; SaveRoomToINI(&g_rooms[2]);
            g_room_count = 3;
        }
        LeaveCriticalSection(&g_rooms_cs);
    }
}

static int ReadLine(SOCKET s, char* buf, int maxlen) {
    int total = 0;
    while (total < maxlen - 1) {
        char c;
        int r = recv(s, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\r') continue;
        if (c == '\n') break;
        buf[total++] = c;
    }
    buf[total] = '\0';
    return total;
}

static void GenerateUUID(char* out_uuid) {
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK) {
        sprintf(out_uuid, "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    } else {
        strcpy(out_uuid, "msg-uuid-fallback");
    }
}

static void SaveMessageRecord(const char* sender, const char* target, const char* msg_id, const char* body) {
    char clean_body[4096];
    strncpy(clean_body, body ? body : "", sizeof(clean_body) - 1);
    clean_body[sizeof(clean_body) - 1] = '\0';
    SanitizeMessageBody(clean_body);

    char folder[MAX_PATH], file_path[MAX_PATH];
    GetChatFolder(sender, target, folder);
    snprintf(file_path, sizeof(file_path), "%s\\history.txt", folder);
    
    FILE* f = fopen(file_path, "ab");
    if (f) {
        fprintf(f, "<message from=\"%s\" to=\"%s\" id=\"%s\" status=\"1\"><body>%s</body></message>\n", sender, target, msg_id, clean_body);
        fclose(f);
    }
}

static void SendChatHistory(SOCKET sock, const char* reader, const char* target) {
    char folder[MAX_PATH], file_path[MAX_PATH];
    GetChatFolder(reader, target, folder);
    snprintf(file_path, sizeof(file_path), "%s\\history.txt", folder);
    
    FILE* f = fopen(file_path, "rb");
    if (f) {
        char line[8192];
        while (fgets(line, sizeof(line), f)) {
            send(sock, line, (int)strlen(line), 0);
        }
        fclose(f);
    }
}

static void RouteLivePacket(const char* target_user, const char* payload, int len, SOCKET exclude_sock) {
    EnterCriticalSection(&g_clients_cs);
    ClientSession* curr = g_clients;
    while (curr) {
        if (curr->authenticated && curr->sock != exclude_sock &&
            CaseInsensitiveCompare(curr->user, target_user) == 0) {
            send(curr->sock, payload, len, 0);
        }
        curr = curr->next;
    }
    LeaveCriticalSection(&g_clients_cs);
}

static void BroadcastPresence(ClientSession* sender) {
    char pkt[256];
    int plen = snprintf(pkt, sizeof(pkt), "<presence from=\"%s\"><show>%d</show></presence>\n", sender->user, (int)sender->presence);
    EnterCriticalSection(&g_clients_cs);
    ClientSession* curr = g_clients;
    while (curr) {
        if (curr->authenticated) {
            send(curr->sock, pkt, plen, 0);
        }
        curr = curr->next;
    }
    LeaveCriticalSection(&g_clients_cs);
}

static void FlushOfflineQueue(SOCKET client, const char* username) {
    char base[MAX_PATH], qfile[MAX_PATH];
    GetModuleFileNameA(NULL, base, MAX_PATH);
    char* slash = strrchr(base, '\\');
    if (slash) *slash = '\0';
    snprintf(qfile, sizeof(qfile), "%s\\offline\\%s.txt", base, username);

    FILE* f = fopen(qfile, "rb");
    if (f) {
        char line[8192];
        while (fgets(line, sizeof(line), f)) {
            SendAll(client, line, (int)strlen(line));
        }
        fclose(f);
        DeleteFileA(qfile);
    }
}

static void HandleJoinRoom(ClientSession* session, const char* room_jid, BOOL create_if_missing) {
    EnterCriticalSection(&g_rooms_cs);
    ChatRoom* room = NULL;
    for (int i = 0; i < g_room_count; i++) {
        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_jid) == 0) {
            room = &g_rooms[i];
            break;
        }
    }
    if (!room && create_if_missing && g_room_count < 64) {
        room = &g_rooms[g_room_count++];
        strcpy(room->room_jid, room_jid);
        room->member_count = 0;
    }
    if (room) {
        BOOL already_in = FALSE;
        for (int j = 0; j < room->member_count; j++) {
            if (CaseInsensitiveCompare(room->member_names[j], session->user) == 0) {
                room->member_socks[j] = session->sock;
                already_in = TRUE;
                break;
            }
        }
        if (!already_in && room->member_count < 64) {
            room->member_socks[room->member_count] = session->sock;
            strcpy(room->member_names[room->member_count], session->user);
            room->member_count++;
            SaveRoomToINI(room);
        }
    }
    LeaveCriticalSection(&g_rooms_cs);

    char resp[256];
    int rlen = snprintf(resp, sizeof(resp), "<presence to=\"%s\" type=\"room-joined\"/>\n", room_jid);
    send(session->sock, resp, rlen, 0);
}

static void BroadcastToRoom(const char* room_jid, const char* sender, const char* msg_id, const char* msg, SOCKET exclude_sock) {
    EnterCriticalSection(&g_rooms_cs);
    for (int i = 0; i < g_room_count; i++) {
        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_jid) == 0) {
            char pkt[8192];
            int plen = snprintf(pkt, sizeof(pkt), 
                "<message from=\"%s\" to=\"%s\" id=\"%s\" type=\"groupchat\"><body>%s</body></message>\n",
                sender, room_jid, msg_id, msg);
            for (int j = 0; j < g_rooms[i].member_count; j++) {
                if (g_rooms[i].member_socks[j] != exclude_sock) {
                    send(g_rooms[i].member_socks[j], pkt, plen, 0);
                }
            }
            break;
        }
    }
    LeaveCriticalSection(&g_rooms_cs);
}

static void MutateMessage(const char* sender, const char* target, const char* msg_id, int action, const char* new_body) {
    char pkt[8192];
    int plen = snprintf(pkt, sizeof(pkt), "<mutate id=\"%s\" action=\"%d\" to=\"%s\"><body>%s</body></mutate>\n", msg_id, action, target, new_body ? new_body : "");
    RouteLivePacket(target, pkt, plen, INVALID_SOCKET);
    RouteLivePacket(sender, pkt, plen, INVALID_SOCKET);
}

static BOOL ParseStanza(const char* line, XMPPStanza* stanza) {
    memset(stanza, 0, sizeof(XMPPStanza));
    if (strncmp(line, "AUTH ", 5) == 0) {
        stanza->type = STANZA_AUTH;
        const char* p = line + 5;
        while (*p == ' ') p++;
        const char* space = strchr(p, ' ');
        if (space) {
            size_t ulen = (size_t)(space - p);
            if (ulen >= sizeof(stanza->from)) ulen = sizeof(stanza->from) - 1;
            memcpy(stanza->from, p, ulen);
            stanza->from[ulen] = '\0';
            const char* pass_start = space + 1;
            strncpy(stanza->body, pass_start, sizeof(stanza->body) - 1);
            stanza->body[sizeof(stanza->body) - 1] = '\0';
            TrimString(stanza->body);
            return TRUE;
        }
        return FALSE;
    }
    if (strstr(line, "<message")) {
        stanza->type = STANZA_MESSAGE;
        char* to_ptr = strstr(line, "to=\"");
        if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", stanza->to);
        char* id_ptr = strstr(line, "id=\"");
        if (id_ptr) sscanf(id_ptr, "id=\"%63[^\"]\"", stanza->id);

        char* body_start = strstr(line, "<body>");
        char* body_end = strstr(line, "</body>");
        if (body_start && body_end && body_end > body_start + 6) {
            int len = (int)(body_end - (body_start + 6));
            if (len >= (int)sizeof(stanza->body)) len = sizeof(stanza->body) - 1;
            memcpy(stanza->body, body_start + 6, len);
            stanza->body[len] = '\0';
        }
        return TRUE;
    }
    if (strstr(line, "<presence")) {
        stanza->type = STANZA_PRESENCE;
        char* show = strstr(line, "<show>");
        if (show) sscanf(show, "<show>%d</show>", &stanza->int_val);
        stanza->presence = (UserPresenceState)stanza->int_val;
        return TRUE;
    }
    if (strstr(line, "<join")) {
        stanza->type = STANZA_JOIN_ROOM;
        char* room_ptr = strstr(line, "room=\"");
        if (room_ptr) sscanf(room_ptr, "room=\"%255[^\"]\"", stanza->to);
        return TRUE;
    }
    if (strstr(line, "<mutate")) {
        stanza->type = STANZA_MUTATE;
        char* id_ptr = strstr(line, "id=\"");
        if (id_ptr) sscanf(id_ptr, "id=\"%63[^\"]\"", stanza->id);
        char* act_ptr = strstr(line, "action=\"");
        if (act_ptr) sscanf(act_ptr, "action=\"%d\"", &stanza->int_val);
        char* to_ptr = strstr(line, "to=\"");
        if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", stanza->to);

        char* body_start = strstr(line, "<body>");
        char* body_end = strstr(line, "</body>");
        if (body_start && body_end && body_end > body_start + 6) {
            int len = (int)(body_end - (body_start + 6));
            if (len >= (int)sizeof(stanza->body)) len = sizeof(stanza->body) - 1;
            memcpy(stanza->body, body_start + 6, len);
            stanza->body[len] = '\0';
        }
        return TRUE;
    }
    if (strstr(line, "<vcard")) {
        stanza->type = STANZA_VCARD;
        char* name_ptr = strstr(line, "name=\"");
        if (name_ptr) sscanf(name_ptr, "name=\"%255[^\"]\"", stanza->extra);
        char* email_ptr = strstr(line, "email=\"");
        if (email_ptr) sscanf(email_ptr, "email=\"%255[^\"]\"", stanza->body);
        return TRUE;
    }
    if (strncmp(line, "FILE_CHUNK ", 11) == 0) {
        stanza->type = STANZA_FILE_CHUNK;
        return TRUE;
    }
    if (strncmp(line, "FILE_GET ", 9) == 0) {
        stanza->type = STANZA_FILE_GET;
        return TRUE;
    }
    if (strstr(line, "jabber:iq:search")) {
        stanza->type = STANZA_SEARCH;
        char* t_start = strstr(line, "<text>");
        char* t_end = strstr(line, "</text>");
        if (t_start && t_end && t_end > t_start + 6) {
            int len = (int)(t_end - (t_start + 6));
            if (len >= (int)sizeof(stanza->body)) len = sizeof(stanza->body) - 1;
            memcpy(stanza->body, t_start + 6, len);
            stanza->body[len] = '\0';
        }
        return TRUE;
    }
    if (strstr(line, "<invite")) {
        stanza->type = STANZA_INVITE;
        char* to_ptr = strstr(line, "to=\"");
        if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", stanza->to);
        char* room_ptr = strstr(line, "room=\"");
        if (room_ptr) sscanf(room_ptr, "room=\"%255[^\"]\"", stanza->body);
        return TRUE;
    }
    if (strstr(line, "<kick")) {
        stanza->type = STANZA_KICK;
        char* to_ptr = strstr(line, "to=\"");
        if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", stanza->to);
        char* room_ptr = strstr(line, "room=\"");
        if (room_ptr) sscanf(room_ptr, "room=\"%255[^\"]\"", stanza->body);
        return TRUE;
    }
    if (strstr(line, "<destroy")) {
        stanza->type = STANZA_DESTROY;
        char* room_ptr = strstr(line, "room=\"");
        if (room_ptr) sscanf(room_ptr, "room=\"%255[^\"]\"", stanza->to);
        return TRUE;
    }
    if (strstr(line, "<viewed")) {
        stanza->type = STANZA_VIEWED;
        char* id_ptr = strstr(line, "id=\"");
        if (id_ptr) sscanf(id_ptr, "id=\"%63[^\"]\"", stanza->id);
        char* to_ptr = strstr(line, "to=\"");
        if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", stanza->to);
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI HandleClient(LPVOID lpParam) {
    SOCKET client = (SOCKET)(UINT_PTR)lpParam;
    ClientSession* session = (ClientSession*)calloc(1, sizeof(ClientSession));
    char buf[4096];
    int optval = 1;
    int timeout = 45000;
    char active_upload_orig[256] = "";
    char active_upload_actual[256] = "";

    session->sock = client;
    session->presence = PRESENCE_OFFLINE;

    setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, sizeof(optval));
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    EnterCriticalSection(&g_clients_cs);
    session->next = g_clients;
    g_clients = session;
    LeaveCriticalSection(&g_clients_cs);

    const char* greeting = "<?xml version='1.0'?><stream:stream xmlns=\"jabber:client\" version=\"1.0\">\n";
    SendAll(client, greeting, (int)strlen(greeting));

    while (ReadLine(client, buf, sizeof(buf)) >= 0) {
        XMPPStanza stanza;
        if (ParseStanza(buf, &stanza)) {
            if (stanza.type == STANZA_AUTH) {
                WCHAR w_user[256], w_val[512];
                TrimString(stanza.from);
                TrimString(stanza.body);

                if (GetINIPath()) {
                    MultiByteToWideChar(CP_UTF8, 0, stanza.from, -1, w_user, 256);
                    GetPrivateProfileStringW(L"Users", w_user, L"", w_val, 512, g_ini_path);
                    if (wcslen(w_val) > 0) {
                        char val[512];
                        WideCharToMultiByte(CP_UTF8, 0, w_val, -1, val, 512, NULL, NULL);
                        char* colon = strchr(val, ':');
                        if (colon) {
                            *colon = '\0';
                            char computed[128];
                            ComputeSaltedHash(stanza.body, val, computed);
                            if (CaseInsensitiveCompare(computed, colon + 1) == 0) {
                                session->authenticated = TRUE;
                                strncpy(session->user, stanza.from, 255);
                                session->presence = PRESENCE_ONLINE;
                                
                                const char* succ = "<success/>\n";
                                SendAll(client, succ, (int)strlen(succ));
                                
                                SendUserRoomsOnLogin(session);
                                FlushOfflineQueue(client, session->user);
                                BroadcastPresence(session);
                                continue;
                            }
                        }
                    }
                }
                const char* fail = "<failure/><not-authorized/>\n";
                SendAll(client, fail, (int)strlen(fail));
            }
            else if (!session->authenticated) {
                const char* err = "<stream:error><not-authorized/></stream:error>\n";
                SendAll(client, err, (int)strlen(err));
            }
            else if (stanza.type == STANZA_MESSAGE) {
                SanitizeMessageBody(stanza.body);

                if (stanza.to[0] == '#' && !IsUserRoomMember(session->user, stanza.to)) {
                    char err_pkt[512];
                    int elen = snprintf(err_pkt, sizeof(err_pkt),
                        "<message from=\"Server\" to=\"%s\"><body>Error: You are not a member of %s.</body></message>\n",
                        session->user, stanza.to);
                    SendAll(client, err_pkt, elen);
                    continue;
                }

                char msg_id[64];
                if (strlen(stanza.id) == 0) GenerateUUID(msg_id);
                else strncpy(msg_id, stanza.id, 63);

                SaveMessageRecord(session->user, stanza.to, msg_id, stanza.body);

                char ack_pkt[256];
                int alen = snprintf(ack_pkt, sizeof(ack_pkt), "<ack id=\"%s\" status=\"1\"/>\n", msg_id);
                SendAll(client, ack_pkt, alen);

                char pkt[8192];
                int plen = snprintf(pkt, sizeof(pkt), 
                    "<message from=\"%s\" to=\"%s\" id=\"%s\" status=\"1\"><body>%s</body></message>\n",
                    session->user, stanza.to, msg_id, stanza.body);

                if (stanza.to[0] == '#') {
                    BroadcastToRoom(stanza.to, session->user, msg_id, stanza.body, client);
                } else {
                    RouteLivePacket(stanza.to, pkt, plen, INVALID_SOCKET);
                    if (CaseInsensitiveCompare(session->user, stanza.to) != 0) {
                        RouteLivePacket(session->user, pkt, plen, client);
                    }
                }
            }
            else if (stanza.type == STANZA_VIEWED) {
                char dummy[16] = "";
                RewriteHistoryMessage(session->user, stanza.to, stanza.id, 5, "", dummy, sizeof(dummy));

                char v_pkt[256];
                int vlen = snprintf(v_pkt, sizeof(v_pkt), "<ack id=\"%s\" status=\"2\"/>\n", stanza.id);
                if (stanza.to[0] == '#') {
                    BroadcastRawToRoom(stanza.to, v_pkt, vlen, client);
                } else {
                    RouteLivePacket(stanza.to, v_pkt, vlen, INVALID_SOCKET);
                }
            }
            else if (stanza.type == STANZA_PRESENCE) {
                session->presence = stanza.presence;
                BroadcastPresence(session);
            }
            else if (stanza.type == STANZA_JOIN_ROOM) {
                if (stanza.to[0] == '#') {
                    BOOL exists = FALSE;
                    EnterCriticalSection(&g_rooms_cs);
                    for (int i = 0; i < g_room_count; i++) {
                        if (CaseInsensitiveCompare(g_rooms[i].room_jid, stanza.to) == 0) {
                            exists = TRUE;
                            break;
                        }
                    }
                    LeaveCriticalSection(&g_rooms_cs);

                    if (!exists) {
                        if (!IsUserModerator(session->user)) {
                            char err_pkt[512];
                            int elen = snprintf(err_pkt, sizeof(err_pkt),
                                "<message from=\"Server\" to=\"%s\" id=\"kick_notify\" room=\"%s\"><body>Error: Only moderators can create new group chats (%s).</body></message>\n",
                                session->user, stanza.to, stanza.to);
                            SendAll(client, err_pkt, elen);
                            continue;
                        }
                        HandleJoinRoom(session, stanza.to, TRUE);
                    } else {
                        if (!IsUserRoomMember(session->user, stanza.to)) {
                            char err_pkt[512];
                            int elen = snprintf(err_pkt, sizeof(err_pkt),
                                "<message from=\"Server\" to=\"%s\" id=\"kick_notify\" room=\"%s\"><body>Error: Access denied to private room %s.</body></message>\n",
                                session->user, stanza.to, stanza.to);
                            SendAll(client, err_pkt, elen);
                            continue;
                        }
                        HandleJoinRoom(session, stanza.to, FALSE);
                    }
                }
                SendChatHistory(session->sock, session->user, stanza.to);
            }
            else if (stanza.type == STANZA_MUTATE) {
                MutateMessage(session->user, stanza.to, stanza.id, stanza.int_val, stanza.body);
            }
            else if (stanza.type == STANZA_VCARD) {
                if (GetINIPath()) {
                    SanitizeMessageBody(stanza.extra);
                    SanitizeMessageBody(stanza.body);
                    WCHAR w_user[256], w_vcard[512];
                    char combined[512];
                    snprintf(combined, sizeof(combined), "%s|%s", stanza.extra, stanza.body);
                    MultiByteToWideChar(CP_UTF8, 0, session->user, -1, w_user, 256);
                    MultiByteToWideChar(CP_UTF8, 0, combined, -1, w_vcard, 512);
                    WritePrivateProfileStringW(L"VCards", w_user, w_vcard, g_ini_path);
                    char ok_pkt[256];
                    int olen = snprintf(ok_pkt, sizeof(ok_pkt),
                        "<message from=\"Server\" to=\"%s\"><body>vCard profile updated (%s, %s).</body></message>\n",
                        session->user, stanza.extra, stanza.body);
                    SendAll(client, ok_pkt, olen);
                }
            }
            else if (stanza.type == STANZA_INVITE) {
                TrimString(stanza.to);
                TrimString(stanza.body);
                if (strlen(stanza.to) > 0 && strlen(stanza.body) > 0) {
                    char room_name[256];
                    if (stanza.body[0] != '#') snprintf(room_name, sizeof(room_name), "#%s", stanza.body);
                    else strncpy(room_name, stanza.body, sizeof(room_name) - 1);

                    if (!IsUserRoomMember(session->user, room_name)) {
                        char err_pkt[512];
                        int elen = snprintf(err_pkt, sizeof(err_pkt),
                            "<message from=\"Server\" to=\"%s\"><body>Error: You must be a member of %s to invite others.</body></message>\n",
                            session->user, room_name);
                        SendAll(client, err_pkt, elen);
                        continue;
                    }

                    EnterCriticalSection(&g_rooms_cs);
                    ChatRoom* room = NULL;
                    for (int i = 0; i < g_room_count; i++) {
                        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_name) == 0) {
                            room = &g_rooms[i];
                            break;
                        }
                    }
                    if (!room && IsUserModerator(session->user) && g_room_count < 64) {
                        room = &g_rooms[g_room_count++];
                        memset(room, 0, sizeof(ChatRoom));
                        strncpy(room->room_jid, room_name, 255);
                    }
                    if (room) {
                        BOOL in_room = FALSE;
                        for (int j = 0; j < room->member_count; j++) {
                            if (CaseInsensitiveCompare(room->member_names[j], stanza.to) == 0) {
                                in_room = TRUE;
                                break;
                            }
                        }
                        if (!in_room && room->member_count < 64) {
                            room->member_socks[room->member_count] = INVALID_SOCKET;
                            strncpy(room->member_names[room->member_count], stanza.to, 255);
                            room->member_count++;
                        }
                        SaveRoomToINI(room);
                    }
                    LeaveCriticalSection(&g_rooms_cs);

                    EnterCriticalSection(&g_clients_cs);
                    ClientSession* curr = g_clients;
                    while (curr) {
                        if (curr->authenticated && CaseInsensitiveCompare(curr->user, stanza.to) == 0) {
                            HandleJoinRoom(curr, room_name, FALSE);
                        }
                        curr = curr->next;
                    }
                    LeaveCriticalSection(&g_clients_cs);

                    char msg_id[64], notice[512];
                    GenerateUUID(msg_id);
                    snprintf(notice, sizeof(notice), "%s added %s to %s", session->user, stanza.to, room_name);
                    SaveMessageRecord("Server", room_name, msg_id, notice);

                    char inv_pkt[1024];
                    int ilen = snprintf(inv_pkt, sizeof(inv_pkt),
                        "<message from=\"Server\" to=\"%s\" id=\"invite_notify\" room=\"%s\"><body>You have been added to %s by %s.</body></message>\n",
                        stanza.to, room_name, room_name, session->user);
                    RouteLivePacket(stanza.to, inv_pkt, ilen, INVALID_SOCKET);
                    QueueOfflinePacket(stanza.to, inv_pkt);

                    BroadcastToRoom(room_name, "Server", msg_id, notice, INVALID_SOCKET);
                }
            }
            else if (stanza.type == STANZA_KICK) {
                TrimString(stanza.to);
                TrimString(stanza.body);
                if (!IsUserModerator(session->user)) {
                    char err_pkt[512];
                    int elen = snprintf(err_pkt, sizeof(err_pkt),
                        "<message from=\"Server\" to=\"%s\"><body>Error: Only moderators can remove users from chats.</body></message>\n",
                        session->user);
                    SendAll(client, err_pkt, elen);
                    continue;
                }
                if (strlen(stanza.to) > 0 && strlen(stanza.body) > 0) {
                    char room_name[256];
                    if (stanza.body[0] != '#') snprintf(room_name, sizeof(room_name), "#%s", stanza.body);
                    else strncpy(room_name, stanza.body, sizeof(room_name) - 1);

                    EnterCriticalSection(&g_rooms_cs);
                    for (int i = 0; i < g_room_count; i++) {
                        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_name) == 0) {
                            for (int j = 0; j < g_rooms[i].member_count; j++) {
                                if (CaseInsensitiveCompare(g_rooms[i].member_names[j], stanza.to) == 0) {
                                    g_rooms[i].member_socks[j] = g_rooms[i].member_socks[g_rooms[i].member_count - 1];
                                    strcpy(g_rooms[i].member_names[j], g_rooms[i].member_names[g_rooms[i].member_count - 1]);
                                    g_rooms[i].member_count--;
                                    j--;
                                }
                            }
                            SaveRoomToINI(&g_rooms[i]);
                            break;
                        }
                    }
                    LeaveCriticalSection(&g_rooms_cs);

                    char kick_pkt[1024];
                    int klen = snprintf(kick_pkt, sizeof(kick_pkt),
                        "<message from=\"Server\" to=\"%s\" id=\"kick_notify\" room=\"%s\"><body>You have been removed from %s by %s.</body></message>\n",
                        stanza.to, room_name, room_name, session->user);
                    RouteLivePacket(stanza.to, kick_pkt, klen, INVALID_SOCKET);
                    QueueOfflinePacket(stanza.to, kick_pkt);

                    char msg_id[64], notice[512];
                    GenerateUUID(msg_id);
                    snprintf(notice, sizeof(notice), "%s removed %s from %s", session->user, stanza.to, room_name);
                    SaveMessageRecord("Server", room_name, msg_id, notice);
                    BroadcastToRoom(room_name, "Server", msg_id, notice, INVALID_SOCKET);
                }
            }
            else if (stanza.type == STANZA_DESTROY) {
                if (stanza.to[0] == '#') {
                    if (!IsUserModerator(session->user)) {
                        char err_pkt[512];
                        int elen = snprintf(err_pkt, sizeof(err_pkt),
                            "<message from=\"Server\" to=\"%s\"><body>Error: Only moderators can delete group chats.</body></message>\n",
                            session->user);
                        SendAll(client, err_pkt, elen);
                        continue;
                    }
                    
                    char room_name[256];
                    strncpy(room_name, stanza.to, 255);
                    room_name[255] = '\0';
                    TrimString(room_name);

                    EnterCriticalSection(&g_rooms_cs);
                    for (int i = 0; i < g_room_count; i++) {
                        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_name) == 0) {
                            
                            for (int j = 0; j < g_rooms[i].member_count; j++) {
                                char kick_pkt[1024];
                                int klen = snprintf(kick_pkt, sizeof(kick_pkt),
                                    "<message from=\"Server\" to=\"%s\" id=\"kick_notify\" room=\"%s\"><body>Room %s was deleted by %s.</body></message>\n",
                                    g_rooms[i].member_names[j], room_name, room_name, session->user);
                                RouteLivePacket(g_rooms[i].member_names[j], kick_pkt, klen, INVALID_SOCKET);
                                QueueOfflinePacket(g_rooms[i].member_names[j], kick_pkt);
                            }

                            for (int k = i; k < g_room_count - 1; k++) {
                                g_rooms[k] = g_rooms[k + 1];
                            }
                            g_room_count--;

                            if (GetINIPath()) {
                                WCHAR w_room[256];
                                MultiByteToWideChar(CP_UTF8, 0, room_name, -1, w_room, 256);
                                WritePrivateProfileStringW(L"Rooms", w_room, NULL, g_ini_path);
                            }
                            break;
                        }
                    }
                    LeaveCriticalSection(&g_rooms_cs);
                }
            }
            else if (stanza.type == STANZA_SEARCH) {
                char search_query[256];
                strncpy(search_query, stanza.body, 255);
                search_query[255] = '\0';
                TrimString(search_query);

                char results[4096] = "Directory Search Results:\n";
                int found = 0;
                
                if (GetINIPath()) {
                    WCHAR keys[8192] = {0};
                    GetPrivateProfileSectionW(L"Users", keys, 8192, g_ini_path);
                    WCHAR* p = keys;
                    while (*p) {
                        size_t entry_len = wcslen(p);
                        WCHAR* eq = wcschr(p, L'=');
                        if (eq) {
                            WCHAR w_uname[256] = {0};
                            size_t nlen = (size_t)(eq - p);
                            if (nlen > 255) nlen = 255;
                            wcsncpy(w_uname, p, nlen);
                            w_uname[nlen] = L'\0';

                            char uname[256] = "", vcard_str[512] = "", fullname[256] = "", email[256] = "";
                            WideCharToMultiByte(CP_UTF8, 0, w_uname, -1, uname, 256, NULL, NULL);

                            WCHAR w_vcard[512] = {0};
                            GetPrivateProfileStringW(L"VCards", w_uname, L"", w_vcard, 512, g_ini_path);
                            WideCharToMultiByte(CP_UTF8, 0, w_vcard, -1, vcard_str, 512, NULL, NULL);
                            char* pipe = strchr(vcard_str, '|');
                            if (pipe) {
                                *pipe = '\0';
                                strncpy(fullname, vcard_str, 255);
                                strncpy(email, pipe + 1, 255);
                            } else {
                                strncpy(fullname, vcard_str, 255);
                            }

                            if (strlen(search_query) == 0 ||
                                StrStrIA(uname, search_query) ||
                                StrStrIA(fullname, search_query) ||
                                StrStrIA(email, search_query)) {
                                char entry[512];
                                if (strlen(fullname) > 0 || strlen(email) > 0) {
                                    snprintf(entry, sizeof(entry), "- %s (%s <%s>)\n", uname,
                                             strlen(fullname) ? fullname : uname,
                                             strlen(email) ? email : "no-email");
                                } else {
                                    snprintf(entry, sizeof(entry), "- %s\n", uname);
                                }
                                if (strlen(results) + strlen(entry) < sizeof(results) - 64) {
                                    strcat(results, entry);
                                    found++;
                                }
                            }
                        }
                        p += entry_len + 1;
                    }
                }
                
                if (found == 0) strcat(results, "No users matched your query.");
                
                char pkt[8192];
                int plen = snprintf(pkt, sizeof(pkt), "<message from=\"Server\" to=\"%s\" id=\"search_res\"><body>%s</body></message>\n", session->user, results);
                SendAll(client, pkt, plen);
            }
            else if (stanza.type == STANZA_FILE_CHUNK) {
                char target[256], filename[256];
                int chunk_idx, total_chunks, chunk_size;
                if (sscanf(buf, "FILE_CHUNK %255s %255s %d %d %d", target, filename, &chunk_idx, &total_chunks, &chunk_size) == 5) {
                    char folder[MAX_PATH], file_path[MAX_PATH];
                    GetChatFolder(session->user, target, folder);

                    if (chunk_idx == 0 || strcmp(filename, active_upload_orig) != 0) {
                        strncpy(active_upload_orig, filename, 255);
                        strncpy(active_upload_actual, filename, 255);
                        snprintf(file_path, sizeof(file_path), "%s\\%s", folder, active_upload_actual);

                        int dup = 1;
                        while (GetFileAttributesA(file_path) != INVALID_FILE_ATTRIBUTES) {
                            const char* dot = strrchr(filename, '.');
                            if (dot) {
                                int base_len = (int)(dot - filename);
                                snprintf(active_upload_actual, sizeof(active_upload_actual), "%.*s(%d)%s", base_len, filename, dup++, dot);
                            } else {
                                snprintf(active_upload_actual, sizeof(active_upload_actual), "%s(%d)", filename, dup++);
                            }
                            snprintf(file_path, sizeof(file_path), "%s\\%s", folder, active_upload_actual);
                        }
                    } else {
                        snprintf(file_path, sizeof(file_path), "%s\\%s", folder, active_upload_actual);
                    }

                    char* cbuf = (char*)malloc(chunk_size > 0 ? chunk_size : 1);
                    int r = 0, total_read = 0;
                    while (total_read < chunk_size && (r = recv(client, cbuf + total_read, chunk_size - total_read, 0)) > 0) {
                        total_read += r;
                    }
                    FILE* f = fopen(file_path, chunk_idx == 0 ? "wb" : "ab");
                    if (f) {
                        if (total_read > 0) fwrite(cbuf, 1, total_read, f);
                        fclose(f);
                    }
                    free(cbuf);

                    if (chunk_idx == total_chunks - 1) {
                        char msg_id[64], att_body[512], pkt[8192];
                        GenerateUUID(msg_id);
                        snprintf(att_body, sizeof(att_body), "[Attachment: %s] (Click to download)", active_upload_actual);
                        SaveMessageRecord(session->user, target, msg_id, att_body);

                        int plen = snprintf(pkt, sizeof(pkt),
                            "<message from=\"%s\" to=\"%s\" id=\"%s\" status=\"1\"><body>%s</body></message>\n",
                            session->user, target, msg_id, att_body);

                        if (target[0] == '#') {
                            BroadcastToRoom(target, session->user, msg_id, att_body, INVALID_SOCKET);
                        } else {
                            RouteLivePacket(target, pkt, plen, INVALID_SOCKET);
                            if (CaseInsensitiveCompare(session->user, target) != 0) {
                                RouteLivePacket(session->user, pkt, plen, INVALID_SOCKET);
                            }
                        }
                    }
                }
            }
            else if (stanza.type == STANZA_FILE_GET) {
                char target[256], filename[256];
                if (sscanf(buf, "FILE_GET %255s %255s", target, filename) == 2) {
                    char folder[MAX_PATH], file_path[MAX_PATH];
                    GetChatFolder(session->user, target, folder);
                    snprintf(file_path, sizeof(file_path), "%s\\%s", folder, filename);

                    FILE* f = fopen(file_path, "rb");
                    if (f) {
                        fseek(f, 0, SEEK_END);
                        long fsize = ftell(f);
                        fseek(f, 0, SEEK_SET);

                        int chunk_size = 4096;
                        int total_chunks = (int)((fsize + chunk_size - 1) / chunk_size);
                        if (total_chunks == 0) total_chunks = 1;

                        for (int i = 0; i < total_chunks; i++) {
                            char cbuf[4096];
                            int r = (int)fread(cbuf, 1, chunk_size, f);
                            if (r < 0) r = 0;
                            char header[512];
                            int hlen = snprintf(header, sizeof(header), "FILE_DATA %s %d %d %d\n", filename, i, total_chunks, r);
                            SendAll(client, header, hlen);
                            if (r > 0) SendAll(client, cbuf, r);
                        }
                        fclose(f);
                    } else {
                        char pkt[512];
                        int plen = snprintf(pkt, sizeof(pkt), "<message from=\"Server\" to=\"%s\"><body>Error: Attachment %s not found on server.</body></message>\n", session->user, filename);
                        SendAll(client, pkt, plen);
                    }
                }
            }
        }
    }

    session->presence = PRESENCE_OFFLINE;
    BroadcastPresence(session);

    EnterCriticalSection(&g_rooms_cs);
    for (int i = 0; i < g_room_count; i++) {
        for (int j = 0; j < g_rooms[i].member_count; j++) {
            if (g_rooms[i].member_socks[j] == client) {
                g_rooms[i].member_socks[j] = INVALID_SOCKET;
            }
        }
    }
    LeaveCriticalSection(&g_rooms_cs);

    EnterCriticalSection(&g_clients_cs);
    ClientSession** curr = &g_clients;
    while (*curr) {
        if (*curr == session) { *curr = session->next; break; }
        curr = &(*curr)->next;
    }
    LeaveCriticalSection(&g_clients_cs);

    closesocket(client);
    free(session);
    return 0;
}
static DWORD WINAPI ServerWorker(LPVOID lpParam) {
    WSADATA wsa;
    struct sockaddr_in serv = {0};
    int opt = 1;
    (void)lpParam;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;
    
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = INADDR_ANY;
    serv.sin_port = htons((u_short)g_state.port);
    g_state.listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    setsockopt(g_state.listen_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    if (bind(g_state.listen_socket, (struct sockaddr*)&serv, sizeof(serv)) == SOCKET_ERROR) {
        WSACleanup();
        return 1;
    }
    listen(g_state.listen_socket, SOMAXCONN);
    
    while (g_state.running) {
        struct sockaddr_in cli;
        int csize = sizeof(cli);
        SOCKET client = accept(g_state.listen_socket, (struct sockaddr*)&cli, &csize);
        if (client != INVALID_SOCKET) {
            HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HandleClient, (LPVOID)(SIZE_T)(UINT_PTR)client, 0, NULL);
            if (th) CloseHandle(th);
        } else if (g_state.running) {
            Sleep(50);
        }
    }
    if (g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
    WSACleanup();
    g_state.running = FALSE;
    if (g_state.settings_hwnd) PostMessage(g_state.settings_hwnd, WM_PORT_UPDATE, 0, 0);
    return 0;
}

static void PopulateUserList(HWND listbox) {
    SendMessageA(listbox, LB_RESETCONTENT, 0, 0);
    if (GetINIPath()) {
        WCHAR keys[4096];
        DWORD size = GetPrivateProfileSectionW(L"Users", keys, 4096, g_ini_path);
        WCHAR* p = keys;
        while (*p) {
            WCHAR* eq = wcschr(p, L'=');
            if (eq) {
                *eq = L'\0';
                char uname[256];
                WideCharToMultiByte(CP_UTF8, 0, p, -1, uname, 256, NULL, NULL);
                SendMessageA(listbox, LB_ADDSTRING, 0, (LPARAM)uname);
            }
            p += wcslen(p) + 1;
        }
    }
}

LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = GetModuleHandle(NULL);
            g_state.font_ui = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            
            CreateWindowA("STATIC", "Server Port:", WS_CHILD | WS_VISIBLE, 15, 18, 90, 20, hwnd, NULL, hInst, NULL);
            char port_s[16]; sprintf(port_s, "%d", g_state.port);
            g_state.edit_port = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", port_s, WS_CHILD | WS_VISIBLE | ES_NUMBER, 110, 15, 80, 24, hwnd, (HMENU)ID_EDIT_PORT, hInst, NULL);

            g_state.btn_startstop = CreateWindowA("BUTTON", "", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 205, 15, 100, 26, hwnd, (HMENU)ID_BTN_STARTSTOP, hInst, NULL);

            CreateWindowA("STATIC", "Registered Users:", WS_CHILD | WS_VISIBLE, 15, 50, 150, 20, hwnd, NULL, hInst, NULL);
            g_state.list_users = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "", WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL, 15, 72, 290, 120, hwnd, (HMENU)ID_LIST_USERS, hInst, NULL);

            CreateWindowA("STATIC", "Username:", WS_CHILD | WS_VISIBLE, 15, 203, 90, 20, hwnd, NULL, hInst, NULL);
            g_state.edit_username = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 200, 195, 24, hwnd, (HMENU)ID_EDIT_USER, hInst, NULL);

            CreateWindowA("STATIC", "Password:", WS_CHILD | WS_VISIBLE, 15, 235, 90, 20, hwnd, NULL, hInst, NULL);
            g_state.edit_password = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 110, 232, 195, 24, hwnd, (HMENU)ID_EDIT_PASS, hInst, NULL);

            CreateWindowA("STATIC", "Full Name:", WS_CHILD | WS_VISIBLE, 15, 267, 90, 20, hwnd, NULL, hInst, NULL);
            g_state.edit_fullname = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 264, 195, 24, hwnd, (HMENU)ID_EDIT_FULLNAME, hInst, NULL);

            CreateWindowA("STATIC", "Email:", WS_CHILD | WS_VISIBLE, 15, 299, 90, 20, hwnd, NULL, hInst, NULL);
            g_state.edit_email = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 296, 195, 24, hwnd, (HMENU)ID_EDIT_EMAIL, hInst, NULL);

            g_state.chk_moderator = CreateWindowA("BUTTON", "Moderator (Create Rooms & Kick)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 110, 326, 200, 24, hwnd, (HMENU)ID_CHK_MOD, hInst, NULL);

            CreateWindowA("BUTTON", "Add / Update", WS_CHILD | WS_VISIBLE, 15, 358, 140, 30, hwnd, (HMENU)ID_BTN_ADDUSER, hInst, NULL);
            CreateWindowA("BUTTON", "Delete User", WS_CHILD | WS_VISIBLE, 165, 358, 140, 30, hwnd, (HMENU)ID_BTN_DELUSER, hInst, NULL);

            HWND child = GetWindow(hwnd, GW_CHILD);
            while (child) {
                SendMessage(child, WM_SETFONT, (WPARAM)g_state.font_ui, TRUE);
                child = GetWindow(child, GW_HWNDNEXT);
            }
            PopulateUserList(g_state.list_users);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == ID_LIST_USERS && HIWORD(wp) == LBN_SELCHANGE) {
                int idx = (int)SendMessage(g_state.list_users, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char buf[256];
                    SendMessageA(g_state.list_users, LB_GETTEXT, idx, (LPARAM)buf);
                    char* space = strchr(buf, ' '); 
                    if (space) *space = '\0';
                    SetWindowTextA(g_state.edit_username, buf);
                    SetWindowTextA(g_state.edit_password, "");

                    SendMessage(g_state.chk_moderator, BM_SETCHECK, IsUserModerator(buf) ? BST_CHECKED : BST_UNCHECKED, 0);

                    WCHAR w_user[256], w_vcard[512] = {0};
                    MultiByteToWideChar(CP_UTF8, 0, buf, -1, w_user, 256);
                    GetPrivateProfileStringW(L"VCards", w_user, L"", w_vcard, 512, g_ini_path);
                    char vcard[512] = "";
                    WideCharToMultiByte(CP_UTF8, 0, w_vcard, -1, vcard, 512, NULL, NULL);
                    char* pipe = strchr(vcard, '|');
                    if (pipe) {
                        *pipe = '\0';
                        SetWindowTextA(g_state.edit_fullname, vcard);
                        SetWindowTextA(g_state.edit_email, pipe + 1);
                    } else {
                        SetWindowTextA(g_state.edit_fullname, vcard);
                        SetWindowTextA(g_state.edit_email, "");
                    }
                }
            } else if (LOWORD(wp) == ID_EDIT_PORT && HIWORD(wp) == EN_CHANGE) {
                KillTimer(hwnd, TIMER_PORT_DELAY);
                SetTimer(hwnd, TIMER_PORT_DELAY, 1000, NULL);
            } else if (LOWORD(wp) == ID_BTN_STARTSTOP && HIWORD(wp) == BN_CLICKED) {
                g_state.running = !g_state.running;
                if (g_state.running) {
                    CreateThread(NULL, 0, ServerWorker, NULL, 0, NULL);
                } else {
                    if (g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
                }
                InvalidateRect(g_state.btn_startstop, NULL, TRUE);
            } else if (LOWORD(wp) == ID_BTN_ADDUSER && HIWORD(wp) == BN_CLICKED) {
                char user[256] = {0}, newp[256] = {0}, fname[256] = {0}, email[256] = {0};
                GetWindowTextA(g_state.edit_username, user, 256);
                GetWindowTextA(g_state.edit_password, newp, 256);
                GetWindowTextA(g_state.edit_fullname, fname, 256);
                GetWindowTextA(g_state.edit_email, email, 256);
                BOOL is_mod = (SendMessage(g_state.chk_moderator, BM_GETCHECK, 0, 0) == BST_CHECKED);

                TrimString(user);
                TrimString(newp);
                TrimString(fname);
                TrimString(email);

                if (strlen(user) > 0 && GetINIPath()) {
                    WCHAR w_user[256], w_val[512], w_vcard[512];
                    MultiByteToWideChar(CP_UTF8, 0, user, -1, w_user, 256);

                    WCHAR existing_pw[512] = {0};
                    GetPrivateProfileStringW(L"Users", w_user, L"", existing_pw, 512, g_ini_path);
                    if (strlen(newp) > 0 || wcslen(existing_pw) == 0) {
                        char hash[128];
                        ComputeSaltedHash(strlen(newp) > 0 ? newp : "password", "salty", hash);
                        swprintf_s(w_val, 512, L"salty:%hs", hash);
                        WritePrivateProfileStringW(L"Users", w_user, w_val, g_ini_path);
                    }

                    WritePrivateProfileStringW(L"Permissions", w_user, is_mod ? L"moderator" : L"user", g_ini_path);

                    char vcard_comb[512];
                    snprintf(vcard_comb, sizeof(vcard_comb), "%s|%s", fname, email);
                    MultiByteToWideChar(CP_UTF8, 0, vcard_comb, -1, w_vcard, 512);
                    WritePrivateProfileStringW(L"VCards", w_user, w_vcard, g_ini_path);

                    PopulateUserList(g_state.list_users);
                    SetWindowTextA(g_state.edit_password, "");
                }
            } else if (LOWORD(wp) == ID_BTN_DELUSER && HIWORD(wp) == BN_CLICKED) {
                char user[256] = {0};
                GetWindowTextA(g_state.edit_username, user, 256);
                TrimString(user);
                if (strlen(user) > 0 && CaseInsensitiveCompare(user, "admin") != 0 && GetINIPath()) {
                    WCHAR w_user[256];
                    MultiByteToWideChar(CP_UTF8, 0, user, -1, w_user, 256);
                    WritePrivateProfileStringW(L"Users", w_user, NULL, g_ini_path);
                    WritePrivateProfileStringW(L"Permissions", w_user, NULL, g_ini_path);
                    WritePrivateProfileStringW(L"VCards", w_user, NULL, g_ini_path);

                    EnterCriticalSection(&g_rooms_cs);
                    for (int i = 0; i < g_room_count; i++) {
                        for (int j = 0; j < g_rooms[i].member_count; j++) {
                            if (CaseInsensitiveCompare(g_rooms[i].member_names[j], user) == 0) {
                                g_rooms[i].member_socks[j] = g_rooms[i].member_socks[g_rooms[i].member_count - 1];
                                strcpy(g_rooms[i].member_names[j], g_rooms[i].member_names[g_rooms[i].member_count - 1]);
                                g_rooms[i].member_count--;
                                j--;
                            }
                        }
                        SaveRoomToINI(&g_rooms[i]);
                    }
                    LeaveCriticalSection(&g_rooms_cs);

                    PopulateUserList(g_state.list_users);
                    SetWindowTextA(g_state.edit_username, "");
                    SetWindowTextA(g_state.edit_password, "");
                    SetWindowTextA(g_state.edit_fullname, "");
                    SetWindowTextA(g_state.edit_email, "");
                    SendMessage(g_state.chk_moderator, BM_SETCHECK, BST_UNCHECKED, 0);
                }
            }
            break;
        case WM_TIMER:
            if (wp == TIMER_PORT_DELAY) {
                char buf[16];
                int np;
                GetWindowTextA(g_state.edit_port, buf, sizeof(buf));
                np = atoi(buf);
                if (np >= 1 && np <= 65535 && np != g_state.port) {
                    g_state.port = np;
                    SaveSettings();
                }
                KillTimer(hwnd, TIMER_PORT_DELAY);
            }
            break;
        case WM_PORT_UPDATE:
            InvalidateRect(g_state.btn_startstop, NULL, TRUE);
            break;
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lp;
            if (dis && dis->CtlID == ID_BTN_STARTSTOP) {
                HBRUSH bg = g_state.running ? g_state.green_brush : g_state.gray_brush;
                HPEN pen = CreatePen(PS_SOLID, 2, g_state.running ? RGB(0,150,0) : RGB(150,150,150));
                HGDIOBJ oldp = SelectObject(dis->hDC, pen);
                HGDIOBJ oldb = SelectObject(dis->hDC, bg);
                RoundRect(dis->hDC, dis->rcItem.left, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom, 8, 8);
                SelectObject(dis->hDC, oldb);
                SelectObject(dis->hDC, oldp);
                DeleteObject(pen);
                HGDIOBJ oldf = SelectObject(dis->hDC, g_state.font_ui);
                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, RGB(255,255,255));
                RECT trc = dis->rcItem;
                DrawTextA(dis->hDC, g_state.running ? "Running" : "Stopped", -1, &trc, DT_CENTER|DT_VCENTER|DT_SINGLELINE);
                SelectObject(dis->hDC, oldf);
                return TRUE;
            }
            break;
        }
        case WM_SYSCOMMAND:
            if ((wp & 0xFFF0) == SC_MINIMIZE) {
                ShowWindow(hwnd, SW_HIDE);
                return 0;
            }
            break;
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case WM_DESTROY:
            g_state.settings_hwnd = NULL;
            return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    static NOTIFYICONDATAA nid;

    switch (msg) {
        case WM_CREATE:
            g_state.green_brush = CreateSolidBrush(RGB(52, 199, 89));
            g_state.gray_brush = CreateSolidBrush(RGB(142, 142, 147));
            LoadSettings();

            {
                WNDCLASSA wc = {0};
                wc.lpfnWndProc = SettingsWndProc;
                wc.hInstance = GetModuleHandle(NULL);
                wc.hCursor = LoadCursor(NULL, IDC_ARROW);
                wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
                wc.lpszClassName = "ChatSettingsClass";
                RegisterClassA(&wc);

                // Increased window height from 380 to 430 to prevent controls from being cut off
                g_state.settings_hwnd = CreateWindowExA(0, "ChatSettingsClass", "Chat Server Settings",
                    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                    CW_USEDEFAULT, CW_USEDEFAULT, 335, 430, hwnd, NULL, GetModuleHandle(NULL), NULL);
            }

            memset(&nid, 0, sizeof(NOTIFYICONDATAA));
            nid.cbSize = sizeof(NOTIFYICONDATAA);
            nid.hWnd = hwnd;
            nid.uID = ID_TRAY_APP_ICON;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
            strcpy(nid.szTip, "Chat Server");
            Shell_NotifyIconA(NIM_ADD, &nid);

            g_state.running = TRUE;
            CreateThread(NULL, 0, ServerWorker, NULL, 0, NULL);
            return 0;

        case WM_TRAYICON:
            if (lp == WM_LBUTTONUP || lp == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                
                HMENU hMenu = CreatePopupMenu();
                // Moved "Server Running" toggle to the top of the tray menu
                AppendMenuA(hMenu, MF_STRING, ID_TRAY_TOGGLE_RUN, "Server Running");
                AppendMenuA(hMenu, MF_STRING, ID_TRAY_SHOW, "Show Settings");
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit Server");
                
                CheckMenuItem(hMenu, ID_TRAY_TOGGLE_RUN, MF_BYCOMMAND | (g_state.running ? MF_CHECKED : MF_UNCHECKED));

                TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
            return 0;

        case WM_COMMAND:
            if (LOWORD(wp) == ID_TRAY_SHOW) {
                ShowWindow(g_state.settings_hwnd, SW_RESTORE);
                SetForegroundWindow(g_state.settings_hwnd);
            } else if (LOWORD(wp) == ID_TRAY_TOGGLE_RUN) {
                g_state.running = !g_state.running;
                if (g_state.running) {
                    CreateThread(NULL, 0, ServerWorker, NULL, 0, NULL);
                } else {
                    if (g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
                }
                if (g_state.settings_hwnd) {
                    InvalidateRect(g_state.btn_startstop, NULL, TRUE);
                }
            } else if (LOWORD(wp) == ID_TRAY_EXIT) {
                PostMessage(hwnd, WM_CLOSE, 0, 0);
            }
            return 0;

        case WM_DESTROY:
            Shell_NotifyIconA(NIM_DELETE, &nid);
            g_state.running = FALSE;
            if (g_state.listen_socket != INVALID_SOCKET) closesocket(g_state.listen_socket);
            if (g_state.green_brush) DeleteObject(g_state.green_brush);
            if (g_state.gray_brush) DeleteObject(g_state.gray_brush);
            if (g_state.font_ui) DeleteObject(g_state.font_ui);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wp, lp);
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    InitializeCriticalSection(&g_clients_cs);
    InitializeCriticalSection(&g_rooms_cs);

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "ChatServerMainClass";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(0, "ChatServerMainClass", "Chat Server Host",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 250, 100, NULL, NULL, hInstance, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DeleteCriticalSection(&g_clients_cs);
    DeleteCriticalSection(&g_rooms_cs);
    return (int)msg.wParam;
}