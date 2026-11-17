 /* ============================================================================
 * Enterprise Chat Client - Win32 UI + XMPP / Binary Chat Protocol
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
#define WM_PORT_UPDATE (WM_USER + 101)
#define ID_BTN_STARTSTOP 1001
#define ID_BTN_CLOSE     1002
#define ID_BTN_ADDUSER   1003
#define ID_LIST_USERS    1004
#define ID_EDIT_PORT     1005
#define ID_EDIT_USER     1006
#define ID_EDIT_PASS     1007
#define TIMER_PORT_DELAY 2001
#define WM_TRAYICON (WM_USER + 102)
#define ID_TRAY_APP_ICON 5000
#define ID_TRAY_SHOW 5001
#define ID_TRAY_EXIT 5002
#define ID_TRAY_TOGGLE_RUN 5003
typedef enum {
    PRESENCE_OFFLINE = 0,
    PRESENCE_ONLINE = 1,
    PRESENCE_AWAY = 2
} UserPresenceState;

typedef enum {
    ST_UNKNOWN = 0,
    ST_AUTH,
    ST_MESSAGE,
    ST_PRESENCE,
    ST_JOIN_ROOM,
    ST_MUTATE,
    ST_FILE_CHUNK,
    ST_FILE_GET,
    ST_SEARCH,
    ST_INVITE
} StanzaType;

typedef struct {
    StanzaType type;
    char from[256];
    char to[256];
    char id[64];
    char body[4096];
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
// Later in the globals block...
static ChatRoom g_rooms[64];  
static int g_room_count = 0;
static CRITICAL_SECTION g_rooms_cs;
static WCHAR g_ini_path[MAX_PATH] = {0};

// Forward Declarations
static DWORD WINAPI ServerWorker(LPVOID lpParam);
LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

static int CaseInsensitiveCompare(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return *a - *b;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
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

    // Changed PROV_RSA_FULL to PROV_RSA_AES
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
        }
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

static void SendAll(SOCKET s, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, data + sent, len - sent, 0);
        if (r <= 0) break;
        sent += r;
    }
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

static void SaveMessageRecord(const char* sender, const char* target, const char* msg_id, const char* body) {
    char folder[MAX_PATH];
    GetChatFolder(sender, target, folder);

    char file_path[MAX_PATH];
    snprintf(file_path, sizeof(file_path), "%s\\history.txt", folder);
    
    FILE* f = fopen(file_path, "ab");
    if (f) {
        fprintf(f, "<message from=\"%s\" to=\"%s\" id=\"%s\"><body>%s</body></message>\n", sender, target, msg_id, body);
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
    (void)client; (void)username;
}

static void HandleJoinRoom(ClientSession* session, const char* room_jid) {
    EnterCriticalSection(&g_rooms_cs);
    ChatRoom* room = NULL;
    for (int i = 0; i < g_room_count; i++) {
        if (CaseInsensitiveCompare(g_rooms[i].room_jid, room_jid) == 0) {
            room = &g_rooms[i];
            break;
        }
    }
    if (!room && g_room_count < 32) {
        room = &g_rooms[g_room_count++];
        strcpy(room->room_jid, room_jid);
        room->member_count = 0;
    }
    if (room) {
        BOOL already_in = FALSE;
        for (int j = 0; j < room->member_count; j++) {
            if (room->member_socks[j] == session->sock) {
                already_in = TRUE;
                break;
            }
        }
        if (!already_in && room->member_count < 64) {
            room->member_socks[room->member_count] = session->sock;
            strcpy(room->member_names[room->member_count], session->user);
            room->member_count++;
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
        stanza->type = ST_AUTH;
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
        stanza->type = ST_MESSAGE;
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
        stanza->type = ST_PRESENCE;
        char* show = strstr(line, "<show>");
        if (show) sscanf(show, "<show>%d</show>", &stanza->int_val);
        stanza->presence = (UserPresenceState)stanza->int_val;
        return TRUE;
    }
    if (strstr(line, "<join")) {
        stanza->type = ST_JOIN_ROOM;
        char* room_ptr = strstr(line, "room=\"");
        if (room_ptr) sscanf(room_ptr, "room=\"%255[^\"]\"", stanza->to);
        return TRUE;
    }
    if (strstr(line, "<mutate")) {
        stanza->type = ST_MUTATE;
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
    if (strncmp(line, "FILE_CHUNK ", 11) == 0) {
        stanza->type = ST_FILE_CHUNK;
        return TRUE;
    }
    if (strncmp(line, "FILE_GET ", 9) == 0) {
        stanza->type = ST_FILE_GET;
        return TRUE;
    }
    if (strstr(line, "jabber:iq:search")) {
        stanza->type = ST_SEARCH;
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
        stanza->type = ST_INVITE;
        char* to_ptr = strstr(line, "to=\"");
        if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", stanza->to);
        char* room_ptr = strstr(line, "room=\"");
        if (room_ptr) sscanf(room_ptr, "room=\"%255[^\"]\"", stanza->body);
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
    send(client, greeting, (int)strlen(greeting), 0);

    while (ReadLine(client, buf, sizeof(buf)) >= 0) {
        XMPPStanza stanza;
        if (ParseStanza(buf, &stanza)) {
            if (stanza.type == ST_AUTH) {
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
                                send(client, succ, (int)strlen(succ), 0);
                                
                                FlushOfflineQueue(client, session->user);
                                BroadcastPresence(session);
                                continue;
                            }
                        }
                    }
                }
                const char* fail = "<failure/><not-authorized/>\n";
                send(client, fail, (int)strlen(fail), 0);
            }
            else if (!session->authenticated) {
                const char* err = "<stream:error><not-authorized/></stream:error>\n";
                send(client, err, (int)strlen(err), 0);
            }
            else if (stanza.type == ST_MESSAGE) {
                char msg_id[64];
                if (strlen(stanza.id) == 0) GenerateUUID(msg_id);
                else strncpy(msg_id, stanza.id, 63);

                SaveMessageRecord(session->user, stanza.to, msg_id, stanza.body);

                char pkt[8192];
                int plen = snprintf(pkt, sizeof(pkt), 
                    "<message from=\"%s\" to=\"%s\" id=\"%s\"><body>%s</body></message>\n",
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
            else if (stanza.type == ST_PRESENCE) {
                session->presence = stanza.presence;
                BroadcastPresence(session);
            }
            else if (stanza.type == ST_JOIN_ROOM) {
                if (stanza.to[0] == '#') {
                    HandleJoinRoom(session, stanza.to);
                }
                SendChatHistory(session->sock, session->user, stanza.to);
            }
            else if (stanza.type == ST_MUTATE) {
                MutateMessage(session->user, stanza.to, stanza.id, stanza.int_val, stanza.body);
            }
            else if (stanza.type == ST_INVITE) {
                TrimString(stanza.to);
                TrimString(stanza.body);
                if (strlen(stanza.to) > 0 && strlen(stanza.body) > 0) {
                    char room_name[256];
                    if (stanza.body[0] != '#') snprintf(room_name, sizeof(room_name), "#%s", stanza.body);
                    else strncpy(room_name, stanza.body, sizeof(room_name) - 1);

                    // Add all online sessions of target user to the room
                    EnterCriticalSection(&g_clients_cs);
                    ClientSession* curr = g_clients;
                    while (curr) {
                        if (curr->authenticated && CaseInsensitiveCompare(curr->user, stanza.to) == 0) {
                            HandleJoinRoom(curr, room_name);
                        }
                        curr = curr->next;
                    }
                    LeaveCriticalSection(&g_clients_cs);

                    // Record a system notice in the room history
                    char msg_id[64], notice[512];
                    GenerateUUID(msg_id);
                    snprintf(notice, sizeof(notice), "%s added %s to %s", session->user, stanza.to, room_name);
                    SaveMessageRecord("Server", room_name, msg_id, notice);

                    // Send explicit invite packet to target user so their client adds the room & alerts them
                    char inv_pkt[1024];
                    int ilen = snprintf(inv_pkt, sizeof(inv_pkt),
                        "<message from=\"Server\" to=\"%s\" id=\"invite_notify\" room=\"%s\"><body>You have been added to %s by %s.</body></message>\n",
                        stanza.to, room_name, room_name, session->user);
                    RouteLivePacket(stanza.to, inv_pkt, ilen, INVALID_SOCKET);

                    // Broadcast notice to everyone in the room (including the inviter)
                    BroadcastToRoom(room_name, "Server", msg_id, notice, INVALID_SOCKET);
                }
            }
            else if (stanza.type == ST_SEARCH) {
                char search_query[256];
                strncpy(search_query, stanza.body, 255);
                search_query[255] = '\0';
                TrimString(search_query);

                char results[4096] = "Directory Search Results:\n";
                int found = 0;
                
                if (GetINIPath()) {
                    WCHAR keys[4096];
                    GetPrivateProfileSectionW(L"Users", keys, 4096, g_ini_path);
                    WCHAR* p = keys;
                    while (*p) {
                        WCHAR* eq = wcschr(p, L'=');
                        if (eq) {
                            *eq = L'\0';
                            char uname[256];
                            WideCharToMultiByte(CP_UTF8, 0, p, -1, uname, 256, NULL, NULL);
                            if (strlen(search_query) == 0 || StrStrIA(uname, search_query)) {
                                strcat(results, "- ");
                                strcat(results, uname);
                                strcat(results, "\n");
                                found++;
                            }
                        }
                        p += wcslen(p) + 1;
                    }
                }
                
                if (found == 0) strcat(results, "No users matched your query.");
                
                char pkt[8192];
                int plen = snprintf(pkt, sizeof(pkt), "<message from=\"Server\" to=\"%s\" id=\"search_res\"><body>%s</body></message>\n", session->user, results);
                send(client, pkt, plen, 0);
            }
            else if (stanza.type == ST_FILE_CHUNK) {
                char target[256], filename[256];
                int chunk_idx, total_chunks, chunk_size;
                if (sscanf(buf, "FILE_CHUNK %255s %255s %d %d %d", target, filename, &chunk_idx, &total_chunks, &chunk_size) == 5) {
                    char folder[MAX_PATH], file_path[MAX_PATH];
                    GetChatFolder(session->user, target, folder);

                    if (chunk_idx == 0 || strcmp(filename, active_upload_orig) != 0) {
                        strncpy(active_upload_orig, filename, 255);
                        strncpy(active_upload_actual, filename, 255);
                        snprintf(file_path, sizeof(file_path), "%s\\%s", folder, active_upload_actual);

                        // Prevent overwriting duplicate filenames
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

                    char* cbuf = (char*)malloc(chunk_size);
                    int r = 0, total_read = 0;
                    while (total_read < chunk_size && (r = recv(client, cbuf + total_read, chunk_size - total_read, 0)) > 0) {
                        total_read += r;
                    }
                    FILE* f = fopen(file_path, chunk_idx == 0 ? "wb" : "ab");
                    if (f) {
                        fwrite(cbuf, 1, total_read, f);
                        fclose(f);
                    }
                    free(cbuf);

                    // When the final chunk completes, broadcast the clickable attachment message
                    if (chunk_idx == total_chunks - 1) {
                        char msg_id[64], att_body[512], pkt[8192];
                        GenerateUUID(msg_id);
                        snprintf(att_body, sizeof(att_body), "[Attachment: %s] (Click to download)", active_upload_actual);
                        SaveMessageRecord(session->user, target, msg_id, att_body);

                        int plen = snprintf(pkt, sizeof(pkt),
                            "<message from=\"%s\" to=\"%s\" id=\"%s\"><body>%s</body></message>\n",
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
            else if (stanza.type == ST_FILE_GET) {
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
                        send(client, pkt, plen, 0);
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
                g_rooms[i].member_socks[j] = g_rooms[i].member_socks[--g_rooms[i].member_count];
                break;
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

            CreateWindowA("STATIC", "Registered Users:", WS_CHILD | WS_VISIBLE, 15, 55, 150, 20, hwnd, NULL, hInst, NULL);
            g_state.list_users = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "", WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL, 15, 80, 290, 140, hwnd, (HMENU)ID_LIST_USERS, hInst, NULL);

            CreateWindowA("STATIC", "Username:", WS_CHILD | WS_VISIBLE, 15, 233, 90, 20, hwnd, NULL, hInst, NULL);
            g_state.edit_username = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 230, 195, 24, hwnd, (HMENU)ID_EDIT_USER, hInst, NULL);

            CreateWindowA("STATIC", "Password:", WS_CHILD | WS_VISIBLE, 15, 268, 90, 20, hwnd, NULL, hInst, NULL);
            g_state.edit_password = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 110, 265, 195, 24, hwnd, (HMENU)ID_EDIT_PASS, hInst, NULL);

            CreateWindowA("BUTTON", "Add / Update User", WS_CHILD | WS_VISIBLE, 110, 300, 195, 30, hwnd, (HMENU)ID_BTN_ADDUSER, hInst, NULL);

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
                char user[256] = {0}, newp[256] = {0};
                GetWindowTextA(g_state.edit_username, user, 256);
                GetWindowTextA(g_state.edit_password, newp, 256);
                TrimString(user);
                TrimString(newp);
                if (strlen(user) > 0 && strlen(newp) > 0 && GetINIPath()) {
                    WCHAR w_user[256], w_val[512];
                    char hash[128];
                    MultiByteToWideChar(CP_UTF8, 0, user, -1, w_user, 256);
                    ComputeSaltedHash(newp, "salty", hash);
                    swprintf_s(w_val, 512, L"salty:%hs", hash);
                    WritePrivateProfileStringW(L"Users", w_user, w_val, g_ini_path);
                    PopulateUserList(g_state.list_users);
                    SetWindowTextA(g_state.edit_username, "");
                    SetWindowTextA(g_state.edit_password, "");
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
                return 0; // Hides to tray instead of taskbar
            }
            break;
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0; // Hides to tray on X
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

                g_state.settings_hwnd = CreateWindowExA(0, "ChatSettingsClass", "Chat Server Settings",
                    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                    CW_USEDEFAULT, CW_USEDEFAULT, 335, 380, hwnd, NULL, GetModuleHandle(NULL), NULL);
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
            // Settings window remains hidden on startup, opened only via tray menu
            return 0;

        case WM_TRAYICON:
            if (lp == WM_LBUTTONUP || lp == WM_RBUTTONUP) {
                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                
                HMENU hMenu = CreatePopupMenu();
                AppendMenuA(hMenu, MF_STRING, ID_TRAY_SHOW, "Show Settings");
                AppendMenuA(hMenu, MF_STRING, ID_TRAY_TOGGLE_RUN, "Server Running");
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