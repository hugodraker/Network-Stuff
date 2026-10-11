//DLNA Server
//gcc dlna_server.c -o dlna_server.exe -lws2_32 -lshell32 -lole32 -lgdi32 -mwindows
//2026-10-11 Hugo
//Released into the Public Domain

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

/* --------------------------------------------------------------------------
 * GUI Constants & Control IDs (from SMB1 Server GUI)
 * -------------------------------------------------------------------------- */
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
#define IDB_DEL_SHARE       2011

/* --------------------------------------------------------------------------
 * DLNA / UPnP Constants
 * -------------------------------------------------------------------------- */
#define SSDP_ADDR           "239.255.255.250"
#define SSDP_PORT           1900
#define DEFAULT_DLNA_PORT   8200
#define MAX_SHARES          16
#define LOG_BUF_SIZE        65536
#define SERVER_UUID         "uuid:4d696e69-444c-164e-9d41-57696e333200"

typedef struct {
    char name[64];
    char path[MAX_PATH];
} ServerShare;

/* --------------------------------------------------------------------------
 * Global State
 * -------------------------------------------------------------------------- */
static HWND             g_hMain          = NULL;
static HWND             g_hSettings      = NULL;
static HWND             g_hLogEdit       = NULL;
static HWND             g_hCmbShares     = NULL;
static HWND             g_hSharePath     = NULL;
static HINSTANCE        g_hInst          = NULL;
static NOTIFYICONDATAA  g_nid;
static char             g_ini_path[MAX_PATH];

static volatile int     g_server_running = 0;
static SOCKET           g_listen_socket  = INVALID_SOCKET;
static SOCKET           g_ssdp_socket    = INVALID_SOCKET;
static HANDLE           g_server_thread  = NULL;
static int              g_port           = DEFAULT_DLNA_PORT;
static uint32_t         g_system_update  = 1;

static char             g_log_buffer[LOG_BUF_SIZE];
static CRITICAL_SECTION g_cs_log;
static CRITICAL_SECTION g_cs_shares;

static ServerShare      g_shares[MAX_SHARES];
static int              g_share_count    = 0;

/* --------------------------------------------------------------------------
 * Logging & Utility Functions
 * -------------------------------------------------------------------------- */
static void server_log(const char *fmt, ...) {
    char msg[1024];
    char line[1152];
    SYSTEMTIME st;
    GetLocalTime(&st);

    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    snprintf(line, sizeof(line), "[%02d:%02d:%02d] %s\r\n",
             st.wHour, st.wMinute, st.wSecond, msg);

    EnterCriticalSection(&g_cs_log);
    size_t cur_len = strlen(g_log_buffer);
    size_t add_len = strlen(line);
    if (cur_len + add_len >= LOG_BUF_SIZE - 1) {
        size_t keep = LOG_BUF_SIZE / 2;
        memmove(g_log_buffer, g_log_buffer + (cur_len - keep), keep + 1);
        cur_len = strlen(g_log_buffer);
    }
    memcpy(g_log_buffer + cur_len, line, add_len + 1);
    LeaveCriticalSection(&g_cs_log);

    if (g_hLogEdit && IsWindow(g_hLogEdit)) {
        SetWindowTextA(g_hLogEdit, g_log_buffer);
        int total = GetWindowTextLengthA(g_hLogEdit);
        SendMessageA(g_hLogEdit, EM_SETSEL, (WPARAM)total, (LPARAM)total);
        SendMessageA(g_hLogEdit, EM_SCROLLCARET, 0, 0);
    }
}

static void FreePidl(LPITEMIDLIST pidl) {
    IMalloc *pMalloc = NULL;
    if (SUCCEEDED(SHGetMalloc(&pMalloc)) && pMalloc) {
        pMalloc->lpVtbl->Free(pMalloc, pidl);
        pMalloc->lpVtbl->Release(pMalloc);
    }
}

static void LoadConfig(void) {
    g_port = GetPrivateProfileIntA("Server", "Port", DEFAULT_DLNA_PORT, g_ini_path);
    if (g_port <= 0 || g_port > 65535) g_port = DEFAULT_DLNA_PORT;

    EnterCriticalSection(&g_cs_shares);
    g_share_count = GetPrivateProfileIntA("Shares", "Count", 0, g_ini_path);
    if (g_share_count > MAX_SHARES) g_share_count = MAX_SHARES;

    for (int i = 0; i < g_share_count; i++) {
        char key_n[32], key_p[32];
        snprintf(key_n, sizeof(key_n), "Name%d", i);
        snprintf(key_p, sizeof(key_p), "Path%d", i);
        GetPrivateProfileStringA("Shares", key_n, "", g_shares[i].name, sizeof(g_shares[i].name), g_ini_path);
        GetPrivateProfileStringA("Shares", key_p, "", g_shares[i].path, sizeof(g_shares[i].path), g_ini_path);
    }

    if (g_share_count == 0) {
        strcpy(g_shares[0].name, "Media");
        GetCurrentDirectoryA(MAX_PATH, g_shares[0].path);
        g_share_count = 1;
    }
    LeaveCriticalSection(&g_cs_shares);
}

static void SaveConfig(void) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%d", g_port);
    WritePrivateProfileStringA("Server", "Port", buf, g_ini_path);

    EnterCriticalSection(&g_cs_shares);
    snprintf(buf, sizeof(buf), "%d", g_share_count);
    WritePrivateProfileStringA("Shares", "Count", buf, g_ini_path);
    for (int i = 0; i < g_share_count; i++) {
        char key_n[32], key_p[32];
        snprintf(key_n, sizeof(key_n), "Name%d", i);
        snprintf(key_p, sizeof(key_p), "Path%d", i);
        WritePrivateProfileStringA("Shares", key_n, g_shares[i].name, g_ini_path);
        WritePrivateProfileStringA("Shares", key_p, g_shares[i].path, g_ini_path);
    }
    LeaveCriticalSection(&g_cs_shares);
}

/* --------------------------------------------------------------------------
 * ObjectID <-> Filesystem Path Mapping & XML Escaping
 * -------------------------------------------------------------------------- */
/*
 * ObjectID format:
 *   "0"               -> Root container
 *   "S0", "S1", ...   -> Top-level share g_shares[idx]
 *   "S0_<hex_relpath>"-> Subdirectory or media file inside g_shares[idx]
 */
static void bytes_to_hex(const char *in, char *out, size_t out_max) {
    static const char hex[] = "0123456789ABCDEF";
    size_t i = 0, j = 0;
    while (in[i] && (j + 2) < out_max) {
        unsigned char c = (unsigned char)in[i++];
        out[j++] = hex[(c >> 4) & 0x0F];
        out[j++] = hex[c & 0x0F];
    }
    out[j] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void hex_to_bytes(const char *in, char *out, size_t out_max) {
    size_t i = 0, j = 0;
    while (in[i] && in[i + 1] && (j + 1) < out_max) {
        int hi = hex_val(in[i]);
        int lo = hex_val(in[i + 1]);
        if (hi < 0 || lo < 0) break;
        out[j++] = (char)((hi << 4) | lo);
        i += 2;
    }
    out[j] = '\0';
}

static void build_object_id(int share_idx, const char *rel_path, char *out_id, size_t out_max) {
    if (!rel_path || !rel_path[0]) {
        snprintf(out_id, out_max, "S%d", share_idx);
    } else {
        char hex[MAX_PATH * 2 + 4];
        bytes_to_hex(rel_path, hex, sizeof(hex));
        snprintf(out_id, out_max, "S%d_%s", share_idx, hex);
    }
}

/* Resolves an ObjectID into its share index, relative path, and full disk path */
static int resolve_object_id(const char *obj_id, int *out_share_idx,
                             char *out_rel, size_t rel_max,
                             char *out_full, size_t full_max,
                             char *out_title, size_t title_max,
                             char *out_parent_id, size_t parent_max) {
    if (!obj_id || strcmp(obj_id, "0") == 0) {
        if (out_share_idx) *out_share_idx = -1;
        if (out_rel) out_rel[0] = '\0';
        if (out_full) out_full[0] = '\0';
        if (out_title) snprintf(out_title, title_max, "Root");
        if (out_parent_id) snprintf(out_parent_id, parent_max, "-1");
        return 1;
    }

    if (obj_id[0] != 'S') return 0;
    int idx = atoi(obj_id + 1);

    EnterCriticalSection(&g_cs_shares);
    if (idx < 0 || idx >= g_share_count) {
        LeaveCriticalSection(&g_cs_shares);
        return 0;
    }
    char base_path[MAX_PATH];
    char share_name[64];
    strncpy(base_path, g_shares[idx].path, sizeof(base_path) - 1);
    base_path[sizeof(base_path) - 1] = '\0';
    strncpy(share_name, g_shares[idx].name, sizeof(share_name) - 1);
    share_name[sizeof(share_name) - 1] = '\0';
    LeaveCriticalSection(&g_cs_shares);

    /* Strip trailing backslash on base_path */
    size_t blen = strlen(base_path);
    while (blen > 3 && (base_path[blen - 1] == '\\' || base_path[blen - 1] == '/')) {
        base_path[--blen] = '\0';
    }

    char rel[MAX_PATH] = {0};
    const char *underscore = strchr(obj_id, '_');
    if (underscore && *(underscore + 1)) {
        hex_to_bytes(underscore + 1, rel, sizeof(rel));
        if (strstr(rel, "..")) return 0; /* Block directory traversal */
    }

    if (out_share_idx) *out_share_idx = idx;
    if (out_rel) snprintf(out_rel, rel_max, "%s", rel);

    if (!rel[0]) {
        if (out_full) snprintf(out_full, full_max, "%s", base_path);
        if (out_title) snprintf(out_title, title_max, "%s", share_name);
        if (out_parent_id) snprintf(out_parent_id, parent_max, "0");
    } else {
        if (out_full) snprintf(out_full, full_max, "%s\\%s", base_path, rel);
        const char *last_sep = strrchr(rel, '\\');
        if (out_title) snprintf(out_title, title_max, "%s", last_sep ? (last_sep + 1) : rel);
        if (out_parent_id) {
            if (!last_sep) {
                snprintf(out_parent_id, parent_max, "S%d", idx);
            } else {
                char parent_rel[MAX_PATH];
                size_t plen = (size_t)(last_sep - rel);
                if (plen >= sizeof(parent_rel)) plen = sizeof(parent_rel) - 1;
                memcpy(parent_rel, rel, plen);
                parent_rel[plen] = '\0';
                build_object_id(idx, parent_rel, out_parent_id, parent_max);
            }
        }
    }
    return 1;
}

/* Double-escapes text so it can sit inside XML-escaped DIDL-Lite inside SOAP */
static void append_didl_escaped(char **buf, size_t *cap, size_t *len, const char *raw) {
    for (size_t i = 0; raw[i]; i++) {
        const char *rep = NULL;
        char single[2] = { raw[i], '\0' };
        switch (raw[i]) {
            case '&':  rep = "&amp;amp;";  break;
            case '<':  rep = "&amp;lt;";   break;
            case '>':  rep = "&amp;gt;";   break;
            case '\"': rep = "&amp;quot;"; break;
            case '\'': rep = "&amp;apos;"; break;
            default:   rep = single;       break;
        }
        size_t rlen = strlen(rep);
        if (*len + rlen + 256 >= *cap) {
            *cap *= 2;
            *buf = (char *)realloc(*buf, *cap);
        }
        memcpy(*buf + *len, rep, rlen);
        *len += rlen;
        (*buf)[*len] = '\0';
    }
}

static void append_str(char **buf, size_t *cap, size_t *len, const char *fmt, ...) {
    char tmp[2048];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    if (n <= 0) return;

    if (*len + (size_t)n + 256 >= *cap) {
        while (*len + (size_t)n + 256 >= *cap) *cap *= 2;
        *buf = (char *)realloc(*buf, *cap);
    }
    memcpy(*buf + *len, tmp, (size_t)n);
    *len += (size_t)n;
    (*buf)[*len] = '\0';
}

/* --------------------------------------------------------------------------
 * Media Format Classification & DLNA Profile Mapping
 * -------------------------------------------------------------------------- */
static int get_media_profile(const char *filename, const char **out_mime,
                             const char **out_class, const char **out_pn) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return 0;
    ext++;

    if (_stricmp(ext, "mp4") == 0 || _stricmp(ext, "m4v") == 0 || _stricmp(ext, "mov") == 0) {
        *out_mime  = "video/mp4";
        *out_class = "object.item.videoItem";
        *out_pn    = "DLNA.ORG_PN=AVC_MP4_MP_SD_AAC_MULT5;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "mkv") == 0 || _stricmp(ext, "webm") == 0) {
        *out_mime  = "video/x-matroska";
        *out_class = "object.item.videoItem";
        *out_pn    = "DLNA.ORG_PN=MATROSKA;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "avi") == 0) {
        *out_mime  = "video/x-msvideo";
        *out_class = "object.item.videoItem";
        *out_pn    = "DLNA.ORG_PN=AVI;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "mpg") == 0 || _stricmp(ext, "mpeg") == 0 || _stricmp(ext, "ts") == 0) {
        *out_mime  = "video/mpeg";
        *out_class = "object.item.videoItem";
        *out_pn    = "DLNA.ORG_PN=MPEG_PS_NTSC;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "wmv") == 0) {
        *out_mime  = "video/x-ms-wmv";
        *out_class = "object.item.videoItem";
        *out_pn    = "DLNA.ORG_PN=WMVMED_FULL;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "mp3") == 0) {
        *out_mime  = "audio/mpeg";
        *out_class = "object.item.audioItem.musicTrack";
        *out_pn    = "DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "flac") == 0) {
        *out_mime  = "audio/flac";
        *out_class = "object.item.audioItem.musicTrack";
        *out_pn    = "DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "wav") == 0) {
        *out_mime  = "audio/wav";
        *out_class = "object.item.audioItem.musicTrack";
        *out_pn    = "DLNA.ORG_PN=LPCM;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "m4a") == 0 || _stricmp(ext, "aac") == 0) {
        *out_mime  = "audio/mp4";
        *out_class = "object.item.audioItem.musicTrack";
        *out_pn    = "DLNA.ORG_PN=AAC_ISO_320;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "jpg") == 0 || _stricmp(ext, "jpeg") == 0) {
        *out_mime  = "image/jpeg";
        *out_class = "object.item.imageItem.photo";
        *out_pn    = "DLNA.ORG_PN=JPEG_LRG;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=00f00000000000000000000000000000";
        return 1;
    }
    if (_stricmp(ext, "png") == 0) {
        *out_mime  = "image/png";
        *out_class = "object.item.imageItem.photo";
        *out_pn    = "DLNA.ORG_PN=PNG_LRG;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=00f00000000000000000000000000000";
        return 1;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Static UPnP / DLNA XML Descriptors
 * -------------------------------------------------------------------------- */
static const char ROOT_DESC_XML_FMT[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\" "
    "xmlns:dlna=\"urn:schemas-dlna-org:device-1-0\">\r\n"
    "  <specVersion><major>1</major><minor>0</minor></specVersion>\r\n"
    "  <device>\r\n"
    "    <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>\r\n"
    "    <friendlyName>Win32 DLNA Media Server (%s)</friendlyName>\r\n"
    "    <manufacturer>Custom Win32 Systems</manufacturer>\r\n"
    "    <modelName>Win32-DLNA-Server</modelName>\r\n"
    "    <modelNumber>1.0</modelNumber>\r\n"
    "    <UDN>" SERVER_UUID "</UDN>\r\n"
    "    <dlna:X_DLNADOC xmlns:dlna=\"urn:schemas-dlna-org:device-1-0\">DMS-1.50</dlna:X_DLNADOC>\r\n"
    "    <serviceList>\r\n"
    "      <service>\r\n"
    "        <serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType>\r\n"
    "        <serviceId>urn:upnp-org:serviceId:ContentDirectory</serviceId>\r\n"
    "        <SCPDURL>/cds_scpd.xml</SCPDURL>\r\n"
    "        <controlURL>/ctl/ContentDir</controlURL>\r\n"
    "        <eventSubURL>/evt/ContentDir</eventSubURL>\r\n"
    "      </service>\r\n"
    "      <service>\r\n"
    "        <serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType>\r\n"
    "        <serviceId>urn:upnp-org:serviceId:ConnectionManager</serviceId>\r\n"
    "        <SCPDURL>/cms_scpd.xml</SCPDURL>\r\n"
    "        <controlURL>/ctl/ConnMgr</controlURL>\r\n"
    "        <eventSubURL>/evt/ConnMgr</eventSubURL>\r\n"
    "      </service>\r\n"
    "    </serviceList>\r\n"
    "  </device>\r\n"
    "</root>\r\n";

static const char CDS_SCPD_XML[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
    "<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\r\n"
    "  <specVersion><major>1</major><minor>0</minor></specVersion>\r\n"
    "  <actionList>\r\n"
    "    <action><name>Browse</name><argumentList>\r\n"
    "      <argument><name>ObjectID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_ObjectID</relatedStateVariable></argument>\r\n"
    "      <argument><name>BrowseFlag</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_BrowseFlag</relatedStateVariable></argument>\r\n"
    "      <argument><name>Filter</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Filter</relatedStateVariable></argument>\r\n"
    "      <argument><name>StartingIndex</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Index</relatedStateVariable></argument>\r\n"
    "      <argument><name>RequestedCount</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument>\r\n"
    "      <argument><name>SortCriteria</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_SortCriteria</relatedStateVariable></argument>\r\n"
    "      <argument><name>Result</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable></argument>\r\n"
    "      <argument><name>NumberReturned</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument>\r\n"
    "      <argument><name>TotalMatches</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument>\r\n"
    "      <argument><name>UpdateID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_UpdateID</relatedStateVariable></argument>\r\n"
    "    </argumentList></action>\r\n"
    "    <action><name>GetSystemUpdateID</name><argumentList>\r\n"
    "      <argument><name>Id</name><direction>out</direction><relatedStateVariable>SystemUpdateID</relatedStateVariable></argument>\r\n"
    "    </argumentList></action>\r\n"
    "    <action><name>GetSearchCapabilities</name><argumentList>\r\n"
    "      <argument><name>SearchCaps</name><direction>out</direction><relatedStateVariable>SearchCapabilities</relatedStateVariable></argument>\r\n"
    "    </argumentList></action>\r\n"
    "    <action><name>GetSortCapabilities</name><argumentList>\r\n"
    "      <argument><name>SortCaps</name><direction>out</direction><relatedStateVariable>SortCapabilities</relatedStateVariable></argument>\r\n"
    "    </argumentList></action>\r\n"
    "  </actionList>\r\n"
    "  <serviceStateTable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_BrowseFlag</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_Filter</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_SortCriteria</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_Index</name><dataType>ui4</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_Count</name><dataType>ui4</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_UpdateID</name><dataType>ui4</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_Result</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>A_ARG_TYPE_ObjectID</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"yes\"><name>SystemUpdateID</name><dataType>ui4</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>SearchCapabilities</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"no\"><name>SortCapabilities</name><dataType>string</dataType></stateVariable>\r\n"
    "  </serviceStateTable>\r\n"
    "</scpd>\r\n";

static const char CMS_SCPD_XML[] =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
    "<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">\r\n"
    "  <specVersion><major>1</major><minor>0</minor></specVersion>\r\n"
    "  <actionList>\r\n"
    "    <action><name>GetProtocolInfo</name><argumentList>\r\n"
    "      <argument><name>Source</name><direction>out</direction><relatedStateVariable>SourceProtocolInfo</relatedStateVariable></argument>\r\n"
    "      <argument><name>Sink</name><direction>out</direction><relatedStateVariable>SinkProtocolInfo</relatedStateVariable></argument>\r\n"
    "    </argumentList></action>\r\n"
    "    <action><name>GetCurrentConnectionIDs</name><argumentList>\r\n"
    "      <argument><name>ConnectionIDs</name><direction>out</direction><relatedStateVariable>CurrentConnectionIDs</relatedStateVariable></argument>\r\n"
    "    </argumentList></action>\r\n"
    "  </actionList>\r\n"
    "  <serviceStateTable>\r\n"
    "    <stateVariable sendEvents=\"yes\"><name>SourceProtocolInfo</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"yes\"><name>SinkProtocolInfo</name><dataType>string</dataType></stateVariable>\r\n"
    "    <stateVariable sendEvents=\"yes\"><name>CurrentConnectionIDs</name><dataType>string</dataType></stateVariable>\r\n"
    "  </serviceStateTable>\r\n"
    "</scpd>\r\n";

/* --------------------------------------------------------------------------
 * Dynamic SOAP ContentDirectory Browse Engine
 * -------------------------------------------------------------------------- */
static int extract_xml_tag(const char *xml, const char *tag, char *out, size_t out_max) {
    char open_t[64], close_t[64];
    snprintf(open_t, sizeof(open_t), "<%s", tag);
    snprintf(close_t, sizeof(close_t), "</%s>", tag);

    const char *p = strstr(xml, open_t);
    if (!p) return 0;
    p = strchr(p, '>');
    if (!p) return 0;
    p++;
    const char *e = strstr(p, close_t);
    if (!e) return 0;

    size_t len = (size_t)(e - p);
    if (len >= out_max) len = out_max - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

static void append_container_didl(char **buf, size_t *cap, size_t *len,
                                  const char *id, const char *parent_id, const char *title) {
    append_str(buf, cap, len,
        "&lt;container id=\"%s\" parentID=\"%s\" restricted=\"1\" searchable=\"0\"&gt;"
        "&lt;dc:title&gt;", id, parent_id);
    append_didl_escaped(buf, cap, len, title);
    append_str(buf, cap, len,
        "&lt;/dc:title&gt;"
        "&lt;upnp:class&gt;object.container.storageFolder&lt;/upnp:class&gt;"
        "&lt;/container&gt;");
}

static void append_item_didl(char **buf, size_t *cap, size_t *len,
                             const char *id, const char *parent_id,
                             const char *title, const char *upnp_class,
                             const char *mime, const char *dlna_pn,
                             uint64_t file_size, const char *local_ip, const char *ext) {
    append_str(buf, cap, len,
        "&lt;item id=\"%s\" parentID=\"%s\" restricted=\"1\"&gt;"
        "&lt;dc:title&gt;", id, parent_id);
    append_didl_escaped(buf, cap, len, title);
    append_str(buf, cap, len,
        "&lt;/dc:title&gt;"
        "&lt;upnp:class&gt;%s&lt;/upnp:class&gt;"
        "&lt;res size=\"%llu\" protocolInfo=\"http-get:*:%s:%s\"&gt;"
        "http://%s:%d/media/%s/stream%s"
        "&lt;/res&gt;"
        "&lt;/item&gt;",
        upnp_class, (unsigned long long)file_size, mime, dlna_pn,
        local_ip, g_port, id, ext ? ext : "");
}

static char *build_soap_browse_response(const char *req_xml, const char *local_ip) {
    char obj_id[MAX_PATH * 2] = "0";
    char browse_flag[64]      = "BrowseDirectChildren";
    char start_str[32]        = "0";
    char count_str[32]        = "0";

    extract_xml_tag(req_xml, "ObjectID", obj_id, sizeof(obj_id));
    extract_xml_tag(req_xml, "BrowseFlag", browse_flag, sizeof(browse_flag));
    extract_xml_tag(req_xml, "StartingIndex", start_str, sizeof(start_str));
    extract_xml_tag(req_xml, "RequestedCount", count_str, sizeof(count_str));

    uint32_t start_idx = (uint32_t)strtoul(start_str, NULL, 10);
    uint32_t req_count = (uint32_t)strtoul(count_str, NULL, 10);
    int is_metadata    = (strstr(browse_flag, "BrowseMetadata") != NULL);

    size_t cap = 16384;
    size_t len = 0;
    char *buf  = (char *)malloc(cap);
    buf[0]     = '\0';

    append_str(&buf, &cap, &len,
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
        "  <s:Body>\r\n"
        "    <u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">\r\n"
        "      <Result>"
        "&lt;DIDL-Lite xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\" "
        "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
        "xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\"&gt;");

    uint32_t total_matches = 0;
    uint32_t num_returned  = 0;

    int share_idx = -1;
    char rel_path[MAX_PATH] = {0};
    char full_path[MAX_PATH] = {0};
    char title[MAX_PATH] = {0};
    char parent_id[MAX_PATH * 2] = {0};

    if (resolve_object_id(obj_id, &share_idx, rel_path, sizeof(rel_path),
                          full_path, sizeof(full_path), title, sizeof(title),
                          parent_id, sizeof(parent_id))) {

        if (is_metadata) {
            /* Metadata request for a single container or item */
            if (strcmp(obj_id, "0") == 0 || share_idx >= 0) {
                DWORD attr = (strcmp(obj_id, "0") == 0) ? FILE_ATTRIBUTE_DIRECTORY : GetFileAttributesA(full_path);
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    append_container_didl(&buf, &cap, &len, obj_id, parent_id, title);
                    total_matches = num_returned = 1;
                } else if (attr != INVALID_FILE_ATTRIBUTES) {
                    const char *mime, *uclass, *pn;
                    if (get_media_profile(title, &mime, &uclass, &pn)) {
                        WIN32_FILE_ATTRIBUTE_DATA fad;
                        uint64_t fsize = 0;
                        if (GetFileAttributesExA(full_path, GetFileExInfoStandard, &fad)) {
                            fsize = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
                        }
                        const char *ext = strrchr(title, '.');
                        append_item_didl(&buf, &cap, &len, obj_id, parent_id,
                                         title, uclass, mime, pn, fsize, local_ip, ext);
                        total_matches = num_returned = 1;
                    }
                }
            }
        } else {
            /* BrowseDirectChildren */
            if (strcmp(obj_id, "0") == 0) {
                EnterCriticalSection(&g_cs_shares);
                for (int i = 0; i < g_share_count; i++) {
                    if (total_matches >= start_idx && (req_count == 0 || num_returned < req_count)) {
                        char cid[32];
                        snprintf(cid, sizeof(cid), "S%d", i);
                        append_container_didl(&buf, &cap, &len, cid, "0", g_shares[i].name);
                        num_returned++;
                    }
                    total_matches++;
                }
                LeaveCriticalSection(&g_cs_shares);
            } else {
                char search_pattern[MAX_PATH];
                snprintf(search_pattern, sizeof(search_pattern), "%s\\*", full_path);

                WIN32_FIND_DATAA fd;
                HANDLE hFind = FindFirstFileA(search_pattern, &fd);
                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                            continue;
                        if (fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
                            continue;

                        int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        const char *mime = NULL, *uclass = NULL, *pn = NULL;
                        if (!is_dir && !get_media_profile(fd.cFileName, &mime, &uclass, &pn))
                            continue;

                        if (total_matches >= start_idx && (req_count == 0 || num_returned < req_count)) {
                            char child_rel[MAX_PATH];
                            if (rel_path[0])
                                snprintf(child_rel, sizeof(child_rel), "%s\\%s", rel_path, fd.cFileName);
                            else
                                snprintf(child_rel, sizeof(child_rel), "%s", fd.cFileName);

                            char child_id[MAX_PATH * 2 + 16];
                            build_object_id(share_idx, child_rel, child_id, sizeof(child_id));

                            if (is_dir) {
                                append_container_didl(&buf, &cap, &len, child_id, obj_id, fd.cFileName);
                            } else {
                                uint64_t fsize = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                                const char *ext = strrchr(fd.cFileName, '.');
                                append_item_didl(&buf, &cap, &len, child_id, obj_id,
                                                 fd.cFileName, uclass, mime, pn, fsize, local_ip, ext);
                            }
                            num_returned++;
                        }
                        total_matches++;
                    } while (FindNextFileA(hFind, &fd));
                    FindClose(hFind);
                }
            }
        }
    }

    append_str(&buf, &cap, &len,
        "&lt;/DIDL-Lite&gt;</Result>\r\n"
        "      <NumberReturned>%u</NumberReturned>\r\n"
        "      <TotalMatches>%u</TotalMatches>\r\n"
        "      <UpdateID>%u</UpdateID>\r\n"
        "    </u:BrowseResponse>\r\n"
        "  </s:Body>\r\n"
        "</s:Envelope>\r\n",
        num_returned, total_matches, g_system_update);

    server_log("SOAP Browse ObjectID=\"%s\" (%s) -> returned %u/%u items",
               obj_id, is_metadata ? "Metadata" : "Children", num_returned, total_matches);
    return buf;
}

/* --------------------------------------------------------------------------
 * HTTP / SOAP / Media Streaming Client Thread
 * -------------------------------------------------------------------------- */
static void send_http_xml(SOCKET s, const char *xml) {
    char hdr[512];
    int body_len = (int)strlen(xml);
    int hdr_len  = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "Content-Length: %d\r\n"
        "Server: Windows/10.0 UPnP/1.0 Win32DLNA/1.0\r\n"
        "EXT:\r\n"
        "Connection: close\r\n\r\n", body_len);
    send(s, hdr, hdr_len, 0);
    send(s, xml, body_len, 0);
}

static void stream_media_by_object_id(SOCKET s, const char *uri_path,
                                      const char *req_buf, int is_head) {
    /* URI format: /media/<ObjectID>/stream.ext */
    const char *p = uri_path + 7; /* skip "/media/" */
    char obj_id[MAX_PATH * 2] = {0};
    const char *slash = strchr(p, '/');
    size_t id_len = slash ? (size_t)(slash - p) : strlen(p);
    if (id_len >= sizeof(obj_id)) id_len = sizeof(obj_id) - 1;
    memcpy(obj_id, p, id_len);
    obj_id[id_len] = '\0';

    char full_path[MAX_PATH] = {0};
    char title[MAX_PATH]     = {0};
    if (!resolve_object_id(obj_id, NULL, NULL, 0, full_path, sizeof(full_path),
                           title, sizeof(title), NULL, 0) || !full_path[0]) {
        const char *r404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(s, r404, (int)strlen(r404), 0);
        return;
    }

    const char *mime = "application/octet-stream", *uclass = "", *dlna_pn = "";
    get_media_profile(title, &mime, &uclass, &dlna_pn);

    FILE *fp = fopen(full_path, "rb");
    if (!fp) {
        const char *r404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(s, r404, (int)strlen(r404), 0);
        return;
    }

    _fseeki64(fp, 0, SEEK_END);
    uint64_t total_size = (uint64_t)_ftelli64(fp);
    uint64_t start_byte = 0;
    uint64_t end_byte   = (total_size > 0) ? (total_size - 1) : 0;
    int is_partial      = 0;

    const char *range = strstr(req_buf, "Range: bytes=");
    if (!range) range = strstr(req_buf, "range: bytes=");
    if (range) {
        is_partial = 1;
        range += 13;
        start_byte = _strtoui64(range, NULL, 10);
        const char *dash = strchr(range, '-');
        if (dash && isdigit((unsigned char)*(dash + 1))) {
            end_byte = _strtoui64(dash + 1, NULL, 10);
        }
    }
    if (start_byte >= total_size) start_byte = 0;
    if (end_byte >= total_size)   end_byte = (total_size > 0) ? (total_size - 1) : 0;
    uint64_t content_len = (total_size > 0) ? (end_byte - start_byte + 1) : 0;

    char hdr[1024];
    int hdr_len;
    if (is_partial) {
        hdr_len = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 206 Partial Content\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %llu\r\n"
            "Content-Range: bytes %llu-%llu/%llu\r\n"
            "Accept-Ranges: bytes\r\n"
            "transferMode.dlna.org: Streaming\r\n"
            "contentFeatures.dlna.org: %s\r\n"
            "Server: Windows/10.0 UPnP/1.0 Win32DLNA/1.0\r\n"
            "Connection: close\r\n\r\n",
            mime,
            (unsigned long long)content_len,
            (unsigned long long)start_byte,
            (unsigned long long)end_byte,
            (unsigned long long)total_size,
            dlna_pn);
    } else {
        hdr_len = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %llu\r\n"
            "Accept-Ranges: bytes\r\n"
            "transferMode.dlna.org: Streaming\r\n"
            "contentFeatures.dlna.org: %s\r\n"
            "Server: Windows/10.0 UPnP/1.0 Win32DLNA/1.0\r\n"
            "Connection: close\r\n\r\n",
            mime,
            (unsigned long long)content_len,
            dlna_pn);
    }

    send(s, hdr, hdr_len, 0);

    if (!is_head && content_len > 0) {
        server_log("Streaming \"%s\" (%llu bytes, offset %llu)",
                   title, (unsigned long long)content_len, (unsigned long long)start_byte);
        _fseeki64(fp, (int64_t)start_byte, SEEK_SET);
        char chunk[65536];
        uint64_t rem = content_len;
        while (rem > 0 && g_server_running) {
            size_t to_read = (rem < sizeof(chunk)) ? (size_t)rem : sizeof(chunk);
            size_t n = fread(chunk, 1, to_read, fp);
            if (n == 0) break;
            int sent = send(s, chunk, (int)n, 0);
            if (sent <= 0) break;
            rem -= (uint64_t)sent;
        }
    }
    fclose(fp);
}

static DWORD WINAPI ClientThread(LPVOID lpParam) {
    SOCKET client_sock = (SOCKET)(uintptr_t)lpParam;

    /* Determine which local IP accepted this connection so URLs match the subnet */
    struct sockaddr_in local_addr;
    int addr_len = sizeof(local_addr);
    char local_ip[64] = "127.0.0.1";
    if (getsockname(client_sock, (struct sockaddr *)&local_addr, &addr_len) == 0) {
        strncpy(local_ip, inet_ntoa(local_addr.sin_addr), sizeof(local_ip) - 1);
    }

    char req[8192];
    int received = recv(client_sock, req, sizeof(req) - 1, 0);
    if (received <= 0) {
        closesocket(client_sock);
        return 0;
    }
    req[received] = '\0';

    /* If POST has a body that arrived in a second TCP segment, read it */
    const char *cl_hdr = strstr(req, "Content-Length:");
    if (!cl_hdr) cl_hdr = strstr(req, "content-length:");
    const char *hdr_end = strstr(req, "\r\n\r\n");
    if (cl_hdr && hdr_end) {
        int content_len = atoi(cl_hdr + 15);
        int body_have   = received - (int)((hdr_end + 4) - req);
        while (body_have < content_len && received < (int)sizeof(req) - 1) {
            int n = recv(client_sock, req + received, (int)sizeof(req) - 1 - received, 0);
            if (n <= 0) break;
            received  += n;
            body_have += n;
            req[received] = '\0';
        }
    }

    char method[32] = {0}, path[512] = {0};
    sscanf(req, "%31s %511s", method, path);

    if (strcmp(method, "GET") == 0 && strcmp(path, "/rootDesc.xml") == 0) {
        char desc[4096];
        char host_name[128] = "PC";
        gethostname(host_name, sizeof(host_name));
        snprintf(desc, sizeof(desc), ROOT_DESC_XML_FMT, host_name);
        server_log("HTTP GET /rootDesc.xml from client (via %s)", local_ip);
        send_http_xml(client_sock, desc);
    }
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/cds_scpd.xml") == 0) {
        send_http_xml(client_sock, CDS_SCPD_XML);
    }
    else if (strcmp(method, "GET") == 0 && strcmp(path, "/cms_scpd.xml") == 0) {
        send_http_xml(client_sock, CMS_SCPD_XML);
    }
    else if (strcmp(method, "SUBSCRIBE") == 0 || strcmp(method, "UNSUBSCRIBE") == 0) {
        /* GENA Eventing stub so strict UPnP renderers/controllers stay happy */
        const char *sub_ok =
            "HTTP/1.1 200 OK\r\n"
            "SID: uuid:11223344-5566-7788-99aa-bbccddeeff00\r\n"
            "TIMEOUT: Second-1800\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n";
        send(client_sock, sub_ok, (int)strlen(sub_ok), 0);
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/ctl/ContentDir") == 0) {
        if (strstr(req, "GetSystemUpdateID")) {
            char xml[512];
            snprintf(xml, sizeof(xml),
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                "  <s:Body><u:GetSystemUpdateIDResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">"
                "<Id>%u</Id></u:GetSystemUpdateIDResponse></s:Body>\r\n</s:Envelope>\r\n",
                g_system_update);
            send_http_xml(client_sock, xml);
        }
        else if (strstr(req, "GetSearchCapabilities")) {
            const char *xml =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                "  <s:Body><u:GetSearchCapabilitiesResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">"
                "<SearchCaps></SearchCaps></u:GetSearchCapabilitiesResponse></s:Body>\r\n</s:Envelope>\r\n";
            send_http_xml(client_sock, xml);
        }
        else if (strstr(req, "GetSortCapabilities")) {
            const char *xml =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                "  <s:Body><u:GetSortCapabilitiesResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">"
                "<SortCaps>dc:title</SortCaps></u:GetSortCapabilitiesResponse></s:Body>\r\n</s:Envelope>\r\n";
            send_http_xml(client_sock, xml);
        }
        else {
            char *browse_xml = build_soap_browse_response(req, local_ip);
            send_http_xml(client_sock, browse_xml);
            free(browse_xml);
        }
    }
    else if (strcmp(method, "POST") == 0 && strcmp(path, "/ctl/ConnMgr") == 0) {
        if (strstr(req, "GetCurrentConnectionIDs")) {
            const char *xml =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                "  <s:Body><u:GetCurrentConnectionIDsResponse xmlns:u=\"urn:schemas-upnp-org:service:ConnectionManager:1\">"
                "<ConnectionIDs>0</ConnectionIDs></u:GetCurrentConnectionIDsResponse></s:Body>\r\n</s:Envelope>\r\n";
            send_http_xml(client_sock, xml);
        } else {
            const char *xml =
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
                "  <s:Body><u:GetProtocolInfoResponse xmlns:u=\"urn:schemas-upnp-org:service:ConnectionManager:1\">"
                "<Source>http-get:*:video/mp4:*,http-get:*:video/x-matroska:*,http-get:*:video/x-msvideo:*,"
                "http-get:*:video/mpeg:*,http-get:*:audio/mpeg:*,http-get:*:audio/flac:*,http-get:*:audio/wav:*,"
                "http-get:*:image/jpeg:*,http-get:*:image/png:*</Source><Sink></Sink>"
                "</u:GetProtocolInfoResponse></s:Body>\r\n</s:Envelope>\r\n";
            send_http_xml(client_sock, xml);
        }
    }
    else if (strncmp(path, "/media/", 7) == 0) {
        int is_head = (strcmp(method, "HEAD") == 0);
        stream_media_by_object_id(client_sock, path, req, is_head);
    }
    else {
        const char *r404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send(client_sock, r404, (int)strlen(r404), 0);
    }

    closesocket(client_sock);
    return 0;
}

/* --------------------------------------------------------------------------
 * SSDP Discovery & Multicast Helpers
 * -------------------------------------------------------------------------- */
static int get_local_ipv4_list(char ips[][64], int max_ips) {
    char host[256];
    if (gethostname(host, sizeof(host)) != 0) return 0;
    struct hostent *he = gethostbyname(host);
    if (!he) return 0;

    int count = 0;
    for (int i = 0; he->h_addr_list[i] != NULL && count < max_ips; i++) {
        struct in_addr addr;
        memcpy(&addr, he->h_addr_list[i], sizeof(struct in_addr));
        const char *s = inet_ntoa(addr);
        if (s && strcmp(s, "127.0.0.1") != 0) {
            strncpy(ips[count], s, 63);
            ips[count][63] = '\0';
            count++;
        }
    }
    if (count == 0 && max_ips > 0) {
        strcpy(ips[0], "127.0.0.1");
        count = 1;
    }
    return count;
}

/* Picks the local interface IP on the same /24 subnet as the peer (or first LAN IP) */
static void select_best_local_ip(struct in_addr peer, char *out_ip, size_t max_len) {
    char ips[16][64];
    int n = get_local_ipv4_list(ips, 16);
    uint32_t peer_net = ntohl(peer.s_addr) & 0xFFFFFF00;

    for (int i = 0; i < n; i++) {
        uint32_t lip = ntohl(inet_addr(ips[i]));
        if ((lip & 0xFFFFFF00) == peer_net) {
            snprintf(out_ip, max_len, "%s", ips[i]);
            return;
        }
    }
    snprintf(out_ip, max_len, "%s", (n > 0) ? ips[0] : "127.0.0.1");
}

static void broadcast_ssdp_notify(SOCKET ssdp_sock, int alive) {
    static const char *nt_list[] = {
        "upnp:rootdevice",
        SERVER_UUID,
        "urn:schemas-upnp-org:device:MediaServer:1",
        "urn:schemas-upnp-org:service:ContentDirectory:1",
        "urn:schemas-upnp-org:service:ConnectionManager:1"
    };

    char ips[16][64];
    int ip_count = get_local_ipv4_list(ips, 16);

    struct sockaddr_in mcast;
    memset(&mcast, 0, sizeof(mcast));
    mcast.sin_family      = AF_INET;
    mcast.sin_port        = htons(SSDP_PORT);
    mcast.sin_addr.s_addr = inet_addr(SSDP_ADDR);

    for (int i = 0; i < ip_count; i++) {
        struct in_addr iface;
        iface.s_addr = inet_addr(ips[i]);
        setsockopt(ssdp_sock, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&iface, sizeof(iface));

        for (int j = 0; j < 5; j++) {
            char usn[256];
            if (j == 1)
                snprintf(usn, sizeof(usn), "%s", SERVER_UUID);
            else
                snprintf(usn, sizeof(usn), "%s::%s", SERVER_UUID, nt_list[j]);

            char pkt[1024];
            int len;
            if (alive) {
                len = snprintf(pkt, sizeof(pkt),
                    "NOTIFY * HTTP/1.1\r\n"
                    "HOST: %s:%d\r\n"
                    "CACHE-CONTROL: max-age=1800\r\n"
                    "LOCATION: http://%s:%d/rootDesc.xml\r\n"
                    "NT: %s\r\n"
                    "NTS: ssdp:alive\r\n"
                    "SERVER: Windows/10.0 UPnP/1.0 Win32DLNA/1.0\r\n"
                    "USN: %s\r\n\r\n",
                    SSDP_ADDR, SSDP_PORT, ips[i], g_port, nt_list[j], usn);
            } else {
                len = snprintf(pkt, sizeof(pkt),
                    "NOTIFY * HTTP/1.1\r\n"
                    "HOST: %s:%d\r\n"
                    "NT: %s\r\n"
                    "NTS: ssdp:byebye\r\n"
                    "USN: %s\r\n\r\n",
                    SSDP_ADDR, SSDP_PORT, nt_list[j], usn);
            }
            sendto(ssdp_sock, pkt, len, 0, (struct sockaddr *)&mcast, sizeof(mcast));
        }
    }
}

static void handle_ssdp_msearch(SOCKET ssdp_sock) {
    char buf[2048];
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);

    int len = recvfrom(ssdp_sock, buf, sizeof(buf) - 1, 0,
                       (struct sockaddr *)&client_addr, &addr_len);
    if (len <= 0) return;
    buf[len] = '\0';

    if (strncmp(buf, "M-SEARCH", 8) != 0) return;

    const char *st = NULL;
    if (strstr(buf, "urn:schemas-upnp-org:device:MediaServer:1"))
        st = "urn:schemas-upnp-org:device:MediaServer:1";
    else if (strstr(buf, "urn:schemas-upnp-org:service:ContentDirectory:1"))
        st = "urn:schemas-upnp-org:service:ContentDirectory:1";
    else if (strstr(buf, "urn:schemas-upnp-org:service:ConnectionManager:1"))
        st = "urn:schemas-upnp-org:service:ConnectionManager:1";
    else if (strstr(buf, "upnp:rootdevice"))
        st = "upnp:rootdevice";
    else if (strstr(buf, "ssdp:all"))
        st = "urn:schemas-upnp-org:device:MediaServer:1";

    if (!st) return;

    char best_ip[64];
    select_best_local_ip(client_addr.sin_addr, best_ip, sizeof(best_ip));

    char reply[1024];
    int reply_len = snprintf(reply, sizeof(reply),
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        "EXT:\r\n"
        "LOCATION: http://%s:%d/rootDesc.xml\r\n"
        "SERVER: Windows/10.0 UPnP/1.0 Win32DLNA/1.0\r\n"
        "ST: %s\r\n"
        "USN: %s::%s\r\n\r\n",
        best_ip, g_port, st, SERVER_UUID, st);

    sendto(ssdp_sock, reply, reply_len, 0, (struct sockaddr *)&client_addr, addr_len);
    server_log("SSDP M-SEARCH from %s -> advertised http://%s:%d/rootDesc.xml",
               inet_ntoa(client_addr.sin_addr), best_ip, g_port);
}

/* --------------------------------------------------------------------------
 * ServerThread & ToggleServer Lifecycle
 * -------------------------------------------------------------------------- */
static DWORD WINAPI ServerThread(LPVOID lpParam) {
    (void)lpParam;

    /* 1. Create SSDP UDP socket on 1900 */
    g_ssdp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_ssdp_socket != INVALID_SOCKET) {
        int reuse = 1;
        setsockopt(g_ssdp_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

        struct sockaddr_in ssdp_addr;
        memset(&ssdp_addr, 0, sizeof(ssdp_addr));
        ssdp_addr.sin_family      = AF_INET;
        ssdp_addr.sin_port        = htons(SSDP_PORT);
        ssdp_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(g_ssdp_socket, (struct sockaddr *)&ssdp_addr, sizeof(ssdp_addr)) == SOCKET_ERROR) {
            server_log("Warning: UDP port 1900 busy (Windows SSDPSRV may be active).");
        }

        char ips[16][64];
        int n = get_local_ipv4_list(ips, 16);
        for (int i = 0; i < n; i++) {
            struct ip_mreq mreq;
            mreq.imr_multiaddr.s_addr = inet_addr(SSDP_ADDR);
            mreq.imr_interface.s_addr = inet_addr(ips[i]);
            setsockopt(g_ssdp_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
        }
        broadcast_ssdp_notify(g_ssdp_socket, 1);
    }

    /* 2. Create HTTP TCP listening socket on g_port */
    g_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen_socket == INVALID_SOCKET) {
        server_log("Error: Failed to create HTTP listening socket.");
        g_server_running = 0;
        return 1;
    }

    int reuse = 1;
    setsockopt(g_listen_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family      = AF_INET;
    srv_addr.sin_port        = htons((u_short)g_port);
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(g_listen_socket, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) == SOCKET_ERROR ||
        listen(g_listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        server_log("Error: Failed to bind/listen on TCP port %d.", g_port);
        closesocket(g_listen_socket);
        g_listen_socket = INVALID_SOCKET;
        g_server_running = 0;
        return 1;
    }

    server_log("DLNA Server started on HTTP port %d + SSDP UDP %d.", g_port, SSDP_PORT);

    DWORD last_notify = GetTickCount();

    while (g_server_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (g_listen_socket != INVALID_SOCKET) FD_SET(g_listen_socket, &rfds);
        if (g_ssdp_socket   != INVALID_SOCKET) FD_SET(g_ssdp_socket, &rfds);

        struct timeval tv;
        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        int r = select(0, &rfds, NULL, NULL, &tv);
        if (!g_server_running) break;

        if (r > 0) {
            if (g_ssdp_socket != INVALID_SOCKET && FD_ISSET(g_ssdp_socket, &rfds)) {
                handle_ssdp_msearch(g_ssdp_socket);
            }
            if (g_listen_socket != INVALID_SOCKET && FD_ISSET(g_listen_socket, &rfds)) {
                struct sockaddr_in caddr;
                int clen = sizeof(caddr);
                SOCKET client = accept(g_listen_socket, (struct sockaddr *)&caddr, &clen);
                if (client != INVALID_SOCKET) {
                    HANDLE hThread = CreateThread(NULL, 0, ClientThread, (LPVOID)(uintptr_t)client, 0, NULL);
                    if (hThread) CloseHandle(hThread);
                    else closesocket(client);
                }
            }
        }

        /* Broadcast SSDP alive every 30 seconds */
        if (GetTickCount() - last_notify >= 30000) {
            if (g_ssdp_socket != INVALID_SOCKET) {
                broadcast_ssdp_notify(g_ssdp_socket, 1);
            }
            last_notify = GetTickCount();
        }
    }

    return 0;
}

static void ToggleServer(void) {
    if (g_server_running) {
        g_server_running = 0;
        if (g_ssdp_socket != INVALID_SOCKET) {
            broadcast_ssdp_notify(g_ssdp_socket, 0);
            closesocket(g_ssdp_socket);
            g_ssdp_socket = INVALID_SOCKET;
        }
        if (g_listen_socket != INVALID_SOCKET) {
            closesocket(g_listen_socket);
            g_listen_socket = INVALID_SOCKET;
        }
        if (g_server_thread) {
            WaitForSingleObject(g_server_thread, 2000);
            CloseHandle(g_server_thread);
            g_server_thread = NULL;
        }
        server_log("DLNA Server stopped.");
    } else {
        g_server_running = 1;
        g_server_thread  = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    }

    snprintf(g_nid.szTip, sizeof(g_nid.szTip), "DLNA Media Server (%s)",
             g_server_running ? "Running" : "Stopped");
    Shell_NotifyIconA(NIM_MODIFY, &g_nid);

    if (g_hSettings && IsWindow(g_hSettings)) {
        SetDlgItemTextA(g_hSettings, IDB_TOGGLE_SRV,
                        g_server_running ? "Stop Server" : "Start Server");
    }
}

/* --------------------------------------------------------------------------
 * Win32 GUI Functions (SettingsWndProc, ShowContextMenu, MainWndProc)
 * -------------------------------------------------------------------------- */
static BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

static void RefreshSharesCombo(HWND hwnd) {
    SendMessageA(g_hCmbShares, CB_RESETCONTENT, 0, 0);
    EnterCriticalSection(&g_cs_shares);
    for (int i = 0; i < g_share_count; i++) {
        SendMessageA(g_hCmbShares, CB_ADDSTRING, 0, (LPARAM)g_shares[i].name);
    }
    if (g_share_count > 0) {
        SendMessageA(g_hCmbShares, CB_SETCURSEL, 0, 0);
        SetWindowTextA(g_hSharePath, g_shares[0].path);
    } else {
        SetWindowTextA(g_hSharePath, "");
    }
    LeaveCriticalSection(&g_cs_shares);
    (void)hwnd;
}

static void UpdateOrAddCurrentShare(void) {
    char name[64] = {0};
    char path[MAX_PATH] = {0};
    GetWindowTextA(g_hCmbShares, name, sizeof(name));
    GetWindowTextA(g_hSharePath, path, sizeof(path));
    if (!name[0] || !path[0]) return;

    EnterCriticalSection(&g_cs_shares);
    int found = -1;
    for (int i = 0; i < g_share_count; i++) {
        if (_stricmp(g_shares[i].name, name) == 0) {
            found = i;
            break;
        }
    }
    if (found >= 0) {
        strncpy(g_shares[found].path, path, MAX_PATH - 1);
    } else if (g_share_count < MAX_SHARES) {
        strncpy(g_shares[g_share_count].name, name, sizeof(g_shares[0].name) - 1);
        strncpy(g_shares[g_share_count].path, path, MAX_PATH - 1);
        g_share_count++;
    }
    g_system_update++;
    LeaveCriticalSection(&g_cs_shares);
}

static LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "HTTP Port:", WS_CHILD | WS_VISIBLE,
                          15, 18, 75, 20, hwnd, NULL, g_hInst, NULL);
            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%d", g_port);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", port_str,
                            WS_CHILD | WS_VISIBLE | ES_NUMBER,
                            95, 15, 70, 22, hwnd, (HMENU)IDE_PORT, g_hInst, NULL);

            CreateWindowA("BUTTON", g_server_running ? "Stop Server" : "Start Server",
                          WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          180, 14, 110, 24, hwnd, (HMENU)IDB_TOGGLE_SRV, g_hInst, NULL);

            CreateWindowA("STATIC", "Bound Local IPv4 Addresses:", WS_CHILD | WS_VISIBLE,
                          15, 48, 200, 18, hwnd, NULL, g_hInst, NULL);
            HWND hList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL,
                                         WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOSEL,
                                         15, 68, 460, 55, hwnd, (HMENU)IDL_IPS, g_hInst, NULL);

            char ips[16][64];
            int ip_cnt = get_local_ipv4_list(ips, 16);
            for (int i = 0; i < ip_cnt; i++) {
                char entry[128];
                snprintf(entry, sizeof(entry), "%s (http://%s:%d/rootDesc.xml)", ips[i], ips[i], g_port);
                SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)entry);
            }

            CreateWindowA("STATIC", "DLNA Media Folders (Share Name & Folder Path):",
                          WS_CHILD | WS_VISIBLE, 15, 130, 320, 18, hwnd, NULL, g_hInst, NULL);

            g_hCmbShares = CreateWindowA("COMBOBOX", "",
                                         WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | WS_VSCROLL,
                                         15, 150, 120, 120, hwnd, (HMENU)IDC_CMB_SHARES, g_hInst, NULL);

            g_hSharePath = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                           WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                           140, 150, 235, 22, hwnd, (HMENU)IDE_SHAREPATH, g_hInst, NULL);

            CreateWindowA("BUTTON", "...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          380, 150, 32, 22, hwnd, (HMENU)IDB_BROWSE, g_hInst, NULL);

            CreateWindowA("BUTTON", "Delete", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          417, 150, 58, 22, hwnd, (HMENU)IDB_DEL_SHARE, g_hInst, NULL);

            RefreshSharesCombo(hwnd);

            CreateWindowA("STATIC", "DLNA / UPnP Activity Log:", WS_CHILD | WS_VISIBLE,
                          15, 182, 200, 18, hwnd, NULL, g_hInst, NULL);

            EnterCriticalSection(&g_cs_log);
            g_hLogEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_log_buffer,
                                         WS_CHILD | WS_VISIBLE | WS_VSCROLL |
                                         ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                         15, 202, 460, 165, hwnd, (HMENU)IDE_LOG, g_hInst, NULL);
            LeaveCriticalSection(&g_cs_log);

            CreateWindowA("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                          295, 378, 85, 26, hwnd, (HMENU)IDB_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          390, 378, 85, 26, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);

            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hFont);
            return 0;
        }

        case WM_COMMAND: {
            WORD id   = LOWORD(wParam);
            WORD code = HIWORD(wParam);

            if (id == IDC_CMB_SHARES && code == CBN_SELCHANGE) {
                int sel = (int)SendMessageA(g_hCmbShares, CB_GETCURSEL, 0, 0);
                EnterCriticalSection(&g_cs_shares);
                if (sel >= 0 && sel < g_share_count) {
                    SetWindowTextA(g_hSharePath, g_shares[sel].path);
                }
                LeaveCriticalSection(&g_cs_shares);
            }
            else if (id == IDB_BROWSE) {
                BROWSEINFOA bi;
                memset(&bi, 0, sizeof(bi));
                bi.hwndOwner = hwnd;
                bi.lpszTitle = "Select Media Folder to Share over DLNA:";
                bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
                LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
                if (pidl) {
                    char selected[MAX_PATH];
                    if (SHGetPathFromIDListA(pidl, selected)) {
                        SetWindowTextA(g_hSharePath, selected);
                        UpdateOrAddCurrentShare();
                        RefreshSharesCombo(hwnd);
                    }
                    FreePidl(pidl);
                }
            }
            else if (id == IDB_DEL_SHARE) {
                char name[64] = {0};
                GetWindowTextA(g_hCmbShares, name, sizeof(name));
                EnterCriticalSection(&g_cs_shares);
                for (int i = 0; i < g_share_count; i++) {
                    if (_stricmp(g_shares[i].name, name) == 0) {
                        for (int j = i; j < g_share_count - 1; j++) {
                            g_shares[j] = g_shares[j + 1];
                        }
                        g_share_count--;
                        g_system_update++;
                        break;
                    }
                }
                LeaveCriticalSection(&g_cs_shares);
                RefreshSharesCombo(hwnd);
            }
            else if (id == IDB_TOGGLE_SRV) {
                ToggleServer();
            }
            else if (id == IDB_OK) {
                UpdateOrAddCurrentShare();
                BOOL trans = FALSE;
                int new_port = (int)GetDlgItemInt(hwnd, IDE_PORT, &trans, FALSE);
                if (trans && new_port > 0 && new_port <= 65535 && new_port != g_port) {
                    g_port = new_port;
                    if (g_server_running) {
                        ToggleServer();
                        ToggleServer();
                    }
                }
                SaveConfig();
                DestroyWindow(hwnd);
            }
            else if (id == IDB_CANCEL) {
                DestroyWindow(hwnd);
            }
            return 0;
        }

        case WM_DESTROY:
            g_hLogEdit   = NULL;
            g_hCmbShares = NULL;
            g_hSharePath = NULL;
            g_hSettings  = NULL;
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static void OpenSettingsWindow(void) {
    if (g_hSettings && IsWindow(g_hSettings)) {
        ShowWindow(g_hSettings, SW_RESTORE);
        SetForegroundWindow(g_hSettings);
        return;
    }
    g_hSettings = CreateWindowExA(
        WS_EX_DLGMODALFRAME, "DLNASettingsWnd", "DLNA Media Server Settings",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 445,
        g_hMain, NULL, g_hInst, NULL);
}

static void ShowContextMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_SETTINGS, "Settings...");
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_TOGGLE,
                g_server_running ? "Stop DLNA Server" : "Start DLNA Server");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    PostMessageA(hwnd, WM_NULL, 0, 0);
    DestroyMenu(hMenu);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            memset(&g_nid, 0, sizeof(g_nid));
            g_nid.cbSize           = sizeof(NOTIFYICONDATAA);
            g_nid.hWnd             = hwnd;
            g_nid.uID              = 1;
            g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            g_nid.uCallbackMessage = WM_TRAYICON;
            g_nid.hIcon            = LoadIconA(NULL, IDI_APPLICATION);
            strcpy(g_nid.szTip, "DLNA Media Server (Starting...)");
            Shell_NotifyIconA(NIM_ADD, &g_nid);
            return 0;

        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) {
                ShowContextMenu(hwnd);
            } else if (lParam == WM_LBUTTONDBLCLK) {
                OpenSettingsWindow();
            }
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_TRAY_SETTINGS:
                    OpenSettingsWindow();
                    break;
                case ID_TRAY_TOGGLE:
                    ToggleServer();
                    break;
                case ID_TRAY_EXIT:
                    DestroyWindow(hwnd);
                    break;
            }
            return 0;

        case WM_DESTROY:
            if (g_server_running) ToggleServer();
            Shell_NotifyIconA(NIM_DELETE, &g_nid);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;
    g_hInst = hInstance;

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    InitializeCriticalSection(&g_cs_log);
    InitializeCriticalSection(&g_cs_shares);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    GetModuleFileNameA(NULL, g_ini_path, MAX_PATH);
    char *dot = strrchr(g_ini_path, '.');
    if (dot) strcpy(dot, ".ini");
    else strcat(g_ini_path, ".ini");

    LoadConfig();

    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = "DLNAMainHiddenWnd";
    RegisterClassA(&wc);

    WNDCLASSA wcSet = {0};
    wcSet.lpfnWndProc   = SettingsWndProc;
    wcSet.hInstance     = hInstance;
    wcSet.hIcon         = LoadIconA(NULL, IDI_APPLICATION);
    wcSet.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wcSet.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcSet.lpszClassName = "DLNASettingsWnd";
    RegisterClassA(&wcSet);

    g_hMain = CreateWindowA("DLNAMainHiddenWnd", "DLNA Server", 0,
                            0, 0, 0, 0, NULL, NULL, hInstance, NULL);

    /* Start the DLNA server immediately on launch and show the settings dialog */
    ToggleServer();
    OpenSettingsWindow();

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    WSACleanup();
    DeleteCriticalSection(&g_cs_shares);
    DeleteCriticalSection(&g_cs_log);
    CoUninitialize();
    return (int)msg.wParam;
}
