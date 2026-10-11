//DLNA Client
//gcc dlna2c.c -Os -s -o dlna2c.exe -lws2_32 -lcomctl32 -lshell32 -lgdi32 -mwindows
//2026-10-11 Hugo
//Released into the Public Domain
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

/* --------------------------------------------------------------------------
 * GUI Control IDs (Preserved from smb2c.c)
 * -------------------------------------------------------------------------- */
#define ID_LIST_LOCAL       1001
#define ID_LIST_REMOTE      1002
#define ID_STATUSBAR        1003
#define ID_COMBO_CONN       1004
#define ID_BTN_CONNECT      1005
#define ID_BTN_EDIT_CONN    1006
#define ID_BTN_SCAN_SSDP    1007

#define ID_BTN_COPY         1101  /* Download from DLNA Server to Local Pane */
#define ID_BTN_MOVE         1102  /* Stream / Play Remote Media URL */
#define ID_BTN_RENAME       1103  /* Rename Local File */
#define ID_BTN_DELETE       1104  /* Delete Local File */
#define ID_BTN_MKDIR        1105  /* Create Local Folder */

#define IDE_NAME            2001
#define IDE_SERVER          2002
#define IDE_SHARE           2003  /* Root XML Path (e.g., /rootDesc.xml) */
#define IDE_USER            2004  /* Control URL override (optional) */
#define IDE_PASS            2005  /* Starting ObjectID (default "0") */
#define IDB_SAVE            2006
#define IDB_CANCEL          2007
#define IDB_ADD             2008
#define IDB_DELETE          2009
#define IDE_PORT            2010
#define IDC_CMB_PROTO       2012
#define IDB_TEST            2013

#define IDB_RENAME_OK       3001
#define IDE_RENAME_NEW      3002
#define IDE_MKDIR_NAME      3003
#define IDB_MKDIR_OK        3004

#define SSDP_MULTICAST_IP   "239.255.255.250"
#define SSDP_PORT           1900
#define MAX_NAV_DEPTH       64

/* --------------------------------------------------------------------------
 * Data Structures (Adapted from smb2c.c)
 * -------------------------------------------------------------------------- */
typedef struct {
    char     path[MAX_PATH];       /* Display name / filename */
    int      is_dir;               /* 1 = Container/Directory, 0 = Media Item */
    uint64_t size;                 /* Media resource byte size */
    char     object_id[512];       /* DLNA ContentDirectory ObjectID */
    char     parent_id[512];       /* DLNA parentID */
    char     res_url[1024];        /* Direct HTTP streaming URL (<res>) */
    char     mime[128];            /* MIME / protocolInfo summary */
} DirectoryItem;

typedef struct {
    char name[64];
    char server[128];
    int  port;
    char desc_path[256];           /* e.g. /rootDesc.xml */
    char control_url[256];         /* e.g. /ctl/ContentDir (auto-discovered) */
    char root_obj_id[64];          /* Default "0" */
} ConnectionProfile;

typedef struct {
    HWND hMain, hComboConn, hBtnEdit, hBtnConnect, hBtnScan;
    HWND hBtnCopy, hBtnMove, hBtnRename, hBtnDelete, hBtnMkDir;
    HWND hLocalList, hRemoteList, hStatus, hProgress, hLblLocal, hLblRemote;

    ConnectionProfile *connections;
    int  conn_capacity;
    int  conn_count;
    int  selected_conn_idx;

    int  is_connected;
    char active_server[128];
    int  active_port;
    char active_control_url[256];
    char active_friendly_name[128];

    char remote_base[512];         /* Current DLNA ObjectID being browsed */
    char remote_title_path[512];   /* Breadcrumb path for UI label */
    char nav_id_stack[MAX_NAV_DEPTH][512];
    char nav_title_stack[MAX_NAV_DEPTH][128];
    int  nav_depth;

    char local_base[MAX_PATH];

    DirectoryItem *remote_items;
    DirectoryItem *local_items;
    int  remote_count;
    int  local_count;
    int  active_pane;              /* 0 = Local, 1 = Remote */

    char ini_path[MAX_PATH];
} AppContext;

static AppContext g_app;
static HINSTANCE  g_hInst = NULL;

/* Forward Declarations */
static void list_local(void);
static void list_remote(void);
static void update_local_list(void);
static void update_remote_list(void);
static void refresh_conn_combo(void);

/* --------------------------------------------------------------------------
 * UI Status, Progress, and String Helpers
 * -------------------------------------------------------------------------- */
static void add_log(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (g_app.hStatus && IsWindow(g_app.hStatus)) {
        SendMessageA(g_app.hStatus, SB_SETTEXTA, 0, (LPARAM)buf);
    }
}

static void set_progress(int percent) {
    if (g_app.hProgress && IsWindow(g_app.hProgress)) {
        if (percent < 0) percent = 0;
        if (percent > 100) percent = 100;
        SendMessageA(g_app.hProgress, PBM_SETPOS, (WPARAM)percent, 0);
    }
}

static BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

static void format_size_str(uint64_t bytes, char *out, size_t out_max) {
    if (bytes >= (1024ULL * 1024 * 1024))
        snprintf(out, out_max, "%.2f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    else if (bytes >= (1024ULL * 1024))
        snprintf(out, out_max, "%.1f MB", (double)bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024ULL)
        snprintf(out, out_max, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(out, out_max, "%llu B", (unsigned long long)bytes);
}

/* --------------------------------------------------------------------------
 * Configuration Persistence (INI)
 * -------------------------------------------------------------------------- */
static void init_ini_path(void) {
    GetModuleFileNameA(NULL, g_app.ini_path, MAX_PATH);
    char *dot = strrchr(g_app.ini_path, '.');
    if (dot) strcpy(dot, ".ini");
    else strcat(g_app.ini_path, ".ini");
}

static void add_connection_profile(const char *name, const char *server, int port,
                                   const char *desc_path, const char *ctrl_url) {
    /* Update existing if same server + port */
    for (int i = 0; i < g_app.conn_count; i++) {
        if (_stricmp(g_app.connections[i].server, server) == 0 &&
            g_app.connections[i].port == port) {
            if (name && name[0])
                strncpy(g_app.connections[i].name, name, sizeof(g_app.connections[i].name) - 1);
            if (desc_path && desc_path[0])
                strncpy(g_app.connections[i].desc_path, desc_path, sizeof(g_app.connections[i].desc_path) - 1);
            if (ctrl_url && ctrl_url[0])
                strncpy(g_app.connections[i].control_url, ctrl_url, sizeof(g_app.connections[i].control_url) - 1);
            return;
        }
    }

    if (g_app.conn_count >= g_app.conn_capacity) {
        g_app.conn_capacity = (g_app.conn_capacity == 0) ? 8 : g_app.conn_capacity * 2;
        g_app.connections = (ConnectionProfile *)realloc(
            g_app.connections, g_app.conn_capacity * sizeof(ConnectionProfile));
    }

    ConnectionProfile *p = &g_app.connections[g_app.conn_count++];
    memset(p, 0, sizeof(*p));
    strncpy(p->name, (name && name[0]) ? name : server, sizeof(p->name) - 1);
    strncpy(p->server, server, sizeof(p->server) - 1);
    p->port = (port > 0) ? port : 8200;
    strncpy(p->desc_path, (desc_path && desc_path[0]) ? desc_path : "/rootDesc.xml", sizeof(p->desc_path) - 1);
    strncpy(p->control_url, (ctrl_url && ctrl_url[0]) ? ctrl_url : "", sizeof(p->control_url) - 1);
    strcpy(p->root_obj_id, "0");
}

static void load_config(void) {
    GetPrivateProfileStringA("General", "LocalBase", "", g_app.local_base, MAX_PATH, g_app.ini_path);
    if (!g_app.local_base[0]) {
        GetCurrentDirectoryA(MAX_PATH, g_app.local_base);
    }

    int count = GetPrivateProfileIntA("Connections", "Count", 0, g_app.ini_path);
    for (int i = 0; i < count; i++) {
        char sec[32], name[64], srv[128], desc[256], ctrl[256], robj[64];
        snprintf(sec, sizeof(sec), "Conn%d", i);
        GetPrivateProfileStringA(sec, "Name", "DLNA Server", name, sizeof(name), g_app.ini_path);
        GetPrivateProfileStringA(sec, "Server", "127.0.0.1", srv, sizeof(srv), g_app.ini_path);
        int port = GetPrivateProfileIntA(sec, "Port", 8200, g_app.ini_path);
        GetPrivateProfileStringA(sec, "DescPath", "/rootDesc.xml", desc, sizeof(desc), g_app.ini_path);
        GetPrivateProfileStringA(sec, "ControlURL", "", ctrl, sizeof(ctrl), g_app.ini_path);
        GetPrivateProfileStringA(sec, "RootID", "0", robj, sizeof(robj), g_app.ini_path);

        add_connection_profile(name, srv, port, desc, ctrl);
        strncpy(g_app.connections[g_app.conn_count - 1].root_obj_id, robj, 63);
    }

    if (g_app.conn_count == 0) {
        add_connection_profile("Local DLNA Server", "127.0.0.1", 8200, "/rootDesc.xml", "/ctl/ContentDir");
    }
}

static void save_config(void) {
    WritePrivateProfileStringA("General", "LocalBase", g_app.local_base, g_app.ini_path);

    char buf[32];
    snprintf(buf, sizeof(buf), "%d", g_app.conn_count);
    WritePrivateProfileStringA("Connections", "Count", buf, g_app.ini_path);

    for (int i = 0; i < g_app.conn_count; i++) {
        char sec[32], port_s[16];
        snprintf(sec, sizeof(sec), "Conn%d", i);
        snprintf(port_s, sizeof(port_s), "%d", g_app.connections[i].port);
        WritePrivateProfileStringA(sec, "Name", g_app.connections[i].name, g_app.ini_path);
        WritePrivateProfileStringA(sec, "Server", g_app.connections[i].server, g_app.ini_path);
        WritePrivateProfileStringA(sec, "Port", port_s, g_app.ini_path);
        WritePrivateProfileStringA(sec, "DescPath", g_app.connections[i].desc_path, g_app.ini_path);
        WritePrivateProfileStringA(sec, "ControlURL", g_app.connections[i].control_url, g_app.ini_path);
        WritePrivateProfileStringA(sec, "RootID", g_app.connections[i].root_obj_id, g_app.ini_path);
    }
}

/* --------------------------------------------------------------------------
 * HTTP / XML / URL Parsing Helpers
 * -------------------------------------------------------------------------- */
static int parse_http_url(const char *url, char *host, size_t host_max,
                          int *port, char *path, size_t path_max) {
    if (_strnicmp(url, "http://", 7) != 0) return 0;
    const char *p = url + 7;
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_max) hlen = host_max - 1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = atoi(colon + 1);
    } else {
        size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
        if (hlen >= host_max) hlen = host_max - 1;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = 80;
    }

    if (slash) {
        strncpy(path, slash, path_max - 1);
        path[path_max - 1] = '\0';
    } else {
        strcpy(path, "/");
    }
    return 1;
}

static SOCKET connect_with_timeout(const char *host, int port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)port);
    addr.sin_addr.s_addr = inet_addr(host);

    if (addr.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (!he) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));
    }

    u_long nonblock = 1;
    ioctlsocket(s, FIONBIO, &nonblock);

    connect(s, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (select(0, NULL, &wfds, NULL, &tv) <= 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }

    nonblock = 0;
    ioctlsocket(s, FIONBIO, &nonblock);

    DWORD rcv_to = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&rcv_to, sizeof(rcv_to));
    return s;
}

/* Performs an HTTP GET or POST and returns a heap-allocated response body */
static char *http_request_alloc(const char *host, int port, const char *method,
                                const char *path, const char *extra_headers,
                                const char *body, size_t *out_body_len) {
    SOCKET s = connect_with_timeout(host, port, 2500);
    if (s == INVALID_SOCKET) return NULL;

    int body_len = body ? (int)strlen(body) : 0;
    char req_hdr[2048];
    int hdr_len = snprintf(req_hdr, sizeof(req_hdr),
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: Windows/10.0 UPnP/1.0 DLNA2C/1.0\r\n"
        "Connection: close\r\n"
        "%s"
        "Content-Length: %d\r\n\r\n",
        method, path, host, port,
        extra_headers ? extra_headers : "",
        body_len);

    send(s, req_hdr, hdr_len, 0);
    if (body && body_len > 0) {
        send(s, body, body_len, 0);
    }

    size_t cap = 16384;
    size_t len = 0;
    char *resp = (char *)malloc(cap);
    if (!resp) {
        closesocket(s);
        return NULL;
    }

    char chunk[4096];
    int n;
    while ((n = recv(s, chunk, sizeof(chunk), 0)) > 0) {
        if (len + (size_t)n + 1 >= cap) {
            cap *= 2;
            char * nr = (char *)realloc(resp, cap);
            if (!nr) { free(resp); closesocket(s); return NULL; }
            resp = nr;
        }
        memcpy(resp + len, chunk, (size_t)n);
        len += (size_t)n;
    }
    resp[len] = '\0';
    closesocket(s);

    char *hdr_end = strstr(resp, "\r\n\r\n");
    if (!hdr_end) {
        free(resp);
        return NULL;
    }

    size_t hdr_bytes = (size_t)((hdr_end + 4) - resp);
    size_t payload_len = len - hdr_bytes;
    memmove(resp, hdr_end + 4, payload_len + 1);
    if (out_body_len) *out_body_len = payload_len;
    return resp;
}

/* Extracts the inner text of an XML tag (ignoring namespace prefixes like <dc:title>) */
static int xml_get_tag_value(const char *xml, const char *limit,
                             const char *tag_name, char *out, size_t out_max) {
    const char *cur = xml;
    size_t tlen = strlen(tag_name);

    while (cur && (!limit || cur < limit)) {
        const char *lt = strchr(cur, '<');
        if (!lt || (limit && lt >= limit)) break;
        const char * p = lt + 1;
        if (*p == '/' || *p == '?' || *p == '!') {
            cur = p + 1;
            continue;
        }

        /* Skip optional namespace prefix (e.g., dc: or upnp:) */
        const char *gt = strchr(p, '>');
        if (!gt || (limit && gt >= limit)) break;

        const char *colon = strchr(p, ':');
        const char *name_start = (colon && colon < gt && (colon - p) < 16) ? (colon + 1) : p;

        if (_strnicmp(name_start, tag_name, tlen) == 0 &&
            (name_start[tlen] == '>' || isspace((unsigned char)name_start[tlen]))) {
            const char *val_start = gt + 1;
            /* Find closing tag </...tag_name> */
            const char *close_lt = val_start;
            while ((close_lt = strstr(close_lt, "</")) != NULL) {
                if (limit && close_lt >= limit) return 0;
                const char *cp = close_lt + 2;
                const char *ccolon = strchr(cp, ':');
                const char *cgt = strchr(cp, '>');
                const char *cname = (ccolon && cgt && ccolon < cgt) ? (ccolon + 1) : cp;
                if (_strnicmp(cname, tag_name, tlen) == 0 && cname[tlen] == '>') {
                    size_t vlen = (size_t)(close_lt - val_start);
                    if (vlen >= out_max) vlen = out_max - 1;
                    memcpy(out, val_start, vlen);
                    out[vlen] = '\0';
                    return 1;
                }
                close_lt += 2;
            }
            return 0;
        }
        cur = gt + 1;
    }
    return 0;
}

/* Extracts an XML attribute value (e.g., id="123" or size="456") from an opening tag */
static int xml_get_attr(const char *tag_open, const char *tag_gt,
                        const char *attr_name, char *out, size_t out_max) {
    size_t alen = strlen(attr_name);
    const char *p = tag_open;
    while (p < tag_gt) {
        if (_strnicmp(p, attr_name, alen) == 0 &&
            (p == tag_open || isspace((unsigned char)*(p - 1)))) {
            const char *eq = p + alen;
            while (eq < tag_gt && isspace((unsigned char)*eq)) eq++;
            if (eq < tag_gt && *eq == '=') {
                eq++;
                while (eq < tag_gt && isspace((unsigned char)*eq)) eq++;
                if (eq < tag_gt && (*eq == '\"' || *eq == '\'')) {
                    char q = *eq++;
                    const char *end_q = strchr(eq, q);
                    if (end_q && end_q < tag_gt) {
                        size_t vlen = (size_t)(end_q - eq);
                        if (vlen >= out_max) vlen = out_max - 1;
                        memcpy(out, eq, vlen);
                        out[vlen] = '\0';
                        return 1;
                    }
                }
            }
        }
        p++;
    }
    return 0;
}

/* In-place XML entity unescaping (&lt; -> <, &gt; -> >, &quot; -> ", &apos; -> ', &amp; -> &) */
static void xml_unescape_inplace(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '&') {
            if (strncmp(r, "&lt;", 4) == 0)        { *w++ = '<';  r += 4; continue; }
            if (strncmp(r, "&gt;", 4) == 0)        { *w++ = '>';  r += 4; continue; }
            if (strncmp(r, "&quot;", 6) == 0)      { *w++ = '\"'; r += 6; continue; }
            if (strncmp(r, "&apos;", 6) == 0)      { *w++ = '\''; r += 6; continue; }
            if (strncmp(r, "&#39;", 5) == 0)       { *w++ = '\''; r += 5; continue; }
            if (strncmp(r, "&amp;", 5) == 0)       { *w++ = '&';  r += 5; continue; }
        }
        *w++ = *r++;
    }
    *w = '\0';
}

/* --------------------------------------------------------------------------
 * Phase 1 & 2: SSDP Multicast Discovery & Root Description Parsing
 * -------------------------------------------------------------------------- */
static int dlna_fetch_device_info(const char *host, int port, const char *desc_path,
                                  char *out_friendly, size_t friendly_max,
                                  char *out_ctrl_url, size_t ctrl_max) {
    char *xml = http_request_alloc(host, port, "GET", desc_path, NULL, NULL, NULL);
    if (!xml) return 0;

    if (!xml_get_tag_value(xml, NULL, "friendlyName", out_friendly, friendly_max)) {
        snprintf(out_friendly, friendly_max, "DLNA Server (%s)", host);
    }

    /* Locate ContentDirectory service block and extract <controlURL> */
    out_ctrl_url[0] = '\0';
    const char *cd = strstr(xml, "ContentDirectory:");
    if (cd) {
        const char *svc_end = strstr(cd, "</service>");
        char raw_ctrl[256] = {0};
        if (xml_get_tag_value(cd, svc_end, "controlURL", raw_ctrl, sizeof(raw_ctrl))) {
            if (_strnicmp(raw_ctrl, "http://", 7) == 0) {
                char dummy_h[128];
                int dummy_p;
                parse_http_url(raw_ctrl, dummy_h, sizeof(dummy_h), &dummy_p, out_ctrl_url, ctrl_max);
            } else if (raw_ctrl[0] == '/') {
                strncpy(out_ctrl_url, raw_ctrl, ctrl_max - 1);
            } else {
                snprintf(out_ctrl_url, ctrl_max, "/%s", raw_ctrl);
            }
        }
    }
    if (!out_ctrl_url[0]) {
        strncpy(out_ctrl_url, "/ctl/ContentDir", ctrl_max - 1);
    }

    free(xml);
    return 1;
}

static void dlna_ssdp_discover(void) {
    add_log("Scanning LAN via SSDP multicast (239.255.255.250:1900)...");
    set_progress(20);
    UpdateWindow(g_app.hMain);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        add_log("SSDP Error: Could not create UDP socket.");
        set_progress(0);
        return;
    }

    struct sockaddr_in mcast;
    memset(&mcast, 0, sizeof(mcast));
    mcast.sin_family      = AF_INET;
    mcast.sin_port        = htons(SSDP_PORT);
    mcast.sin_addr.s_addr = inet_addr(SSDP_MULTICAST_IP);

    static const char *search_targets[] = {
        "urn:schemas-upnp-org:device:MediaServer:1",
        "urn:schemas-upnp-org:service:ContentDirectory:1",
        "upnp:rootdevice"
    };

    /* Send M-SEARCH out on default route and every local IPv4 interface */
    char host_name[256];
    struct hostent *he = (gethostname(host_name, sizeof(host_name)) == 0) ? gethostbyname(host_name) : NULL;

    for (int t = 0; t < 3; t++) {
        char req[512];
        int req_len = snprintf(req, sizeof(req),
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: %s:%d\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: %s\r\n\r\n",
            SSDP_MULTICAST_IP, SSDP_PORT, search_targets[t]);

        sendto(s, req, req_len, 0, (struct sockaddr *)&mcast, sizeof(mcast));

        if (he) {
            for (int i = 0; he->h_addr_list[i] != NULL; i++) {
                struct in_addr iface;
                memcpy(&iface, he->h_addr_list[i], sizeof(struct in_addr));
                setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&iface, sizeof(iface));
                sendto(s, req, req_len, 0, (struct sockaddr *)&mcast, sizeof(mcast));
            }
        }
    }

    int discovered = 0;
    DWORD start_tick = GetTickCount();

    while (GetTickCount() - start_tick < 1500) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        struct timeval tv = { 0, 250000 };
        if (select(0, &rfds, NULL, NULL, &tv) <= 0) continue;

        char buf[2048];
        struct sockaddr_in from;
        int from_len = sizeof(from);
        int n = recvfrom(s, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &from_len);
        if (n <= 0) continue;
        buf[n] = '\0';

        /* Extract LOCATION header case-insensitively */
        const char *loc = strstr(buf, "LOCATION:");
        if (!loc) loc = strstr(buf, "Location:");
        if (!loc) loc = strstr(buf, "location:");
        if (!loc) continue;

        loc += 9;
        while (*loc == ' ' || *loc == '\t') loc++;
        char url[512] = {0};
        size_t u = 0;
        while (loc[u] && loc[u] != '\r' && loc[u] != '\n' && u < sizeof(url) - 1) {
            url[u] = loc[u];
            u++;
        }
        url[u] = '\0';

        char srv_host[128] = {0}, desc_path[256] = {0};
        int srv_port = 80;
        if (parse_http_url(url, srv_host, sizeof(srv_host), &srv_port, desc_path, sizeof(desc_path))) {
            char friendly[128] = {0}, ctrl_url[256] = {0};
            if (dlna_fetch_device_info(srv_host, srv_port, desc_path,
                                       friendly, sizeof(friendly), ctrl_url, sizeof(ctrl_url))) {
                add_connection_profile(friendly, srv_host, srv_port, desc_path, ctrl_url);
                discovered++;
            }
        }
    }

    closesocket(s);
    save_config();
    refresh_conn_combo();
    set_progress(100);
    add_log("SSDP Scan complete: found %d DLNA MediaServer response(s).", discovered);
}

/* --------------------------------------------------------------------------
 * Phase 3: SOAP ContentDirectory Browse & DIDL-Lite Parser
 * -------------------------------------------------------------------------- */
static void disconnect_all(void) {
    g_app.is_connected = 0;
    g_app.remote_count = 0;
    g_app.nav_depth    = 0;
    update_remote_list();
    SetWindowTextA(g_app.hBtnConnect, "Connect");
    SetWindowTextA(g_app.hLblRemote, "Remote DLNA Server (Disconnected)");
    add_log("Disconnected from DLNA server.");
}

static int connect_selected_profile(void) {
    if (g_app.selected_conn_idx < 0 || g_app.selected_conn_idx >= g_app.conn_count)
        return 0;

    ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
    add_log("Connecting to %s (%s:%d%s)...", p->name, p->server, p->port, p->desc_path);

    char friendly[128] = {0}, ctrl_url[256] = {0};
    if (!dlna_fetch_device_info(p->server, p->port, p->desc_path,
                                friendly, sizeof(friendly), ctrl_url, sizeof(ctrl_url))) {
        add_log("Failed to fetch UPnP description from http://%s:%d%s",
                p->server, p->port, p->desc_path);
        return 0;
    }

    strncpy(p->name, friendly, sizeof(p->name) - 1);
    if (!p->control_url[0]) {
        strncpy(p->control_url, ctrl_url, sizeof(p->control_url) - 1);
    }

    strncpy(g_app.active_server, p->server, sizeof(g_app.active_server) - 1);
    g_app.active_port = p->port;
    strncpy(g_app.active_control_url, p->control_url[0] ? p->control_url : ctrl_url,
            sizeof(g_app.active_control_url) - 1);
    strncpy(g_app.active_friendly_name, friendly, sizeof(g_app.active_friendly_name) - 1);

    strncpy(g_app.remote_base, p->root_obj_id[0] ? p->root_obj_id : "0", sizeof(g_app.remote_base) - 1);
    snprintf(g_app.remote_title_path, sizeof(g_app.remote_title_path), "[%s] /", friendly);
    g_app.nav_depth    = 0;
    g_app.is_connected = 1;

    SetWindowTextA(g_app.hBtnConnect, "Disconnect");
    save_config();
    refresh_conn_combo();
    list_remote();
    return 1;
}

static void add_remote_item(const char *name, int is_dir, uint64_t size,
                            const char *obj_id, const char *parent_id,
                            const char *res_url, const char *mime) {
    g_app.remote_items = (DirectoryItem *)realloc(
        g_app.remote_items, (g_app.remote_count + 1) * sizeof(DirectoryItem));
    DirectoryItem *it = &g_app.remote_items[g_app.remote_count++];
    memset(it, 0, sizeof(*it));
    strncpy(it->path, name, sizeof(it->path) - 1);
    it->is_dir = is_dir;
    it->size   = size;
    if (obj_id)    strncpy(it->object_id, obj_id, sizeof(it->object_id) - 1);
    if (parent_id) strncpy(it->parent_id, parent_id, sizeof(it->parent_id) - 1);
    if (res_url)   strncpy(it->res_url, res_url, sizeof(it->res_url) - 1);
    if (mime)      strncpy(it->mime, mime, sizeof(it->mime) - 1);
}

static void list_remote(void) {
    g_app.remote_count = 0;
    if (!g_app.is_connected) {
        update_remote_list();
        return;
    }

    char soap_body[1024];
    snprintf(soap_body, sizeof(soap_body),
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
        "  <s:Body>\r\n"
        "    <u:Browse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\">\r\n"
        "      <ObjectID>%s</ObjectID>\r\n"
        "      <BrowseFlag>BrowseDirectChildren</BrowseFlag>\r\n"
        "      <Filter>*</Filter>\r\n"
        "      <StartingIndex>0</StartingIndex>\r\n"
        "      <RequestedCount>500</RequestedCount>\r\n"
        "      <SortCriteria></SortCriteria>\r\n"
        "    </u:Browse>\r\n"
        "  </s:Body>\r\n"
        "</s:Envelope>\r\n",
        g_app.remote_base);

    const char *soap_hdrs =
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "SOAPAction: \"urn:schemas-upnp-org:service:ContentDirectory:1#Browse\"\r\n";

    char *resp_xml = http_request_alloc(g_app.active_server, g_app.active_port,
                                        "POST", g_app.active_control_url,
                                        soap_hdrs, soap_body, NULL);
    if (!resp_xml) {
        add_log("SOAP Browse failed on http://%s:%d%s",
                g_app.active_server, g_app.active_port, g_app.active_control_url);
        update_remote_list();
        return;
    }

    /* Add [..] parent navigation entry if we are deeper than root */
    if (g_app.nav_depth > 0) {
        add_remote_item("..", 1, 0,
                        g_app.nav_id_stack[g_app.nav_depth - 1], "", "", "");
    }

    /* Extract <Result>...</Result> and unescape DIDL-Lite entities */
    const char *res_start = strstr(resp_xml, "<Result");
    if (res_start) res_start = strchr(res_start, '>');
    const char *res_end   = res_start ? strstr(res_start, "</Result>") : NULL;

    if (res_start && res_end && res_end > res_start) {
        res_start++;
        size_t dlen = (size_t)(res_end - res_start);
        char *didl = (char *)malloc(dlen + 1);
        memcpy(didl, res_start, dlen);
        didl[dlen] = '\0';

        /* Unescape first-level SOAP XML entities (&lt;container...&gt;) */
        xml_unescape_inplace(didl);

        /* Walk through all <container ...> and <item ...> blocks */
        const char *p = didl;
        while (*p) {
            const char *lt = strchr(p, '<');
            if (!lt) break;

            int is_container = (_strnicmp(lt, "<container", 10) == 0 &&
                                (isspace((unsigned char)lt[10]) || lt[10] == '>'));
            int is_item      = (_strnicmp(lt, "<item", 5) == 0 &&
                                (isspace((unsigned char)lt[5]) || lt[5] == '>'));

            if (!is_container && !is_item) {
                p = lt + 1;
                continue;
            }

            const char *tag_gt = strchr(lt, '>');
            const char *close_tag = is_container ? "</container>" : "</item>";
            const char *block_end = tag_gt ? strstr(tag_gt, close_tag) : NULL;
            if (!tag_gt || !block_end) break;

            char id[512] = {0}, parent_id[512] = {0}, title[MAX_PATH] = {0};
            xml_get_attr(lt, tag_gt, "id", id, sizeof(id));
            xml_get_attr(lt, tag_gt, "parentID", parent_id, sizeof(parent_id));
            xml_get_tag_value(tag_gt + 1, block_end, "title", title, sizeof(title));
            xml_unescape_inplace(title);
            if (!title[0]) strncpy(title, id, sizeof(title) - 1);

            if (is_container) {
                add_remote_item(title, 1, 0, id, parent_id, "", "Container");
            } else {
                char res_url[1024] = {0}, size_s[64] = {0}, proto[256] = {0};
                const char *res_tag = strstr(tag_gt + 1, "<res");
                if (res_tag && res_tag < block_end) {
                    const char *res_gt = strchr(res_tag, '>');
                    const char *res_close = res_gt ? strstr(res_gt, "</res>") : NULL;
                    if (res_gt && res_close && res_close <= block_end) {
                        xml_get_attr(res_tag, res_gt, "size", size_s, sizeof(size_s));
                        xml_get_attr(res_tag, res_gt, "protocolInfo", proto, sizeof(proto));
                        size_t ulen = (size_t)(res_close - (res_gt + 1));
                        if (ulen >= sizeof(res_url)) ulen = sizeof(res_url) - 1;
                        memcpy(res_url, res_gt + 1, ulen);
                        res_url[ulen] = '\0';
                        xml_unescape_inplace(res_url);
                    }
                }
                uint64_t fsize = _strtoui64(size_s, NULL, 10);
                add_remote_item(title, 0, fsize, id, parent_id, res_url, proto);
            }

            p = block_end + strlen(close_tag);
        }
        free(didl);
    }

    free(resp_xml);
    update_remote_list();
    SetWindowTextA(g_app.hLblRemote, g_app.remote_title_path);
    add_log("Browsed ObjectID=\"%s\": %d entries loaded.", g_app.remote_base, g_app.remote_count);
}

static void update_remote_list(void) {
    SendMessageA(g_app.hRemoteList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.remote_count; i++) {
        char line[512];
        if (g_app.remote_items[i].is_dir) {
            snprintf(line, sizeof(line), "[DIR]  %s", g_app.remote_items[i].path);
        } else {
            char sz[64];
            format_size_str(g_app.remote_items[i].size, sz, sizeof(sz));
            snprintf(line, sizeof(line), "%s   (%s)", g_app.remote_items[i].path, sz);
        }
        SendMessageA(g_app.hRemoteList, LB_ADDSTRING, 0, (LPARAM)line);
    }
}

/* --------------------------------------------------------------------------
 * Local Filesystem Pane Enumeration
 * -------------------------------------------------------------------------- */
static void add_local_item(const char *name, int is_dir, uint64_t size) {
    g_app.local_items = (DirectoryItem *)realloc(
        g_app.local_items, (g_app.local_count + 1) * sizeof(DirectoryItem));
    DirectoryItem *it = &g_app.local_items[g_app.local_count++];
    memset(it, 0, sizeof(*it));
    strncpy(it->path, name, sizeof(it->path) - 1);
    it->is_dir = is_dir;
    it->size   = size;
}

static void list_local(void) {
    g_app.local_count = 0;
    size_t blen = strlen(g_app.local_base);
    while (blen > 3 && (g_app.local_base[blen - 1] == '\\' || g_app.local_base[blen - 1] == '/')) {
        g_app.local_base[--blen] = '\0';
    }

    char pattern[MAX_PATH];
    if (blen <= 3 && g_app.local_base[1] == ':')
        snprintf(pattern, sizeof(pattern), "%c:\\*", g_app.local_base[0]);
    else
        snprintf(pattern, sizeof(pattern), "%s\\*", g_app.local_base);

    if (blen > 3) {
        add_local_item("..", 1, 0);
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            add_local_item(fd.cFileName, is_dir, sz);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    update_local_list();
    char lbl[MAX_PATH + 32];
    snprintf(lbl, sizeof(lbl), "Local Folder: %s", g_app.local_base);
    SetWindowTextA(g_app.hLblLocal, lbl);
}

static void update_local_list(void) {
    SendMessageA(g_app.hLocalList, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.local_count; i++) {
        char line[512];
        if (g_app.local_items[i].is_dir) {
            snprintf(line, sizeof(line), "[DIR]  %s", g_app.local_items[i].path);
        } else {
            char sz[64];
            format_size_str(g_app.local_items[i].size, sz, sizeof(sz));
            snprintf(line, sizeof(line), "%s   (%s)", g_app.local_items[i].path, sz);
        }
        SendMessageA(g_app.hLocalList, LB_ADDSTRING, 0, (LPARAM)line);
    }
}

/* --------------------------------------------------------------------------
 * Phase 4: HTTP Media Download & Direct Stream Actions (do_action)
 * -------------------------------------------------------------------------- */
static int download_dlna_item(const DirectoryItem *item) {
    if (!item->res_url[0]) {
        add_log("Selected item does not expose a downloadable <res> URL.");
        return 0;
    }

    char host[128] = {0}, uri_path[512] = {0};
    int port = 80;
    if (!parse_http_url(item->res_url, host, sizeof(host), &port, uri_path, sizeof(uri_path))) {
        add_log("Invalid resource URL: %s", item->res_url);
        return 0;
    }

    /* Sanitize local filename and append extension from URL if title lacks one */
    char clean_name[MAX_PATH];
    strncpy(clean_name, item->path, sizeof(clean_name) - 1);
    clean_name[sizeof(clean_name) - 1] = '\0';
    for (int i = 0; clean_name[i]; i++) {
        if (strchr("<>:\"/\\|?*", clean_name[i])) clean_name[i] = '_';
    }
    if (!strchr(clean_name, '.')) {
        const char *url_ext = strrchr(uri_path, '.');
        if (url_ext && strlen(url_ext) <= 6) strcat(clean_name, url_ext);
        else if (strstr(item->mime, "mp4")) strcat(clean_name, ".mp4");
        else if (strstr(item->mime, "mpeg")) strcat(clean_name, ".mp3");
    }

    char dest_path[MAX_PATH];
    snprintf(dest_path, sizeof(dest_path), "%s\\%s", g_app.local_base, clean_name);

    SOCKET s = connect_with_timeout(host, port, 3000);
    if (s == INVALID_SOCKET) {
        add_log("Failed to connect to media stream %s:%d", host, port);
        return 0;
    }

    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: Windows/10.0 UPnP/1.0 DLNA2C/1.0\r\n"
        "transferMode.dlna.org: Streaming\r\n"
        "getcontentFeatures.dlna.org: 1\r\n"
        "Connection: close\r\n\r\n",
        uri_path, host, port);
    send(s, req, req_len, 0);

    FILE *fp = fopen(dest_path, "wb");
    if (!fp) {
        closesocket(s);
        add_log("Could not open local file for writing: %s", dest_path);
        return 0;
    }

    char buf[65536];
    int header_parsed = 0;
    uint64_t total_expected = item->size;
    uint64_t total_written  = 0;
    int n;

    set_progress(0);
    while ((n = recv(s, buf, sizeof(buf), 0)) > 0) {
        if (!header_parsed) {
            buf[n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1] = '\0';
            char *hdr_end = strstr(buf, "\r\n\r\n");
            if (hdr_end) {
                header_parsed = 1;
                const char *cl = strstr(buf, "Content-Length:");
                if (!cl) cl = strstr(buf, "content-length:");
                if (cl) total_expected = _strtoui64(cl + 15, NULL, 10);

                size_t body_offset = (size_t)((hdr_end + 4) - buf);
                size_t body_bytes  = (size_t)n - body_offset;
                if (body_bytes > 0) {
                    fwrite(buf + body_offset, 1, body_bytes, fp);
                    total_written += body_bytes;
                }
            }
        } else {
            fwrite(buf, 1, (size_t)n, fp);
            total_written += (uint64_t)n;
        }

        if (total_expected > 0) {
            int pct = (int)((total_written * 100ULL) / total_expected);
            set_progress(pct);
        }
        MSG msg;
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    fclose(fp);
    closesocket(s);
    set_progress(100);
    list_local();
    add_log("Downloaded \"%s\" (%llu bytes) to %s",
            clean_name, (unsigned long long)total_written, g_app.local_base);
    return 1;
}

/* --------------------------------------------------------------------------
 * Modal Dialogs (EditConnWndProc, RenameWndProc, CreateDirWndProc)
 * -------------------------------------------------------------------------- */
static LRESULT CALLBACK EditConnWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            ConnectionProfile *p = (g_app.selected_conn_idx >= 0 && g_app.selected_conn_idx < g_app.conn_count)
                                   ? &g_app.connections[g_app.selected_conn_idx] : NULL;

            CreateWindowA("STATIC", "Profile Name:", WS_CHILD | WS_VISIBLE, 15, 18, 105, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", p ? p->name : "DLNA Server",
                            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 125, 15, 220, 22, hwnd, (HMENU)IDE_NAME, g_hInst, NULL);

            CreateWindowA("STATIC", "Server IP / Host:", WS_CHILD | WS_VISIBLE, 15, 48, 105, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", p ? p->server : "127.0.0.1",
                            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 125, 45, 145, 22, hwnd, (HMENU)IDE_SERVER, g_hInst, NULL);

            CreateWindowA("STATIC", "Port:", WS_CHILD | WS_VISIBLE, 275, 48, 30, 18, hwnd, NULL, g_hInst, NULL);
            char port_s[16];
            snprintf(port_s, sizeof(port_s), "%d", p ? p->port : 8200);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", port_s,
                            WS_CHILD | WS_VISIBLE | ES_NUMBER, 305, 45, 40, 22, hwnd, (HMENU)IDE_PORT, g_hInst, NULL);

            CreateWindowA("STATIC", "Root XML Path:", WS_CHILD | WS_VISIBLE, 15, 78, 105, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", p ? p->desc_path : "/rootDesc.xml",
                            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 125, 75, 220, 22, hwnd, (HMENU)IDE_SHARE, g_hInst, NULL);

            CreateWindowA("STATIC", "Control URL:", WS_CHILD | WS_VISIBLE, 15, 108, 105, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", p ? p->control_url : "/ctl/ContentDir",
                            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 125, 105, 220, 22, hwnd, (HMENU)IDE_USER, g_hInst, NULL);

            CreateWindowA("STATIC", "Root ObjectID:", WS_CHILD | WS_VISIBLE, 15, 138, 105, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", p ? p->root_obj_id : "0",
                            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 125, 135, 220, 22, hwnd, (HMENU)IDE_PASS, g_hInst, NULL);

            CreateWindowA("BUTTON", "Test XML", WS_CHILD | WS_VISIBLE, 15, 175, 75, 25, hwnd, (HMENU)IDB_TEST, g_hInst, NULL);
            CreateWindowA("BUTTON", "Add New", WS_CHILD | WS_VISIBLE, 95, 175, 75, 25, hwnd, (HMENU)IDB_ADD, g_hInst, NULL);
            CreateWindowA("BUTTON", "Delete", WS_CHILD | WS_VISIBLE, 175, 175, 65, 25, hwnd, (HMENU)IDB_DELETE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Save", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 245, 175, 50, 25, hwnd, (HMENU)IDB_SAVE, g_hInst, NULL);
            CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE, 300, 175, 45, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);

            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hFont);
            return 0;
        }

        case WM_COMMAND: {
            WORD id = LOWORD(wParam);
            char name[64], srv[128], desc[256], ctrl[256], robj[64];
            GetDlgItemTextA(hwnd, IDE_NAME, name, sizeof(name));
            GetDlgItemTextA(hwnd, IDE_SERVER, srv, sizeof(srv));
            int port = (int)GetDlgItemInt(hwnd, IDE_PORT, NULL, FALSE);
            GetDlgItemTextA(hwnd, IDE_SHARE, desc, sizeof(desc));
            GetDlgItemTextA(hwnd, IDE_USER, ctrl, sizeof(ctrl));
            GetDlgItemTextA(hwnd, IDE_PASS, robj, sizeof(robj));

            if (id == IDB_TEST) {
                char friendly[128] = {0}, found_ctrl[256] = {0};
                if (dlna_fetch_device_info(srv, port, desc, friendly, sizeof(friendly), found_ctrl, sizeof(found_ctrl))) {
                    SetDlgItemTextA(hwnd, IDE_NAME, friendly);
                    SetDlgItemTextA(hwnd, IDE_USER, found_ctrl);
                    MessageBoxA(hwnd, "Successfully fetched UPnP description and ContentDirectory controlURL!",
                                friendly, MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBoxA(hwnd, "Could not reach DLNA XML description at specified host/port.",
                                "Test Failed", MB_OK | MB_ICONERROR);
                }
            }
            else if (id == IDB_ADD) {
                add_connection_profile(name, srv, port, desc, ctrl);
                g_app.selected_conn_idx = g_app.conn_count - 1;
                save_config();
                refresh_conn_combo();
                DestroyWindow(hwnd);
            }
            else if (id == IDB_SAVE) {
                if (g_app.selected_conn_idx >= 0 && g_app.selected_conn_idx < g_app.conn_count) {
                    ConnectionProfile *p = &g_app.connections[g_app.selected_conn_idx];
                    strncpy(p->name, name, sizeof(p->name) - 1);
                    strncpy(p->server, srv, sizeof(p->server) - 1);
                    p->port = port;
                    strncpy(p->desc_path, desc, sizeof(p->desc_path) - 1);
                    strncpy(p->control_url, ctrl, sizeof(p->control_url) - 1);
                    strncpy(p->root_obj_id, robj[0] ? robj : "0", sizeof(p->root_obj_id) - 1);
                } else {
                    add_connection_profile(name, srv, port, desc, ctrl);
                }
                save_config();
                refresh_conn_combo();
                DestroyWindow(hwnd);
            }
            else if (id == IDB_DELETE) {
                if (g_app.conn_count > 1 && g_app.selected_conn_idx >= 0) {
                    for (int i = g_app.selected_conn_idx; i < g_app.conn_count - 1; i++) {
                        g_app.connections[i] = g_app.connections[i + 1];
                    }
                    g_app.conn_count--;
                    g_app.selected_conn_idx = 0;
                    save_config();
                    refresh_conn_combo();
                }
                DestroyWindow(hwnd);
            }
            else if (id == IDB_CANCEL) {
                DestroyWindow(hwnd);
            }
            return 0;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK CreateDirWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            CreateWindowA("STATIC", "New Local Folder Name:", WS_CHILD | WS_VISIBLE, 15, 15, 200, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                            15, 38, 250, 22, hwnd, (HMENU)IDE_MKDIR_NAME, g_hInst, NULL);
            CreateWindowA("BUTTON", "Create", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                          105, 70, 75, 25, hwnd, (HMENU)IDB_MKDIR_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
                          190, 70, 75, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hFont);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDB_MKDIR_OK) {
                char folder[MAX_PATH] = {0}, full[MAX_PATH];
                GetDlgItemTextA(hwnd, IDE_MKDIR_NAME, folder, sizeof(folder));
                if (folder[0]) {
                    snprintf(full, sizeof(full), "%s\\%s", g_app.local_base, folder);
                    if (CreateDirectoryA(full, NULL)) {
                        list_local();
                        add_log("Created local folder: %s", full);
                    }
                }
                DestroyWindow(hwnd);
            } else if (LOWORD(wParam) == IDB_CANCEL) {
                DestroyWindow(hwnd);
            }
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK RenameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static char s_old_name[MAX_PATH];
    switch (msg) {
        case WM_CREATE: {
            CREATESTRUCTA *cs = (CREATESTRUCTA *)lParam;
            strncpy(s_old_name, cs->lpCreateParams ? (const char *)cs->lpCreateParams : "", MAX_PATH - 1);
            CreateWindowA("STATIC", "Rename Local Item To:", WS_CHILD | WS_VISIBLE, 15, 15, 200, 18, hwnd, NULL, g_hInst, NULL);
            CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", s_old_name, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                            15, 38, 250, 22, hwnd, (HMENU)IDE_RENAME_NEW, g_hInst, NULL);
            CreateWindowA("BUTTON", "Rename", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                          105, 70, 75, 25, hwnd, (HMENU)IDB_RENAME_OK, g_hInst, NULL);
            CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
                          190, 70, 75, 25, hwnd, (HMENU)IDB_CANCEL, g_hInst, NULL);
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hFont);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDB_RENAME_OK) {
                char new_name[MAX_PATH] = {0}, old_p[MAX_PATH], new_p[MAX_PATH];
                GetDlgItemTextA(hwnd, IDE_RENAME_NEW, new_name, sizeof(new_name));
                if (new_name[0]) {
                    snprintf(old_p, sizeof(old_p), "%s\\%s", g_app.local_base, s_old_name);
                    snprintf(new_p, sizeof(new_p), "%s\\%s", g_app.local_base, new_name);
                    if (MoveFileA(old_p, new_p)) {
                        list_local();
                        add_log("Renamed \"%s\" -> \"%s\"", s_old_name, new_name);
                    }
                }
                DestroyWindow(hwnd);
            } else if (LOWORD(wParam) == IDB_CANCEL) {
                DestroyWindow(hwnd);
            }
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* --------------------------------------------------------------------------
 * Main Window Procedure & Dual-Pane Action Dispatcher
 * -------------------------------------------------------------------------- */
static void refresh_conn_combo(void) {
    SendMessageA(g_app.hComboConn, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_app.conn_count; i++) {
        char entry[256];
        snprintf(entry, sizeof(entry), "%s (%s:%d)",
                 g_app.connections[i].name,
                 g_app.connections[i].server,
                 g_app.connections[i].port);
        SendMessageA(g_app.hComboConn, CB_ADDSTRING, 0, (LPARAM)entry);
    }
    if (g_app.selected_conn_idx >= g_app.conn_count) g_app.selected_conn_idx = 0;
    SendMessageA(g_app.hComboConn, CB_SETCURSEL, (WPARAM)g_app.selected_conn_idx, 0);
}

static void do_action(WORD action_id) {
    if (action_id == ID_BTN_COPY) {
        /* Copy / Download selected item from DLNA Server to Local Folder */
        int sel = (int)SendMessageA(g_app.hRemoteList, LB_GETCURSEL, 0, 0);
        if (sel < 0 || sel >= g_app.remote_count) {
            add_log("Select a media file in the Remote DLNA pane to download.");
            return;
        }
        DirectoryItem *it = &g_app.remote_items[sel];
        if (it->is_dir) {
            add_log("\"%s\" is a DLNA container; double-click to open it first.", it->path);
            return;
        }
        download_dlna_item(it);
    }
    else if (action_id == ID_BTN_MOVE) {
        /* Stream / Play selected item directly via ShellExecuteA */
        int sel = (int)SendMessageA(g_app.hRemoteList, LB_GETCURSEL, 0, 0);
        if (sel >= 0 && sel < g_app.remote_count && !g_app.remote_items[sel].is_dir) {
            DirectoryItem *it = &g_app.remote_items[sel];
            if (it->res_url[0]) {
                add_log("Launching stream: %s", it->res_url);
                ShellExecuteA(g_app.hMain, "open", it->res_url, NULL, NULL, SW_SHOWNORMAL);
            }
        } else {
            add_log("Select a remote media item to stream/play.");
        }
    }
    else if (action_id == ID_BTN_MKDIR) {
        CreateWindowExA(WS_EX_DLGMODALFRAME, "DLNAMkDirWnd", "Create Local Folder",
                        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                        CW_USEDEFAULT, CW_USEDEFAULT, 295, 135,
                        g_app.hMain, NULL, g_hInst, NULL);
    }
    else if (action_id == ID_BTN_RENAME) {
        int sel = (int)SendMessageA(g_app.hLocalList, LB_GETCURSEL, 0, 0);
        if (sel < 0 || sel >= g_app.local_count || strcmp(g_app.local_items[sel].path, "..") == 0) {
            add_log("Select a file or folder in the Local pane to rename.");
            return;
        }
        CreateWindowExA(WS_EX_DLGMODALFRAME, "DLNARenameWnd", "Rename Local Item",
                        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                        CW_USEDEFAULT, CW_USEDEFAULT, 295, 135,
                        g_app.hMain, NULL, g_hInst, (LPVOID)g_app.local_items[sel].path);
    }
    else if (action_id == ID_BTN_DELETE) {
        int sel = (int)SendMessageA(g_app.hLocalList, LB_GETCURSEL, 0, 0);
        if (sel < 0 || sel >= g_app.local_count || strcmp(g_app.local_items[sel].path, "..") == 0) {
            add_log("Select a file or folder in the Local pane to delete.");
            return;
        }
        char target[MAX_PATH];
        snprintf(target, sizeof(target), "%s\\%s", g_app.local_base, g_app.local_items[sel].path);
        if (MessageBoxA(g_app.hMain, target, "Delete Local Item?", MB_YESNO | MB_ICONWARNING) == IDYES) {
            BOOL ok = g_app.local_items[sel].is_dir ? RemoveDirectoryA(target) : DeleteFileA(target);
            if (ok) {
                list_local();
                add_log("Deleted local item: %s", target);
            } else {
                add_log("Failed to delete local item: %s", target);
            }
        }
    }
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_app.hMain = hwnd;

            g_app.hComboConn = CreateWindowA("COMBOBOX", "",
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                10, 10, 260, 200, hwnd, (HMENU)ID_COMBO_CONN, g_hInst, NULL);

            g_app.hBtnConnect = CreateWindowA("BUTTON", "Connect",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                278, 9, 90, 24, hwnd, (HMENU)ID_BTN_CONNECT, g_hInst, NULL);

            g_app.hBtnEdit = CreateWindowA("BUTTON", "Edit Server...",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                374, 9, 95, 24, hwnd, (HMENU)ID_BTN_EDIT_CONN, g_hInst, NULL);

            g_app.hBtnScan = CreateWindowA("BUTTON", "Scan LAN (SSDP)",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                475, 9, 120, 24, hwnd, (HMENU)ID_BTN_SCAN_SSDP, g_hInst, NULL);

            g_app.hLblLocal = CreateWindowA("STATIC", "Local Folder:",
                WS_CHILD | WS_VISIBLE, 10, 42, 350, 18, hwnd, NULL, g_hInst, NULL);

            g_app.hLblRemote = CreateWindowA("STATIC", "Remote DLNA Server (Disconnected)",
                WS_CHILD | WS_VISIBLE, 400, 42, 350, 18, hwnd, NULL, g_hInst, NULL);

            g_app.hLocalList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS,
                10, 62, 380, 360, hwnd, (HMENU)ID_LIST_LOCAL, g_hInst, NULL);

            g_app.hRemoteList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS,
                400, 62, 380, 360, hwnd, (HMENU)ID_LIST_REMOTE, g_hInst, NULL);

            g_app.hBtnCopy = CreateWindowA("BUTTON", "<- Download (Copy)",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 430, 135, 26, hwnd, (HMENU)ID_BTN_COPY, g_hInst, NULL);

            g_app.hBtnMove = CreateWindowA("BUTTON", "Stream / Play",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                152, 430, 115, 26, hwnd, (HMENU)ID_BTN_MOVE, g_hInst, NULL);

            g_app.hBtnRename = CreateWindowA("BUTTON", "Rename Local",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                274, 430, 105, 26, hwnd, (HMENU)ID_BTN_RENAME, g_hInst, NULL);

            g_app.hBtnDelete = CreateWindowA("BUTTON", "Delete Local",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                386, 430, 105, 26, hwnd, (HMENU)ID_BTN_DELETE, g_hInst, NULL);

            g_app.hBtnMkDir = CreateWindowA("BUTTON", "New Local Dir",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                498, 430, 105, 26, hwnd, (HMENU)ID_BTN_MKDIR, g_hInst, NULL);

            g_app.hProgress = CreateWindowExA(0, PROGRESS_CLASSA, NULL,
                WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                615, 433, 165, 20, hwnd, NULL, g_hInst, NULL);

            g_app.hStatus = CreateWindowExA(0, STATUSCLASSNAMEA, "Ready. Click 'Scan LAN (SSDP)' or 'Connect'.",
                WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                0, 0, 0, 0, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);

            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hFont);

            refresh_conn_combo();
            list_local();
            return 0;
        }

        case WM_SIZE: {
            int w = LOWORD(lParam);
            int h = HIWORD(lParam);
            SendMessageA(g_app.hStatus, WM_SIZE, 0, 0);

            int pane_w = (w - 30) / 2;
            int list_h = h - 135;
            if (list_h < 100) list_h = 100;

            MoveWindow(g_app.hLblLocal,   10,          42, pane_w, 18, TRUE);
            MoveWindow(g_app.hLblRemote,  20 + pane_w, 42, pane_w, 18, TRUE);
            MoveWindow(g_app.hLocalList,  10,          62, pane_w, list_h, TRUE);
            MoveWindow(g_app.hRemoteList, 20 + pane_w, 62, pane_w, list_h, TRUE);

            int btn_y = 68 + list_h;
            MoveWindow(g_app.hBtnCopy,   10,  btn_y, 135, 26, TRUE);
            MoveWindow(g_app.hBtnMove,   152, btn_y, 115, 26, TRUE);
            MoveWindow(g_app.hBtnRename, 274, btn_y, 105, 26, TRUE);
            MoveWindow(g_app.hBtnDelete, 386, btn_y, 105, 26, TRUE);
            MoveWindow(g_app.hBtnMkDir,  498, btn_y, 105, 26, TRUE);
            if (w > 630) {
                MoveWindow(g_app.hProgress, 612, btn_y + 3, w - 622, 20, TRUE);
            }
            return 0;
        }

        case WM_COMMAND: {
            WORD id   = LOWORD(wParam);
            WORD code = HIWORD(wParam);

            if (id == ID_COMBO_CONN && code == CBN_SELCHANGE) {
                g_app.selected_conn_idx = (int)SendMessageA(g_app.hComboConn, CB_GETCURSEL, 0, 0);
            }
            else if (id == ID_BTN_CONNECT) {
                if (g_app.is_connected) disconnect_all();
                else connect_selected_profile();
            }
            else if (id == ID_BTN_EDIT_CONN) {
                CreateWindowExA(WS_EX_DLGMODALFRAME, "DLNAEditConnWnd", "Edit DLNA Server Profile",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 370, 245,
                                hwnd, NULL, g_hInst, NULL);
            }
            else if (id == ID_BTN_SCAN_SSDP) {
                dlna_ssdp_discover();
            }
            else if (id == ID_LIST_LOCAL && code == LBN_SETFOCUS) {
                g_app.active_pane = 0;
            }
            else if (id == ID_LIST_REMOTE && code == LBN_SETFOCUS) {
                g_app.active_pane = 1;
            }
            else if (id == ID_LIST_LOCAL && code == LBN_DBLCLK) {
                int sel = (int)SendMessageA(g_app.hLocalList, LB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < g_app.local_count) {
                    DirectoryItem *it = &g_app.local_items[sel];
                    if (it->is_dir) {
                        if (strcmp(it->path, "..") == 0) {
                            char *last = strrchr(g_app.local_base, '\\');
                            if (last) {
                                if (last - g_app.local_base <= 2) *(last + 1) = '\0';
                                else *last = '\0';
                            }
                        } else {
                            size_t len = strlen(g_app.local_base);
                            if (g_app.local_base[len - 1] != '\\') strcat(g_app.local_base, "\\");
                            strcat(g_app.local_base, it->path);
                        }
                        save_config();
                        list_local();
                    } else {
                        char full[MAX_PATH];
                        snprintf(full, sizeof(full), "%s\\%s", g_app.local_base, it->path);
                        ShellExecuteA(hwnd, "open", full, NULL, NULL, SW_SHOWNORMAL);
                    }
                }
            }
            else if (id == ID_LIST_REMOTE && code == LBN_DBLCLK) {
                int sel = (int)SendMessageA(g_app.hRemoteList, LB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < g_app.remote_count) {
                    DirectoryItem *it = &g_app.remote_items[sel];
                    if (it->is_dir) {
                        if (strcmp(it->path, "..") == 0) {
                            if (g_app.nav_depth > 0) {
                                g_app.nav_depth--;
                                strcpy(g_app.remote_base, g_app.nav_id_stack[g_app.nav_depth]);
                            }
                        } else {
                            if (g_app.nav_depth < MAX_NAV_DEPTH) {
                                strcpy(g_app.nav_id_stack[g_app.nav_depth], g_app.remote_base);
                                strncpy(g_app.nav_title_stack[g_app.nav_depth], it->path, 127);
                                g_app.nav_depth++;
                            }
                            strcpy(g_app.remote_base, it->object_id);
                        }
                        /* Rebuild breadcrumb title */
                        snprintf(g_app.remote_title_path, sizeof(g_app.remote_title_path),
                                 "[%s] /", g_app.active_friendly_name);
                        for (int i = 0; i < g_app.nav_depth; i++) {
                            strncat(g_app.remote_title_path, g_app.nav_title_stack[i],
                                    sizeof(g_app.remote_title_path) - strlen(g_app.remote_title_path) - 2);
                            strcat(g_app.remote_title_path, "/");
                        }
                        list_remote();
                    } else {
                        /* Double-clicking a media file streams it directly */
                        do_action(ID_BTN_MOVE);
                    }
                }
            }
            else if (id >= ID_BTN_COPY && id <= ID_BTN_MKDIR) {
                do_action(id);
            }
            return 0;
        }

        case WM_DESTROY:
            save_config();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

/* --------------------------------------------------------------------------
 * WinMain Entry Point
 * -------------------------------------------------------------------------- */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    g_hInst = hInstance;
    memset(&g_app, 0, sizeof(g_app));

    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES | ICC_BAR_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    init_ini_path();
    load_config();

    WNDCLASSA wc = {0};
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIconA(NULL, IDI_APPLICATION);
    wc.hCursor       = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "DLNA2CMainWnd";
    RegisterClassA(&wc);

    WNDCLASSA wcEdit = wc;
    wcEdit.lpfnWndProc   = EditConnWndProc;
    wcEdit.lpszClassName = "DLNAEditConnWnd";
    RegisterClassA(&wcEdit);

    WNDCLASSA wcMk = wc;
    wcMk.lpfnWndProc   = CreateDirWndProc;
    wcMk.lpszClassName = "DLNAMkDirWnd";
    RegisterClassA(&wcMk);

    WNDCLASSA wcRen = wc;
    wcRen.lpfnWndProc   = RenameWndProc;
    wcRen.lpszClassName = "DLNARenameWnd";
    RegisterClassA(&wcRen);

    HWND hwnd = CreateWindowExA(
        0, "DLNA2CMainWnd", "DLNA2C - Dual-Pane UPnP / DLNA Media Client",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 820, 530,
        NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    free(g_app.connections);
    free(g_app.remote_items);
    free(g_app.local_items);
    WSACleanup();
    return (int)msg.wParam;
}