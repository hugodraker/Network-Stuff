/* 
 * FTP Search & Index Tool
 * - Connects to an FTP server (Passive mode via WinINet).
 * - Crawls and indexes the server contents to a local cache file.
 * - Searches the index instantly.
 * - Downloads files to a local directory selected via a text-typable history combobox.
 * - Prompts on local file overwrite.
 *
 * COMPILATION:
 *   gcc -Os -s -mwindows -o ftpsearch.exe ftpsearch.c -lwininet -lcomctl32 -lshlwapi -luser32 -lgdi32
 *
 * ============================================================================
 * PUBLIC DOMAIN DEDICATION:
 * This software is released into the public domain. It is not fit for any 
 * purpose. Use entirely at your own risk.
 * ============================================================================
 */

#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <wininet.h>
#include <commctrl.h>
#include <shlwapi.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#define ID_SERVER       1001
#define ID_PORT         1002
#define ID_USER         1003
#define ID_PASS         1004
#define ID_BTN_CONNECT  1005
#define ID_LOCAL_DIR    1006
#define ID_BTN_INDEX    1007
#define ID_LAST_INDEX   1008
#define ID_SEARCH       1009
#define ID_BTN_SEARCH   1010
#define ID_BTN_DOWNLOAD 1011
#define ID_LIST         1012
#define ID_STATUSBAR    1013
#define WM_INDEX_DONE   (WM_USER + 1)
#define WM_INDEX_UPDATE (WM_USER + 2)
// Ensure this struct definition is placed BEFORE the g_connections array and your functions.
#define MAX_CONNECTIONS 50
// Add these ID definitions near the top of your file
#define ID_REMOTE_DIR   1020
#define ID_CHK_UPLOAD   1021
#define ID_CHK_DOWNLOAD 1022
#define ID_BTN_CLEAR      1010
#define ID_CHK_FULLPATH   1023
#define TIMER_SEARCH      1001
#define ID_BTN_CANCEL_DL  1024
#define WM_CONNECT_DONE   (WM_USER + 3)
#define WM_DOWNLOAD_DONE  (WM_USER + 4)
#define WM_DOWNLOAD_PROG  (WM_USER + 5)
// Globals
static HINSTANCE g_hInst;
static HWND g_hMain, g_hList, g_hStatus;
static HWND g_hServer, g_hPort, g_hUser, g_hPass, g_hLocalDir;
static HWND g_hSearch, g_hLblLastIndex, g_hBtnIndex;

static char g_ini_path[MAX_PATH];
static char g_index_path[MAX_PATH];
static HINTERNET g_hInternet = NULL;
static HINTERNET g_hFtpSession = NULL;

static HANDLE g_hThread = NULL;
static int g_is_indexing = 0;

static int g_conn_count = 0;

// Add these to your globals
static HWND g_hRemoteDir;
static HWND g_hChkUpload;
static HWND g_hChkDownload;
static char g_current_remote_dir[MAX_PATH];


// Forward declarations
static void LoadConfig();
static void SaveConfig();
static void ConnectFTP();
static void DisconnectFTP();
static void DoSearch();
static void DoDownload();
static void AddLocalDirHistory(const char *dir);

typedef struct {
    char server[128];
    char port[16];
    char user[64];
    char pass[64];
} FtpConnection;

// Add these structures and variables near your other globals
typedef struct _FtpItem {
    char name[MAX_PATH];
    DWORD is_dir;
    DWORD size;
    DWORD attrs;
    FILETIME ft;
    struct _FtpItem *next;
} FtpItem;

typedef struct {
    char type[5];
    char path[MAX_PATH];
    DWORD size;
    char date[32];
    char perms[16];
} SearchResult;

typedef struct {
    char remote[MAX_PATH];
    char local[MAX_PATH];
    DWORD size;
} DownloadItem;

static FtpConnection g_connections[MAX_CONNECTIONS];

static int g_upload_index = 0;
static int g_download_index = 0;
static SearchResult *g_results = NULL;
static int g_result_count = 0;
static int g_result_capacity = 0;
static int g_sort_col = 1; 
// Default to path column
static int g_sort_dir = 1;

static HWND g_hChkFullPath;
static int g_show_full_path = 1;

static HWND g_hProgress;
static HWND g_hBtnCancelDL;
static HANDLE g_hConnThread = NULL;
static HANDLE g_hDlThread = NULL;
static int g_cancel_download = 0;

static DownloadItem *g_dl_items = NULL;
static int g_dl_count = 0;
// Helper: Safely extracts a pipe-delimited segment from read-only memory
static const char* ExtractField(const char *start, const char *end, char *dest, size_t max_len) {
    dest[0] = '\0';
    if (start >= end) return end;
    const char *pipe = (const char*)memchr(start, '|', end - start);
    size_t len = pipe ? (size_t)(pipe - start) : (size_t)(end - start);
    if (len >= max_len) len = max_len - 1;
    memcpy(dest, start, len);
    dest[len] = '\0';
    return pipe ? pipe + 1 : end;
}

// Helper: Ultra-fast case-insensitive memory scan (doesn't require null-terminated strings)
static const char* mem_find_ia(const char* haystack, size_t h_len, const char* lower_needle, size_t n_len) {
    if (n_len == 0) return haystack;
    if (h_len < n_len) return NULL;
    for (size_t i = 0; i <= h_len - n_len; i++) {
        if (tolower((unsigned char)haystack[i]) == (unsigned char)lower_needle[0]) {
            size_t j = 1;
            while (j < n_len && tolower((unsigned char)haystack[i+j]) == (unsigned char)lower_needle[j]) {
                j++;
            }
            if (j == n_len) return haystack + i;
        }
    }
    return NULL;
}

// Utility: Trim whitespace
static void trim_str(char *str) {
    char *p = str; int l = strlen(p);
    while (l > 0 && (p[l-1] == ' ' || p[l-1] == '\r' || p[l-1] == '\n' || p[l-1] == '\t')) p[--l] = 0;
    while (*p && (*p == ' ' || *p == '\t')) { p++; l--; }
    memmove(str, p, l + 1);
}

// Comparison function for qsort
static int compare_results(const void *a, const void *b) {
    SearchResult *resA = (SearchResult *)a;
    SearchResult *resB = (SearchResult *)b;
    int cmp = 0;
    
    switch (g_sort_col) {
        case 0: cmp = strcmp(resA->type, resB->type); break;
        case 1: cmp = _stricmp(resA->path, resB->path); break;
        case 2: 
            if (resA->size < resB->size) cmp = -1;
            else if (resA->size > resB->size) cmp = 1;
            break;
        case 3: cmp = strcmp(resA->date, resB->date); break;
        case 4: cmp = strcmp(resA->perms, resB->perms); break;
    }
    return cmp * g_sort_dir;
}

static void UpdateIndexPath() {
    char srv[128];
    GetWindowTextA(g_hServer, srv, sizeof(srv));
    trim_str(srv);
    if (srv[0] == '\0') strcpy(srv, "default");
    
    // Sanitize illegal filename characters from the server address/host
    for (int i = 0; srv[i]; i++) {
        if (srv[i] == '\\' || srv[i] == '/' || srv[i] == ':' || srv[i] == '*' || 
            srv[i] == '?' || srv[i] == '"' || srv[i] == '<' || srv[i] == '>' || 
            srv[i] == '|' || srv[i] == '.') {
            srv[i] = '_';
        }
    }
    
    char base[MAX_PATH];
    GetModuleFileNameA(NULL, base, MAX_PATH);
    char *slash = strrchr(base, '\\');
    if (slash) *(slash + 1) = '\0';
    snprintf(g_index_path, MAX_PATH, "%sidx_%s.dat", base, srv);
}

// Add these helper functions right below your `trim_str` utility:

static void GetConnID(char *out_id, size_t max_len) {
    char srv[128], prt[16];
    GetWindowTextA(g_hServer, srv, sizeof(srv)); trim_str(srv);
    GetWindowTextA(g_hPort, prt, sizeof(prt)); trim_str(prt);
    if (srv[0] == '\0') strcpy(srv, "default");
    if (prt[0] == '\0') strcpy(prt, "21");
    
    snprintf(out_id, max_len, "%s_%s", srv, prt);
    // Sanitize illegal filename characters
    for (int i = 0; out_id[i]; i++) {
        if (out_id[i] == '\\' || out_id[i] == '/' || out_id[i] == ':' || out_id[i] == '*' || 
            out_id[i] == '?' || out_id[i] == '"' || out_id[i] == '<' || out_id[i] == '>' || 
            out_id[i] == '|' || out_id[i] == '.') {
            out_id[i] = '_';
        }
    }
}

static void InitPaths() {
    GetModuleFileNameA(NULL, g_ini_path, MAX_PATH);
    char *ext = strrchr(g_ini_path, '.');
    if (ext) strcpy(ext, ".ini"); else strcat(g_ini_path, ".ini");
    UpdateIndexPath();
}
// GUI Font Enum
BOOL CALLBACK SetFontEnumProc(HWND hwnd, LPARAM lParam) {
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

static void CreateControls(HWND hwnd) {
    int y = 10;
    
    CreateWindowA("STATIC", "Server:", WS_CHILD|WS_VISIBLE, 10, y+3, 50, 20, hwnd, NULL, g_hInst, NULL);
    g_hServer = CreateWindowExA(0, "COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWN|CBS_SORT|CBS_AUTOHSCROLL|WS_VSCROLL, 60, y, 140, 200, hwnd, (HMENU)ID_SERVER, g_hInst, NULL);
    
    CreateWindowA("STATIC", "Port:", WS_CHILD|WS_VISIBLE, 210, y+3, 40, 20, hwnd, NULL, g_hInst, NULL);
    g_hPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "21", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 250, y, 40, 22, hwnd, (HMENU)ID_PORT, g_hInst, NULL);
    
    CreateWindowA("STATIC", "User:", WS_CHILD|WS_VISIBLE, 300, y+3, 40, 20, hwnd, NULL, g_hInst, NULL);
    g_hUser = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "anonymous", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 340, y, 100, 22, hwnd, (HMENU)ID_USER, g_hInst, NULL);
    
    CreateWindowA("STATIC", "Pass:", WS_CHILD|WS_VISIBLE, 450, y+3, 40, 20, hwnd, NULL, g_hInst, NULL);
    g_hPass = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_PASSWORD|ES_AUTOHSCROLL, 490, y, 100, 22, hwnd, (HMENU)ID_PASS, g_hInst, NULL);
    
    CreateWindowA("BUTTON", "Connect/Save", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 600, y, 100, 24, hwnd, (HMENU)ID_BTN_CONNECT, g_hInst, NULL);
    
    y += 35;
    CreateWindowA("STATIC", "Remote Dir:", WS_CHILD|WS_VISIBLE, 10, y+3, 70, 20, hwnd, NULL, g_hInst, NULL);
    g_hRemoteDir = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "/", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 80, y, 150, 22, hwnd, (HMENU)ID_REMOTE_DIR, g_hInst, NULL);
    
    CreateWindowA("STATIC", "Local Dir:", WS_CHILD|WS_VISIBLE, 240, y+3, 60, 20, hwnd, NULL, g_hInst, NULL);
    g_hLocalDir = CreateWindowExA(0, "COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWN|CBS_AUTOHSCROLL|WS_VSCROLL, 300, y, 360, 200, hwnd, (HMENU)ID_LOCAL_DIR, g_hInst, NULL);
    
    y += 35;
    g_hBtnIndex = CreateWindowA("BUTTON", "Index Site", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 10, y, 100, 24, hwnd, (HMENU)ID_BTN_INDEX, g_hInst, NULL);
    g_hChkUpload = CreateWindowA("BUTTON", "Upload Index", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 120, y+2, 100, 20, hwnd, (HMENU)ID_CHK_UPLOAD, g_hInst, NULL);
    g_hChkDownload = CreateWindowA("BUTTON", "Download Index", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 230, y+2, 120, 20, hwnd, (HMENU)ID_CHK_DOWNLOAD, g_hInst, NULL);
    g_hLblLastIndex = CreateWindowA("STATIC", "Last Indexed: Never", WS_CHILD|WS_VISIBLE, 360, y+4, 300, 20, hwnd, NULL, g_hInst, NULL);
    
    y += 35;
    CreateWindowA("STATIC", "Search:", WS_CHILD|WS_VISIBLE, 10, y+3, 60, 20, hwnd, NULL, g_hInst, NULL);
    g_hSearch = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|ES_AUTOHSCROLL, 70, y, 200, 22, hwnd, (HMENU)ID_SEARCH, g_hInst, NULL);
    CreateWindowA("BUTTON", "Clear", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 280, y, 60, 24, hwnd, (HMENU)ID_BTN_CLEAR, g_hInst, NULL);
    g_hChkFullPath = CreateWindowA("BUTTON", "Show Full Path", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP, 350, y+2, 120, 20, hwnd, (HMENU)ID_CHK_FULLPATH, g_hInst, NULL);
    CreateWindowA("BUTTON", "Download Selected", WS_CHILD|WS_VISIBLE|WS_TABSTOP, 480, y, 140, 24, hwnd, (HMENU)ID_BTN_DOWNLOAD, g_hInst, NULL);

    y += 35;
    g_hList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|LVS_REPORT|LVS_SHOWSELALWAYS, 10, y, 760, 360, hwnd, (HMENU)ID_LIST, g_hInst, NULL);
    // Added LVS_EX_INFOTIP to support mouse hover path tooltips
    ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_INFOTIP);

    LVCOLUMNA lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.pszText = "Type"; lvc.cx = 50; lvc.iSubItem = 0; ListView_InsertColumn(g_hList, 0, &lvc);
    lvc.pszText = "File/Path"; lvc.cx = 360; lvc.iSubItem = 1; ListView_InsertColumn(g_hList, 1, &lvc);
    lvc.pszText = "Size (Bytes)"; lvc.cx = 80; lvc.iSubItem = 2; ListView_InsertColumn(g_hList, 2, &lvc);
    lvc.pszText = "Date Modified"; lvc.cx = 140; lvc.iSubItem = 3; ListView_InsertColumn(g_hList, 3, &lvc);
    lvc.pszText = "Perms"; lvc.cx = 60; lvc.iSubItem = 4; ListView_InsertColumn(g_hList, 4, &lvc);

    g_hStatus = CreateWindowExA(0, STATUSCLASSNAMEA, "Ready", WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);

    HFONT hF = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, ANSI_CHARSET, 0, 0, 0, 0, "Tahoma");
    EnumChildWindows(hwnd, SetFontEnumProc, (LPARAM)hF);
}

// Replace the following functions entirely:

static void UpdateLastIndexedLabel() {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(g_index_path, GetFileExInfoStandard, &fad)) {
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&fad.ftLastWriteTime, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
        char lbl[128];
        snprintf(lbl, sizeof(lbl), "Last Indexed: %04d-%02d-%02d %02d:%02d:%02d", 
            stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        SetWindowTextA(g_hLblLastIndex, lbl);
    } else {
        SetWindowTextA(g_hLblLastIndex, "Last Indexed: Never");
    }
}

static void UpdateListView() {
    SendMessageA(g_hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hList);
    
    for (int i = 0; i < g_result_count; i++) {
        LVITEMA lvi = {0}; 
        lvi.mask = LVIF_TEXT; 
        lvi.iItem = i;
        
        lvi.iSubItem = 0; lvi.pszText = g_results[i].type;
        ListView_InsertItem(g_hList, &lvi);
        
        char *display_path = g_results[i].path;
        if (!g_show_full_path) {
            char *slash = strrchr(display_path, '/');
            if (!slash) slash = strrchr(display_path, '\\');
            if (slash) display_path = slash + 1;
        }
        
        lvi.iSubItem = 1; lvi.pszText = display_path;
        ListView_SetItemText(g_hList, i, 1, lvi.pszText);
        
        char sizeStr[32]; snprintf(sizeStr, sizeof(sizeStr), "%lu", g_results[i].size);
        lvi.iSubItem = 2; lvi.pszText = sizeStr;
        ListView_SetItemText(g_hList, i, 2, lvi.pszText);
        
        lvi.iSubItem = 3; lvi.pszText = g_results[i].date;
        ListView_SetItemText(g_hList, i, 3, lvi.pszText);
        
        lvi.iSubItem = 4; lvi.pszText = g_results[i].perms;
        ListView_SetItemText(g_hList, i, 4, lvi.pszText);
    }
    SendMessageA(g_hList, WM_SETREDRAW, TRUE, 0);
}

static void LoadConfig() {
    char buf[256];
    
    g_conn_count = GetPrivateProfileIntA("Connections", "Count", 0, g_ini_path);
    if (g_conn_count > MAX_CONNECTIONS) g_conn_count = MAX_CONNECTIONS;
    
    for (int i = 0; i < g_conn_count; i++) {
        char key[32];
        snprintf(key, sizeof(key), "Server%d", i); GetPrivateProfileStringA("Connections", key, "", g_connections[i].server, sizeof(g_connections[i].server), g_ini_path);
        snprintf(key, sizeof(key), "Port%d", i); GetPrivateProfileStringA("Connections", key, "21", g_connections[i].port, sizeof(g_connections[i].port), g_ini_path);
        snprintf(key, sizeof(key), "User%d", i); GetPrivateProfileStringA("Connections", key, "anonymous", g_connections[i].user, sizeof(g_connections[i].user), g_ini_path);
        snprintf(key, sizeof(key), "Pass%d", i); GetPrivateProfileStringA("Connections", key, "", g_connections[i].pass, sizeof(g_connections[i].pass), g_ini_path);
        
        if (g_connections[i].server[0]) {
            SendMessageA(g_hServer, CB_ADDSTRING, 0, (LPARAM)g_connections[i].server);
        }
    }
    
    if (g_conn_count > 0) {
        SendMessageA(g_hServer, CB_SETCURSEL, 0, 0);
        char selSrv[128];
        SendMessageA(g_hServer, CB_GETLBTEXT, 0, (LPARAM)selSrv);
        for (int i = 0; i < g_conn_count; i++) {
            if (_stricmp(g_connections[i].server, selSrv) == 0) {
                SetWindowTextA(g_hPort, g_connections[i].port);
                SetWindowTextA(g_hUser, g_connections[i].user);
                SetWindowTextA(g_hPass, g_connections[i].pass);
                break;
            }
        }
    }

    GetPrivateProfileStringA("Connection", "RemoteDir", "/", buf, sizeof(buf), g_ini_path);
    SetWindowTextA(g_hRemoteDir, buf);
    
    g_upload_index = GetPrivateProfileIntA("Index", "Upload", 0, g_ini_path);
    SendMessageA(g_hChkUpload, BM_SETCHECK, g_upload_index ? BST_CHECKED : BST_UNCHECKED, 0);
    
    g_download_index = GetPrivateProfileIntA("Index", "Download", 0, g_ini_path);
    SendMessageA(g_hChkDownload, BM_SETCHECK, g_download_index ? BST_CHECKED : BST_UNCHECKED, 0);

    g_show_full_path = GetPrivateProfileIntA("View", "ShowFullPath", 1, g_ini_path);
    SendMessageA(g_hChkFullPath, BM_SETCHECK, g_show_full_path ? BST_CHECKED : BST_UNCHECKED, 0);

    UpdateIndexPath();
    UpdateLastIndexedLabel();

    int count = GetPrivateProfileIntA("History", "Count", 0, g_ini_path);
    for (int i = 0; i < count; i++) {
        char key[16]; snprintf(key, sizeof(key), "Dir%d", i);
        GetPrivateProfileStringA("History", key, "", buf, sizeof(buf), g_ini_path);
        if (buf[0]) SendMessageA(g_hLocalDir, CB_ADDSTRING, 0, (LPARAM)buf);
    }
    if (count > 0) SendMessageA(g_hLocalDir, CB_SETCURSEL, 0, 0);
    else {
        char curDir[MAX_PATH]; GetCurrentDirectoryA(sizeof(curDir), curDir);
        SetWindowTextA(g_hLocalDir, curDir);
    }
}

static void SaveConfig() {
    char buf[256];
    char srv[128], prt[16], usr[64], pwd[64], remDir[MAX_PATH];
    
    GetWindowTextA(g_hServer, srv, sizeof(srv)); trim_str(srv);
    GetWindowTextA(g_hPort, prt, sizeof(prt)); trim_str(prt);
    GetWindowTextA(g_hUser, usr, sizeof(usr)); trim_str(usr);
    GetWindowTextA(g_hPass, pwd, sizeof(pwd)); trim_str(pwd);
    GetWindowTextA(g_hRemoteDir, remDir, sizeof(remDir)); trim_str(remDir);

    if (srv[0] != '\0') {
        int exists = -1;
        for (int i = 0; i < g_conn_count; i++) {
            if (_stricmp(g_connections[i].server, srv) == 0) { exists = i; break; }
        }
        if (exists != -1) {
            strcpy(g_connections[exists].port, prt);
            strcpy(g_connections[exists].user, usr);
            strcpy(g_connections[exists].pass, pwd);
        } else if (g_conn_count < MAX_CONNECTIONS) {
            strcpy(g_connections[g_conn_count].server, srv);
            strcpy(g_connections[g_conn_count].port, prt);
            strcpy(g_connections[g_conn_count].user, usr);
            strcpy(g_connections[g_conn_count].pass, pwd);
            SendMessageA(g_hServer, CB_ADDSTRING, 0, (LPARAM)srv);
            g_conn_count++;
        }
    }

    WritePrivateProfileSectionA("Connections", "", g_ini_path); 
    snprintf(buf, sizeof(buf), "%d", g_conn_count); WritePrivateProfileStringA("Connections", "Count", buf, g_ini_path);
    WritePrivateProfileStringA("Connection", "RemoteDir", remDir, g_ini_path);
    
    for (int i = 0; i < g_conn_count; i++) {
        char key[32];
        snprintf(key, sizeof(key), "Server%d", i); WritePrivateProfileStringA("Connections", key, g_connections[i].server, g_ini_path);
        snprintf(key, sizeof(key), "Port%d", i); WritePrivateProfileStringA("Connections", key, g_connections[i].port, g_ini_path);
        snprintf(key, sizeof(key), "User%d", i); WritePrivateProfileStringA("Connections", key, g_connections[i].user, g_ini_path);
        snprintf(key, sizeof(key), "Pass%d", i); WritePrivateProfileStringA("Connections", key, g_connections[i].pass, g_ini_path);
    }
    
    WritePrivateProfileStringA("Index", "Upload", g_upload_index ? "1" : "0", g_ini_path);
    WritePrivateProfileStringA("Index", "Download", g_download_index ? "1" : "0", g_ini_path);
    WritePrivateProfileStringA("View", "ShowFullPath", g_show_full_path ? "1" : "0", g_ini_path);

    int count = SendMessageA(g_hLocalDir, CB_GETCOUNT, 0, 0);
    if (count > 10) count = 10;
    snprintf(buf, sizeof(buf), "%d", count); WritePrivateProfileStringA("History", "Count", buf, g_ini_path);
    for (int i = 0; i < count; i++) {
        char key[16]; snprintf(key, sizeof(key), "Dir%d", i);
        SendMessageA(g_hLocalDir, CB_GETLBTEXT, i, (LPARAM)buf);
        WritePrivateProfileStringA("History", key, buf, g_ini_path);
    }
}

static void AddLocalDirHistory(const char *dir) {
    int count = SendMessageA(g_hLocalDir, CB_GETCOUNT, 0, 0);
    int exists = -1;
    for (int i = 0; i < count; i++) {
        char buf[MAX_PATH]; SendMessageA(g_hLocalDir, CB_GETLBTEXT, i, (LPARAM)buf);
        if (_stricmp(buf, dir) == 0) { exists = i; break; }
    }
    if (exists != -1) SendMessageA(g_hLocalDir, CB_DELETESTRING, exists, 0);
    SendMessageA(g_hLocalDir, CB_INSERTSTRING, 0, (LPARAM)dir);
    SendMessageA(g_hLocalDir, CB_SETCURSEL, 0, 0);
}

// Connection
static void DisconnectFTP() {
    if (g_hFtpSession) { InternetCloseHandle(g_hFtpSession); g_hFtpSession = NULL; }
    if (g_hInternet) { InternetCloseHandle(g_hInternet); g_hInternet = NULL; }
    SetWindowTextA(g_hStatus, "Disconnected.");
}

static void ConnectFTP() {
    DisconnectFTP();
    char srv[128], prt[16], usr[64], pwd[64];
    GetWindowTextA(g_hServer, srv, sizeof(srv)); GetWindowTextA(g_hPort, prt, sizeof(prt));
    GetWindowTextA(g_hUser, usr, sizeof(usr)); GetWindowTextA(g_hPass, pwd, sizeof(pwd));

    SetWindowTextA(g_hStatus, "Connecting...");
    
    // Connect to FTP[cite: 1]
    g_hInternet = InternetOpenA("FtpSearchClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0); 
    if (!g_hInternet) { SetWindowTextA(g_hStatus, "InternetOpen failed."); return; }

    INTERNET_PORT iport = (prt[0]) ? (INTERNET_PORT)atoi(prt) : INTERNET_DEFAULT_FTP_PORT;
    g_hFtpSession = InternetConnectA(g_hInternet, srv, iport, usr, pwd, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0); 
    
    if (g_hFtpSession) {
        SetWindowTextA(g_hStatus, "Connected to FTP.");
    } else {
        InternetCloseHandle(g_hInternet); g_hInternet = NULL;
        SetWindowTextA(g_hStatus, "Connection failed.");
    }
}

static void RecursiveCrawl(HINTERNET hConn, const char* basePath, FILE* out) {
    if (!g_is_indexing) return;

    // By not using FtpSetCurrentDirectoryA, we significantly speed up recursive operations.
    char searchPath[MAX_PATH];
    if (strcmp(basePath, "/") == 0 || strcmp(basePath, "\\") == 0) {
        strcpy(searchPath, "/*");
    } else {
        snprintf(searchPath, sizeof(searchPath), "%s/*", basePath);
    }

    WIN32_FIND_DATAA fd;
    HINTERNET hFind = FtpFindFirstFileA(hConn, searchPath, &fd, INTERNET_FLAG_RELOAD | INTERNET_FLAG_DONT_CACHE, 0);
    
    FtpItem *head = NULL, *tail = NULL;

    if (hFind) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            
            FtpItem *item = (FtpItem*)malloc(sizeof(FtpItem));
            strcpy(item->name, fd.cFileName);
            item->is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
            item->size = fd.nFileSizeLow;
            item->attrs = fd.dwFileAttributes;
            item->ft = fd.ftLastWriteTime;
            item->next = NULL;
            
            if (!head) head = item;
            else tail->next = item;
            tail = item;
            
        } while (InternetFindNextFileA(hFind, &fd));
        InternetCloseHandle(hFind); // Close handle BEFORE recursing further down
    }

    FtpItem *curr = head;
    while (curr) {
        if (!g_is_indexing) break;
        
        char fullPath[MAX_PATH];
        if (strcmp(basePath, "/") == 0 || strcmp(basePath, "\\") == 0) {
            snprintf(fullPath, sizeof(fullPath), "/%s", curr->name);
        } else {
            snprintf(fullPath, sizeof(fullPath), "%s/%s", basePath, curr->name);
        }

        // Format Date
        char dateStr[32];
        if (curr->ft.dwHighDateTime == 0 && curr->ft.dwLowDateTime == 0) {
            strcpy(dateStr, "Unknown");
        } else {
            SYSTEMTIME stUTC, stLocal;
            FileTimeToSystemTime(&curr->ft, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            snprintf(dateStr, sizeof(dateStr), "%04d-%02d-%02d %02d:%02d:%02d", 
                stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        }

        // Map WIN32 attributes to generic Permissions equivalent string (Directory, Read-Only, Hidden, System)
        char permStr[16];
        snprintf(permStr, sizeof(permStr), "%c%c%c%c", 
            curr->is_dir ? 'D' : '-', 
            (curr->attrs & FILE_ATTRIBUTE_READONLY) ? 'R' : '-', 
            (curr->attrs & FILE_ATTRIBUTE_HIDDEN) ? 'H' : '-', 
            (curr->attrs & FILE_ATTRIBUTE_SYSTEM) ? 'S' : '-');

        if (curr->is_dir) {
            // Write to index with the new columns
            fprintf(out, "D|%s|0|%s|%s\n", fullPath, dateStr, permStr);
            
            char *msg = malloc(MAX_PATH + 50);
            snprintf(msg, MAX_PATH + 50, "Indexing: %s", fullPath);
            PostMessageA(g_hMain, WM_INDEX_UPDATE, 0, (LPARAM)msg);

            RecursiveCrawl(hConn, fullPath, out);
        } else {
            fprintf(out, "F|%s|%lu|%s|%s\n", fullPath, curr->size, dateStr, permStr);
        }
        
        FtpItem *temp = curr;
        curr = curr->next;
        free(temp);
    }
}

static DWORD WINAPI IndexThreadProc(LPVOID param) {
    FILE *f = fopen(g_index_path, "w");
    if (!f) {
        PostMessageA(g_hMain, WM_INDEX_DONE, 0, 0);
        return 0;
    }

    RecursiveCrawl(g_hFtpSession, g_current_remote_dir, f);
    fclose(f);
    
    if (g_upload_index) {
        char *msg = malloc(MAX_PATH + 50);
        snprintf(msg, MAX_PATH + 50, "Uploading index to server...");
        PostMessageA(g_hMain, WM_INDEX_UPDATE, 0, (LPARAM)msg);

        char remote_index_path[MAX_PATH];
        if (g_current_remote_dir[strlen(g_current_remote_dir)-1] == '/')
            snprintf(remote_index_path, sizeof(remote_index_path), "%sftp_search_index.dat", g_current_remote_dir);
        else
            snprintf(remote_index_path, sizeof(remote_index_path), "%s/ftp_search_index.dat", g_current_remote_dir);
            
        FtpPutFileA(g_hFtpSession, g_index_path, remote_index_path, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0);
    }
    
    PostMessageA(g_hMain, WM_INDEX_DONE, 1, 0);
    return 0;
}

static void StartIndexing() {
    if (!g_hFtpSession) {
        SetWindowTextA(g_hStatus, "Not connected to FTP. Connect first.");
        return;
    }
    
    UpdateIndexPath();
    
    GetWindowTextA(g_hRemoteDir, g_current_remote_dir, sizeof(g_current_remote_dir));
    trim_str(g_current_remote_dir);
    if (g_current_remote_dir[0] == '\0') strcpy(g_current_remote_dir, "/");
    
    g_is_indexing = 1;
    EnableWindow(g_hBtnIndex, FALSE);
    SetWindowTextA(g_hStatus, "Indexing started...");
    g_hThread = CreateThread(NULL, 0, IndexThreadProc, NULL, 0, NULL);
}

static void DoSearch() {
    UpdateIndexPath();
    
    if (g_download_index) {
        if (!g_hFtpSession) {
            SetWindowTextA(g_hStatus, "Must connect to FTP to download the index.");
            return;
        }
        
        char remDir[MAX_PATH];
        GetWindowTextA(g_hRemoteDir, remDir, sizeof(remDir));
        trim_str(remDir);
        if (remDir[0] == '\0') strcpy(remDir, "/");
        
        char remote_index_path[MAX_PATH];
        if (remDir[strlen(remDir)-1] == '/')
            snprintf(remote_index_path, sizeof(remote_index_path), "%sftp_search_index.dat", remDir);
        else
            snprintf(remote_index_path, sizeof(remote_index_path), "%s/ftp_search_index.dat", remDir);
            
        SetWindowTextA(g_hStatus, "Downloading index...");
        if (!FtpGetFileA(g_hFtpSession, remote_index_path, g_index_path, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0)) {
            SetWindowTextA(g_hStatus, "Failed to download index. Searching local cache.");
        } else {
            SetWindowTextA(g_hStatus, "Index downloaded. Searching...");
            UpdateLastIndexedLabel();
        }
    }

    char term[256];
    GetWindowTextA(g_hSearch, term, sizeof(term));
    trim_str(term);

    // Pre-calculate lower case needle for ultra-fast matching
    char term_lower[256];
    size_t term_len = strlen(term);
    for (size_t i = 0; i < term_len; i++) term_lower[i] = (char)tolower((unsigned char)term[i]);
    term_lower[term_len] = '\0';

    // 1. Open the file directly using Win32 API
    HANDLE hFile = CreateFileA(g_index_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char stat[MAX_PATH + 64];
        snprintf(stat, sizeof(stat), "Index file not found: %s. Please index the site first.", g_index_path);
        SetWindowTextA(g_hStatus, stat);
        return;
    }

    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize) || liSize.QuadPart == 0) {
        CloseHandle(hFile);
        SetWindowTextA(g_hStatus, "Index file is empty.");
        return;
    }

    // 2. Create a memory mapping (PAGE_READONLY guarantees 0MB of physical RAM commit overhead)
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        SetWindowTextA(g_hStatus, "Failed to create file mapping.");
        return;
    }

    // 3. Map the file view directly to the OS disk cache
    const char *buffer = (const char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!buffer) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        SetWindowTextA(g_hStatus, "Out of memory mapping index.");
        return;
    }

    g_result_count = 0;
    if (!g_results) {
        g_result_capacity = 10000;
        g_results = (SearchResult*)malloc(sizeof(SearchResult) * g_result_capacity);
    }

    const char *line_start = buffer;
    const char *file_end = buffer + liSize.QuadPart;

    // 4. Instantaneous Memory Scan
    while (line_start < file_end) {
        // Fast boundary lookup
        const char *line_end = (const char*)memchr(line_start, '\n', file_end - line_start);
        if (!line_end) line_end = file_end;
        
        size_t line_len = line_end - line_start;
        if (line_len > 0 && line_start[line_len - 1] == '\r') line_len--;

        // Fast pre-filter: Only parse delimited strings IF the raw string exists in this line
        if (term_len == 0 || mem_find_ia(line_start, line_len, term_lower, term_len) != NULL) {
            
            char type[5], path[MAX_PATH], size_str[32], date[32], perms[16];
            const char *p = line_start;
            const char *end = line_start + line_len;

            p = ExtractField(p, end, type, sizeof(type));
            p = ExtractField(p, end, path, sizeof(path));
            p = ExtractField(p, end, size_str, sizeof(size_str));
            p = ExtractField(p, end, date, sizeof(date));
            p = ExtractField(p, end, perms, sizeof(perms));

            // Verify the match actually occurred in the path (ignoring size/date matches)
            if (term_len == 0 || StrStrIA(path, term) != NULL) {
                if (g_result_count >= g_result_capacity) {
                    g_result_capacity *= 2;
                    g_results = (SearchResult*)realloc(g_results, sizeof(SearchResult) * g_result_capacity);
                }
                
                SearchResult *res = &g_results[g_result_count++];
                strcpy(res->type, (type[0] == 'D') ? "DIR" : "FILE");
                strncpy(res->path, path, sizeof(res->path) - 1); res->path[sizeof(res->path) - 1] = '\0';
                res->size = size_str[0] ? strtoul(size_str, NULL, 10) : 0;
                strncpy(res->date, date, sizeof(res->date) - 1); res->date[sizeof(res->date) - 1] = '\0';
                strncpy(res->perms, perms, sizeof(res->perms) - 1); res->perms[sizeof(res->perms) - 1] = '\0';
            }
        }
        
        line_start = line_end + 1;
    }

    // 5. Cleanup the memory mapping instantly
    UnmapViewOfFile(buffer);
    CloseHandle(hMap);
    CloseHandle(hFile);

    qsort(g_results, g_result_count, sizeof(SearchResult), compare_results);
    UpdateListView();

    char stat[128]; snprintf(stat, sizeof(stat), "Search completed. Found %d items.", g_result_count);
    SetWindowTextA(g_hStatus, stat);
}
static void DoDownload() {
    if (!g_hFtpSession) {
        SetWindowTextA(g_hStatus, "Connect to FTP first.");
        return;
    }

    int sel_count = ListView_GetSelectedCount(g_hList);
    if (sel_count == 0) return;

    char locDir[MAX_PATH];
    GetWindowTextA(g_hLocalDir, locDir, sizeof(locDir));
    trim_str(locDir);
    if (locDir[0] == '\0') {
        SetWindowTextA(g_hStatus, "Please specify a Local Dir.");
        return;
    }
    
    AddLocalDirHistory(locDir);
    SaveConfig();
    CreateDirectoryA(locDir, NULL);

    int idx = -1;
    while ((idx = ListView_GetNextItem(g_hList, idx, LVNI_SELECTED)) != -1) {
        if (idx >= g_result_count) continue;
        
        if (strcmp(g_results[idx].type, "DIR") == 0) {
            SetWindowTextA(g_hStatus, "Cannot download directories directly.");
            continue;
        }

        char *remPath = g_results[idx].path;
        char *filename = strrchr(remPath, '/');
        if (!filename) filename = strrchr(remPath, '\\');
        if (filename) filename++;
        else filename = remPath;

        char locPath[MAX_PATH];
        if (locDir[strlen(locDir)-1] == '\\') snprintf(locPath, sizeof(locPath), "%s%s", locDir, filename);
        else snprintf(locPath, sizeof(locPath), "%s\\%s", locDir, filename);

        if (GetFileAttributesA(locPath) != INVALID_FILE_ATTRIBUTES) {
            SetWindowTextA(g_hStatus, "Overwriting existing local file...");
        } else {
            char statMsg[MAX_PATH + 50];
            snprintf(statMsg, sizeof(statMsg), "Downloading: %s", filename);
            SetWindowTextA(g_hStatus, statMsg);
        }

        if (FtpGetFileA(g_hFtpSession, remPath, locPath, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0)) {
            SetWindowTextA(g_hStatus, "Download complete.");
        } else {
            SetWindowTextA(g_hStatus, "Download failed.");
        }
    }
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            g_hMain = hwnd;
            InitPaths();
            CreateControls(hwnd);
            LoadConfig();
            break;
            
        case WM_COMMAND: {
            int id = LOWORD(wp);
            
            // Search executes via 500ms timer reset by EN_CHANGE typing
            if (id == ID_SEARCH && HIWORD(wp) == EN_CHANGE) {
                SetTimer(hwnd, TIMER_SEARCH, 500, NULL);
            } else if (id == ID_SERVER && HIWORD(wp) == CBN_SELCHANGE) {
                int idx = SendMessageA(g_hServer, CB_GETCURSEL, 0, 0);
                if (idx != CB_ERR) {
                    char selSrv[128];
                    SendMessageA(g_hServer, CB_GETLBTEXT, idx, (LPARAM)selSrv);
                    for (int i = 0; i < g_conn_count; i++) {
                        if (_stricmp(g_connections[i].server, selSrv) == 0) {
                            SetWindowTextA(g_hPort, g_connections[i].port);
                            SetWindowTextA(g_hUser, g_connections[i].user);
                            SetWindowTextA(g_hPass, g_connections[i].pass);
                            UpdateIndexPath();
                            UpdateLastIndexedLabel();
                            break;
                        }
                    }
                }
                SetFocus(g_hSearch);
            } else if (id == ID_BTN_CONNECT) {
                SaveConfig();
                ConnectFTP();
                SetFocus(g_hSearch);
            } else if (id == ID_BTN_INDEX) {
                StartIndexing();
                SetFocus(g_hSearch);
            } else if (id == ID_BTN_CLEAR) {
                SetWindowTextA(g_hSearch, ""); // Will automatically trigger EN_CHANGE and DoSearch
                SetFocus(g_hSearch);
            } else if (id == ID_BTN_DOWNLOAD) {
                DoDownload();
                SetFocus(g_hSearch);
            } else if (id == ID_CHK_UPLOAD) {
                g_upload_index = (SendMessageA(g_hChkUpload, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SaveConfig();
                SetFocus(g_hSearch);
            } else if (id == ID_CHK_DOWNLOAD) {
                g_download_index = (SendMessageA(g_hChkDownload, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SaveConfig();
                SetFocus(g_hSearch);
            } else if (id == ID_CHK_FULLPATH) {
                g_show_full_path = (SendMessageA(g_hChkFullPath, BM_GETCHECK, 0, 0) == BST_CHECKED);
                SaveConfig();
                UpdateListView();
                SetFocus(g_hSearch);
            }
            break;
        }

        case WM_TIMER:
            if (wp == TIMER_SEARCH) {
                KillTimer(hwnd, TIMER_SEARCH);
                DoSearch();
            }
            break;

        case WM_NOTIFY: {
            LPNMHDR nmh = (LPNMHDR)lp;
            if (nmh->idFrom == ID_LIST) {
                if (nmh->code == LVN_COLUMNCLICK) {
                    LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lp;
                    if (g_sort_col == pnmv->iSubItem) {
                        g_sort_dir *= -1; 
                    } else {
                        g_sort_col = pnmv->iSubItem;
                        g_sort_dir = 1;
                    }
                    
                    if (g_result_count > 0) {
                        qsort(g_results, g_result_count, sizeof(SearchResult), compare_results);
                        UpdateListView();
                    }
                } else if (nmh->code == LVN_GETINFOTIPA) {
                    // Populate parent path ToolTip if full path is disabled
                    if (!g_show_full_path) {
                        LPNMLVGETINFOTIPA pGetInfoTip = (LPNMLVGETINFOTIPA)lp;
                        int i = pGetInfoTip->iItem;
                        if (i >= 0 && i < g_result_count) {
                            char full[MAX_PATH];
                            strcpy(full, g_results[i].path);
                            char *slash = strrchr(full, '/');
                            if (!slash) slash = strrchr(full, '\\');
                            if (slash) {
                                if (slash == full) *(slash + 1) = '\0';
                                else *slash = '\0';
                                strncpy(pGetInfoTip->pszText, full, pGetInfoTip->cchTextMax);
                            } else {
                                strncpy(pGetInfoTip->pszText, "/", pGetInfoTip->cchTextMax);
                            }
                        }
                    }
                }
            }
            break;
        }
        
        case WM_INDEX_UPDATE: {
            char *statMsg = (char*)lp;
            SetWindowTextA(g_hStatus, statMsg);
            free(statMsg);
            break;
        }

        case WM_INDEX_DONE: {
            g_is_indexing = 0;
            EnableWindow(g_hBtnIndex, TRUE);
            if (g_hThread) { CloseHandle(g_hThread); g_hThread = NULL; }
            
            if (wp == 1) { 
                UpdateLastIndexedLabel();
                SetWindowTextA(g_hStatus, "Indexing complete. Ready to search.");
                DoSearch();
            } else {
                SetWindowTextA(g_hStatus, "Indexing failed or aborted.");
            }
            SetFocus(g_hSearch);
            break;
        }

        case WM_SIZE: {
            int w = LOWORD(lp), h = HIWORD(lp);
            if (g_hList) {
                SetWindowPos(g_hList, NULL, 10, 165, w - 20, h - 195, SWP_NOZORDER);
                
                RECT rcList;
                GetClientRect(g_hList, &rcList);
                int listWidth = rcList.right - rcList.left;
                
                int pathWidth = listWidth - 330;
                if (pathWidth < 100) pathWidth = 100;
                
                ListView_SetColumnWidth(g_hList, 1, pathWidth);
            }
            if (g_hStatus) SendMessage(g_hStatus, WM_SIZE, 0, 0);
            break;
        }

        case WM_DESTROY:
            if (g_is_indexing) {
                g_is_indexing = 0;
                if (g_hThread) WaitForSingleObject(g_hThread, 2000);
            }
            if (g_results) {
                free(g_results);
                g_results = NULL;
            }
            DisconnectFTP();
            SaveConfig();
            PostQuitMessage(0);
            break;
            
        default: return DefWindowProcA(hwnd, msg, wp, lp);
    }
    return 0;
}
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
    
    g_hInst = hInst;

    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    wc.lpszClassName = "FtpSearchClass";
    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(0, "FtpSearchClass", "FTP Search & Index Tool", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInst, NULL);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
