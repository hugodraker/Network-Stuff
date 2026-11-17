/* ============================================================================
 * Enterprise Chat Client - Win32 UI + XMPP / Binary Chat Protocol
 *
 * COMPILATION INSTRUCTIONS (64-bit GCC/MinGW):
 *   gcc "chatclient.c" -Os -s -o "chatclient.exe" -mwindows -Wl,--large-address-aware -lgdi32 -lshell32 -lcomdlg32 -lws2_32 -lole32 -lwinmm -lshlwapi
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mmsystem.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <shellapi.h>
#include <commdlg.h>
#include <stdarg.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "shlwapi.lib")
#define MAX_MSGS          500
#define ID_EDIT           101
#define ID_COMBO          102
#define ID_LEFT_PANE      103
#define ID_ROOM_SEARCH    104
#define ID_CHAT_SEARCH    105
#define ID_STATUS_BAR     106
#define IDM_COPY_SEL      2001
#define IDM_COPY_ALL      2002
#define IDM_SEL_ALL       2003
#define IDM_SAVE_PDF      2004
#define IDM_CLEAR_CHAT    2005
#define IDM_SET_COLOR_U   2007
#define IDM_SET_COLOR_P   2008
#define IDM_JOIN_ROOM     2009
#define IDM_EDIT_MSG      2010
#define IDM_DEL_MSG       2011
#define IDM_SERVER_CONFIG 2012
#define IDM_NEW_CHAT      2013
#define IDM_ADD_USER      2014
#define IDM_SEARCH_USERS  2015
#define IDM_TOGGLE_STARTUP 2016
#define MSG_USER          0
#define MSG_PEER          1
#define MSG_SYS_OK        2
#define MSG_SYS_ERR       3
#define WM_UPDATE_CHAT    (WM_APP + 1)
COLORREF color_user    = RGB(10, 132, 255);
COLORREF color_peer    = RGB(229, 229, 234);
COLORREF color_sys_ok  = RGB(52, 199, 89);
COLORREF color_sys_err = RGB(255, 59, 48);

typedef struct {
    char text[262144];
    char msg_id[64];
    char sender[256];
    int msg_type;
    time_t timestamp;
    RECT hit_box;
    RECT text_box;
} ChatMsg;

ChatMsg chat_log[MAX_MSGS];
int msg_count = 0;
int scroll_y = 0;
HWND hMainWindow = NULL;
HWND hChatView = NULL;
HWND hEdit = NULL;
HWND hCombo = NULL;
HWND hLeftPane = NULL;
static HWND hSearchDlg = NULL;

HWND hStatusBar = NULL;
HWND hRoomSearch = NULL;
HWND hChatSearch = NULL;
HFONT hChatFont = NULL;
WNDPROC OldEditProc = NULL;
char ini_path[MAX_PATH];
int total_height = 0;
int visible_space = 0;

int sel_bubble_idx = -1;
int sel_anchor_char = -1;
int sel_caret_char = -1;
int is_mouse_selecting = 0;

// --- Network State ---
SOCKET g_sock = INVALID_SOCKET;
HANDLE g_net_thread = NULL;
volatile int g_connected = 0;
char g_username[256] = "admin";
char g_password[256] = "password";
char g_target[256]   = "#general";
char g_server_ip[64] = "127.0.0.1";
int  g_server_port   = 5222;

// --- Search, Notification & Startup Globals ---
int g_strobe_idx = -1;
int g_strobe_ticks = 0;
char g_all_rooms[64][256] = {"# general", "# developers", "# announcements"};
int g_all_rooms_count = 3;

BOOL g_enable_sound = TRUE;
BOOL g_enable_popup = TRUE;
char g_chat_search[256] = "";
volatile int g_app_running = 1;
int g_reconnect_s = 10;
HANDLE g_hReconnectEvent = NULL;

// --- Forward Declarations ---
void add_message(const char* text, int msg_type);
void add_message_full(const char* text, const char* sender, const char* msg_id, int msg_type);
void save_chat_to_pdf(HWND hwnd);
void ShowServerConfigDialog(HWND hwnd);
DWORD WINAPI NetworkWorkerThread(LPVOID lpParam);
int SendAll(SOCKET sock, const char* buf, int len);
void JoinRoom(const char* room_name);
void SetStatusMsg(const char* msg);

void ToggleRunAtStartup(BOOL enable) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE | KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        if (enable) {
            char path[MAX_PATH];
            GetModuleFileNameA(NULL, path, MAX_PATH);
            RegSetValueExA(hKey, "EnterpriseChatClient", 0, REG_SZ, (BYTE*)path, (DWORD)(strlen(path) + 1));
        } else {
            RegDeleteValueA(hKey, "EnterpriseChatClient");
        }
        RegCloseKey(hKey);
    }
}

static int CaseInsensitiveCompare(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return *a - *b;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

// ============================================================================
// UTILITY & CLIPBOARD HELPERS
// ============================================================================
void format_timestamp(time_t t, char* out, int max_len) {
    if (t == 0) t = time(NULL);
    struct tm* tm_info = localtime(&t);
    time_t now = time(NULL);
    struct tm* tm_now = localtime(&now);

    if (tm_info->tm_year == tm_now->tm_year &&
        tm_info->tm_mon == tm_now->tm_mon &&
        tm_info->tm_mday == tm_now->tm_mday) {
        strftime(out, max_len, "%H:%M", tm_info);
    } else {
        strftime(out, max_len, "%Y-%m-%d %H:%M", tm_info);
    }
}

void copy_range_to_clipboard(HWND hwnd, const char* src, int start_idx, int end_idx) {
    if (!src || start_idx < 0 || end_idx <= start_idx) return;
    int len = (int)strlen(src);
    if (start_idx >= len) return;
    if (end_idx > len) end_idx = len;

    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    int slice_len = end_idx - start_idx;
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (size_t)slice_len * 2 + 2);
    if (hg) {
        char* dst = (char*)GlobalLock(hg);
        int j = 0;
        for (int i = start_idx; i < end_idx; i++) {
            if (src[i] == '\n' && (i == start_idx || src[i - 1] != '\r')) dst[j++] = '\r';
            dst[j++] = src[i];
        }
        dst[j] = '\0';
        GlobalUnlock(hg);
        SetClipboardData(CF_TEXT, hg);
    }
    CloseClipboard();
}

void add_message(const char* text, int msg_type) {
    add_message_full(text, "", "", msg_type);
}

void add_message_full(const char* text, const char* sender, const char* msg_id, int msg_type) {
    if (msg_count < MAX_MSGS) {
        strncpy(chat_log[msg_count].text, text, sizeof(chat_log[msg_count].text) - 1);
        chat_log[msg_count].text[sizeof(chat_log[msg_count].text) - 1] = '\0';
        strncpy(chat_log[msg_count].sender, sender, sizeof(chat_log[msg_count].sender) - 1);
        strncpy(chat_log[msg_count].msg_id, msg_id, sizeof(chat_log[msg_count].msg_id) - 1);
        chat_log[msg_count].msg_type = msg_type;
        chat_log[msg_count].timestamp = time(NULL);
        SetRect(&chat_log[msg_count].hit_box, 0, 0, 0, 0);
        SetRect(&chat_log[msg_count].text_box, 0, 0, 0, 0);
        msg_count++;
    }
    scroll_y = -999999;
    if (hMainWindow) PostMessage(hMainWindow, WM_UPDATE_CHAT, 0, 0);
}

// ============================================================================
// DYNAMIC SERVER CONFIGURATION DIALOG
// ============================================================================
#define DLG_EDIT_IP   3001
#define DLG_EDIT_PORT 3002
#define DLG_EDIT_USER 3003
#define DLG_EDIT_PASS 3004
#define DLG_BTN_SAVE  3005
#define DLG_BTN_CANC  3006
// ============================================================================
// DYNAMIC INPUT & SEARCH DIALOGS
// ============================================================================
typedef struct {
    const char* title;
    const char* prompt;
    char* out_buf;
    int buf_size;
    int confirmed;
} InputDialogCtx;

static InputDialogCtx* g_input_ctx = NULL;
char g_download_save_path[MAX_PATH] = "";

HWND hConfigDlg = NULL;

LRESULT CALLBACK ConfigWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = GetModuleHandle(NULL);
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            HWND lbl1 = CreateWindowA("STATIC", "Server IP:", WS_CHILD | WS_VISIBLE, 15, 18, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edIp = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_server_ip, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 15, 160, 24, hwnd, (HMENU)DLG_EDIT_IP, hInst, NULL);
            HWND lbl2 = CreateWindowA("STATIC", "Port:", WS_CHILD | WS_VISIBLE, 15, 53, 90, 20, hwnd, NULL, hInst, NULL);
            char port_s[16]; sprintf(port_s, "%d", g_server_port);
            HWND edPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", port_s, WS_CHILD | WS_VISIBLE | ES_NUMBER, 110, 50, 160, 24, hwnd, (HMENU)DLG_EDIT_PORT, hInst, NULL);
            HWND lbl3 = CreateWindowA("STATIC", "Username:", WS_CHILD | WS_VISIBLE, 15, 88, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edUser = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_username, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 85, 160, 24, hwnd, (HMENU)DLG_EDIT_USER, hInst, NULL);
            HWND lbl4 = CreateWindowA("STATIC", "Password:", WS_CHILD | WS_VISIBLE, 15, 123, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edPass = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_password, WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL, 110, 120, 160, 24, hwnd, (HMENU)DLG_EDIT_PASS, hInst, NULL);
            HWND btnSave = CreateWindowA("BUTTON", "Connect", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 50, 160, 90, 30, hwnd, (HMENU)DLG_BTN_SAVE, hInst, NULL);
            HWND btnCanc = CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE, 155, 160, 90, 30, hwnd, (HMENU)DLG_BTN_CANC, hInst, NULL);
            HWND ctrls[] = {lbl1, edIp, lbl2, edPort, lbl3, edUser, lbl4, edPass, btnSave, btnCanc};
            for (int i = 0; i < 10; i++) SendMessage(ctrls[i], WM_SETFONT, (WPARAM)hFont, TRUE);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == DLG_BTN_SAVE) {
                char port_s[16];
                GetDlgItemTextA(hwnd, DLG_EDIT_IP, g_server_ip, sizeof(g_server_ip));
                GetDlgItemTextA(hwnd, DLG_EDIT_PORT, port_s, sizeof(port_s));
                g_server_port = atoi(port_s);
                GetDlgItemTextA(hwnd, DLG_EDIT_USER, g_username, sizeof(g_username));
                GetDlgItemTextA(hwnd, DLG_EDIT_PASS, g_password, sizeof(g_password));

                WritePrivateProfileStringA("Server", "IP", g_server_ip, ini_path);
                WritePrivateProfileStringA("Server", "Port", port_s, ini_path);
                WritePrivateProfileStringA("Server", "User", g_username, ini_path);
                WritePrivateProfileStringA("Server", "Pass", g_password, ini_path);

                g_connected = 0;
                if (g_sock != INVALID_SOCKET) { closesocket(g_sock); g_sock = INVALID_SOCKET; }
                if (g_hReconnectEvent) SetEvent(g_hReconnectEvent);
                DestroyWindow(hwnd);
            } else if (LOWORD(wParam) == DLG_BTN_CANC) {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_DESTROY:
            EnableWindow(hMainWindow, TRUE);
            SetForegroundWindow(hMainWindow);
            hConfigDlg = NULL;
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void SetStatusMsg(const char* msg) {
    if (hStatusBar) SetWindowTextA(hStatusBar, msg);
}

void ShowServerConfigDialog(HWND hwnd) {
    if (hConfigDlg) { SetForegroundWindow(hConfigDlg); return; }

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = ConfigWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "ServerConfigClass";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    RECT rc; GetWindowRect(hwnd, &rc);
    int x = rc.left + (rc.right - rc.left - 300) / 2;
    int y = rc.top + (rc.bottom - rc.top - 235) / 2;

    EnableWindow(hwnd, FALSE);
    hConfigDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "ServerConfigClass", "Server Connection Settings",
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 x, y, 300, 235, hwnd, NULL, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// GDI WORD-WRAP LAYOUT & CHARACTER HIT-TESTING ENGINE
// ============================================================================
typedef struct {
    int start_idx;
    int len;
    int y_top;
    int line_height;
} WrappedLine;

int compute_wrapped_lines(HDC hdc, const char* text, int max_width, WrappedLine* out_lines, int max_lines) {
    int line_count = 0;
    int len = (int)strlen(text);
    TEXTMETRICA tm;
    GetTextMetricsA(hdc, &tm);
    int lh = tm.tmHeight;
    int y = 0;
    int pos = 0;

    if (len == 0) {
        if (out_lines && max_lines > 0) {
            out_lines[0] = (WrappedLine){0, 0, 0, lh};
        }
        return 1;
    }

    while (pos < len) {
        int hard_nl = pos;
        while (hard_nl < len && text[hard_nl] != '\n' && text[hard_nl] != '\r') hard_nl++;
        int seg_len = hard_nl - pos;

        if (seg_len == 0) {
            if (out_lines && line_count < max_lines) {
                out_lines[line_count] = (WrappedLine){pos, 0, y, lh};
            }
            line_count++;
            y += lh;
            if (text[pos] == '\r' && pos + 1 < len && text[pos + 1] == '\n') pos += 2;
            else pos++;
            continue;
        }

        int fit_chars = 0;
        SIZE sz;
        GetTextExtentExPointA(hdc, text + pos, seg_len, max_width, &fit_chars, NULL, &sz);
        if (fit_chars <= 0) fit_chars = 1;

        if (fit_chars < seg_len) {
            int break_at = fit_chars;
            while (break_at > 1 && text[pos + break_at - 1] != ' ') break_at--;
            if (break_at > 1) fit_chars = break_at;
        }

        if (out_lines && line_count < max_lines) {
            out_lines[line_count] = (WrappedLine){pos, fit_chars, y, lh};
        }
        line_count++;
        y += lh;
        pos += fit_chars;

        if (pos == hard_nl && pos < len) {
            if (text[pos] == '\r' && pos + 1 < len && text[pos + 1] == '\n') pos += 2;
            else if (text[pos] == '\n' || text[pos] == '\r') pos++;
        }
    }
    return line_count;
}

// ============================================================================
// PDF GENERATION
// ============================================================================
typedef struct { char* data; int len; int cap; } Stream;

void s_app(Stream* s, const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (s->len + n >= s->cap) {
        s->cap = (s->cap == 0 ? 4096 : s->cap * 2) + n + 1024;
        s->data = realloc(s->data, s->cap);
    }
    memcpy(s->data + s->len, buf, n);
    s->len += n;
    s->data[s->len] = 0;
}

void pdf_color(Stream* s, int is_stroke, COLORREF col) {
    float r = GetRValue(col) / 255.0f;
    float g = GetGValue(col) / 255.0f;
    float b = GetBValue(col) / 255.0f;
    s_app(s, "%.3f %.3f %.3f %s\n", r, g, b, is_stroke ? "RG" : "rg");
}

void pdf_rounded_rect(Stream* s, float x, float y, float w, float h, float r) {
    float k = 0.55228f * r;
    s_app(s, "%.2f %.2f m\n", x + r, y + h);
    s_app(s, "%.2f %.2f l\n", x + w - r, y + h); 
    s_app(s, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", x + w - r + k, y + h, x + w, y + h - r + k, x + w, y + h - r);
    s_app(s, "%.2f %.2f l\n", x + w, y + r); 
    s_app(s, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", x + w, y + r - k, x + w - r + k, y, x + w - r, y);
    s_app(s, "%.2f %.2f l\n", x + r, y); 
    s_app(s, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", x + r - k, y, x, y + r - k, x, y + r);
    s_app(s, "%.2f %.2f l\n", x, y + h - r); 
    s_app(s, "%.2f %.2f %.2f %.2f %.2f %.2f c\n", x, y + h - r + k, x + r - k, y + h, x + r, y + h);
    s_app(s, "f\n");
}

void save_chat_to_pdf(HWND hwnd) {
    char out_path[MAX_PATH] = "Chat_Log.pdf";
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "PDF Files (*.pdf)\0*.pdf\0";
    ofn.lpstrFile = out_path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileNameA(&ofn)) return;

    FILE* f = fopen(out_path, "wb");
    if (!f) return;

    RECT clientRect; GetClientRect(hwnd, &clientRect);
    int win_width = clientRect.right - clientRect.left;
    HDC hdc = GetDC(hwnd);
    HFONT hOldFont = (HFONT)SelectObject(hdc, hChatFont);
    TEXTMETRICA tm; GetTextMetricsA(hdc, &tm);
    int lh = tm.tmHeight;

    int y_cursor = 20, bubble_padding = 12, max_bubble_w = (win_width * 7) / 10;
    if (max_bubble_w < 120) max_bubble_w = 120;

    int pdf_total_height = 20;
    for (int i = 0; i < msg_count; i++) {
        int n_lines = compute_wrapped_lines(hdc, chat_log[i].text, max_bubble_w, NULL, 0);
        pdf_total_height += (n_lines * lh) + (bubble_padding * 2) + 25;
    }
    if (pdf_total_height < 500) pdf_total_height = 500;

    fprintf(f, "%%PDF-1.1\n");
    long pdf_objects[16];
    pdf_objects[1] = ftell(f); fprintf(f, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    pdf_objects[2] = ftell(f); fprintf(f, "2 0 obj\n<< /Type /Pages /Count 1 /Kids [ 3 0 R ] >>\nendobj\n");
    pdf_objects[4] = ftell(f); fprintf(f, "4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n");

    Stream s = {0};
    s_app(&s, "0.95 0.95 0.97 rg 0 0 %d %d re f\n", win_width, pdf_total_height);

    y_cursor = 20;
    for (int i = 0; i < msg_count; i++) {
        WrappedLine lines[1024];
        int n_lines = compute_wrapped_lines(hdc, chat_log[i].text, max_bubble_w, lines, 1024);
        int max_line_px = 45;
        for (int l = 0; l < n_lines; l++) {
            SIZE sz = {0, 0};
            if (lines[l].len > 0) GetTextExtentPoint32A(hdc, chat_log[i].text + lines[l].start_idx, lines[l].len, &sz);
            if (sz.cx > max_line_px) max_line_px = sz.cx;
        }

        int b_width = max_line_px + (bubble_padding * 2);
        int b_height = (n_lines * lh) + (bubble_padding * 2);

        RECT bRect = (chat_log[i].msg_type == MSG_USER)
            ? (RECT){win_width - b_width - 25, y_cursor, win_width - 25, y_cursor + b_height}
            : (RECT){25, y_cursor, 25 + b_width, y_cursor + b_height};

        COLORREF cur_col = color_peer;
        if (chat_log[i].msg_type == MSG_USER) cur_col = color_user;
        else if (chat_log[i].msg_type == MSG_SYS_OK) cur_col = color_sys_ok;
        else if (chat_log[i].msg_type == MSG_SYS_ERR) cur_col = color_sys_err;

        float pdf_y_bottom = (float)(pdf_total_height - bRect.bottom);
        
        pdf_color(&s, 0, cur_col);
        pdf_rounded_rect(&s, (float)bRect.left, pdf_y_bottom, (float)(bRect.right - bRect.left), (float)b_height, 10.0f);

        if (chat_log[i].msg_type == MSG_USER) {
            s_app(&s, "%.2f %.2f m %.2f %.2f l %.2f %.2f l f\n",
                  (float)(bRect.right - 5), pdf_y_bottom + 20.0f,
                  (float)(bRect.right - 5), pdf_y_bottom + 5.0f,
                  (float)(bRect.right + 10), pdf_y_bottom + 5.0f);
        } else {
            s_app(&s, "%.2f %.2f m %.2f %.2f l %.2f %.2f l f\n",
                  (float)(bRect.left + 5), pdf_y_bottom + 20.0f,
                  (float)(bRect.left + 5), pdf_y_bottom + 5.0f,
                  (float)(bRect.left - 10), pdf_y_bottom + 5.0f);
        }
        
        int r = GetRValue(cur_col), g = GetGValue(cur_col), b = GetBValue(cur_col);
        if ((0.299f*r + 0.587f*g + 0.114f*b) > 186.0f) s_app(&s, "0 0 0 rg\n");
        else s_app(&s, "1 1 1 rg\n");
        
        for (int l = 0; l < n_lines; l++) {
            char lbuf[4096], esc[8192]; 
            int len = lines[l].len;
            if (len > 4000) len = 4000;
            memcpy(lbuf, chat_log[i].text + lines[l].start_idx, len);
            
            int e_idx = 0;
            for (int c = 0; c < len; c++) {
                if (lbuf[c] == '(' || lbuf[c] == ')' || lbuf[c] == '\\') esc[e_idx++] = '\\';
                esc[e_idx++] = lbuf[c];
            }
            esc[e_idx] = '\0';

            float text_y = (float)(pdf_total_height - (bRect.top + bubble_padding + l * lh + lh - 4)); 
            s_app(&s, "BT /F1 %d Tf %.2f %.2f Td (%s) Tj ET\n", 13, (float)(bRect.left + bubble_padding), text_y, esc);
        }
        y_cursor += b_height + 25;
    }

    SelectObject(hdc, hOldFont); ReleaseDC(hwnd, hdc);

    pdf_objects[3] = ftell(f);
    fprintf(f, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Contents 6 0 R /Resources << /Font << /F1 4 0 R >> >> >>\nendobj\n", win_width, pdf_total_height);
    pdf_objects[6] = ftell(f);
    fprintf(f, "6 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", s.len, s.data);

    long xref_pos = ftell(f);
    fprintf(f, "xref\n0 7\n0000000000 65535 f \n");
    for(int i = 1; i <= 6; i++) fprintf(f, "%010ld 00000 n \n", pdf_objects[i]);
    fprintf(f, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%ld\n%%%%EOF\n", xref_pos);
    
    if (s.data) free(s.data);
    fclose(f);
}

void PickColor(HWND hwnd, COLORREF* current_color, const char* key) {
    CHOOSECOLOR cc = {0};
    static COLORREF acrCustClr[16];
    cc.lStructSize = sizeof(cc);
    cc.hwndOwner = hwnd;
    cc.rgbResult = *current_color;
    cc.lpCustColors = (LPDWORD)acrCustClr;
    cc.Flags = CC_FULLOPEN | CC_RGBINIT;
    if (ChooseColor(&cc)) {
        *current_color = cc.rgbResult;
        char buf[32]; sprintf(buf, "%lu", *current_color);
        WritePrivateProfileStringA("Colors", key, buf, ini_path);
        InvalidateRect(hwnd, NULL, TRUE);
    }
}

// ============================================================================
// NETWORK CLIENT WORKER THREAD
// ============================================================================
int SendAll(SOCKET sock, const char* buf, int len) {
    int total = 0;
    while (total < len) {
        int r = send(sock, buf + total, len - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int ReadLine(SOCKET sock, char* buf, int max_len) {
    int i = 0; char c;
    while (i < max_len - 1) {
        int r = recv(sock, &c, 1, 0);
        if (r <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[i++] = c;
    }
    buf[i] = '\0';
    return i;
}

void SendTextMessage(const char* target, const char* text) {
    if (!g_connected || g_sock == INVALID_SOCKET) {
        add_message("Error: Not connected to chat server. Click here to configure.", MSG_SYS_ERR);
        return;
    }
    char stanza[8192];
    int len = snprintf(stanza, sizeof(stanza), 
        "<message to=\"%s\"><body>%s</body></message>\n", target, text);
    SendAll(g_sock, stanza, len);
}

void SendFileTransfer(const char* target, const char* filepath) {
    if (!g_connected || g_sock == INVALID_SOCKET) {
        add_message("Error: Not connected to chat server. Click here to configure.", MSG_SYS_ERR);
        return;
    }
    FILE* f = fopen(filepath, "rb");
    if (!f) {
        add_message("Error: Could not open file for transfer.", MSG_SYS_ERR);
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    const char* raw_name = strrchr(filepath, '\\');
    raw_name = raw_name ? raw_name + 1 : filepath;

    // Sanitize spaces to underscores so protocol parsing never breaks
    char fname[256];
    strncpy(fname, raw_name, sizeof(fname) - 1);
    fname[sizeof(fname) - 1] = '\0';
    for (char* p = fname; *p; p++) {
        if (*p == ' ') *p = '_';
    }

    int chunk_size = 4096;
    int total_chunks = (int)((fsize + chunk_size - 1) / chunk_size);
    if (total_chunks == 0) total_chunks = 1;

    for (int i = 0; i < total_chunks; i++) {
        char* cbuf = (char*)malloc(chunk_size);
        int r = (int)fread(cbuf, 1, chunk_size, f);
        if (r < 0) r = 0;

        char header[512];
        int hlen = snprintf(header, sizeof(header), "FILE_CHUNK %s %s %d %d %d\n", target, fname, i, total_chunks, r);
        SendAll(g_sock, header, hlen);
        if (r > 0) SendAll(g_sock, cbuf, r);
        free(cbuf);
    }
    fclose(f);
}

void JoinRoom(const char* room_name) {
    if (!g_connected || g_sock == INVALID_SOCKET) return;
    char stanza[512];
    int len = snprintf(stanza, sizeof(stanza), "<join room=\"%s\"/>\n", room_name);
    SendAll(g_sock, stanza, len);
    strncpy(g_target, room_name, sizeof(g_target) - 1);
    char buf[256];
    snprintf(buf, sizeof(buf), "Switched channel: #%s", room_name);
    add_message(buf, MSG_SYS_OK);
}

void MutateMessageRequest(const char* msg_id, int action, const char* new_content) {
    if (!g_connected || g_sock == INVALID_SOCKET) return;
    char stanza[4096];
    int len = snprintf(stanza, sizeof(stanza), 
        "<mutate id=\"%s\" action=\"%d\" to=\"%s\"><body>%s</body></mutate>\n",
        msg_id, action, g_target, new_content ? new_content : "");
    SendAll(g_sock, stanza, len);
}

DWORD WINAPI NetworkWorkerThread(LPVOID lpParam) {
    (void)lpParam;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;

    int retry_count = 0;

    while (g_app_running) {
        struct sockaddr_in serv = {0};
        serv.sin_family = AF_INET;
        serv.sin_port = htons((u_short)g_server_port);
        
        serv.sin_addr.s_addr = inet_addr(g_server_ip);
        if (serv.sin_addr.s_addr == INADDR_NONE) {
            struct hostent* he = gethostbyname(g_server_ip);
            if (he && he->h_addr_list[0]) {
                memcpy(&serv.sin_addr, he->h_addr_list[0], he->h_length);
            } else {
                SetStatusMsg("Invalid server address. Check settings.");
                goto wait_reconnect;
            }
        }

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        g_sock = s;

        if (retry_count > 1) SetStatusMsg("Disconnected. Reconnecting...");
        else if (retry_count == 0) SetStatusMsg("Connecting...");

        if (connect(s, (struct sockaddr*)&serv, sizeof(serv)) < 0) {
            closesocket(s);
            if (g_sock == s) g_sock = INVALID_SOCKET;
            goto wait_reconnect;
        }

        char buf[8192];
        if (ReadLine(s, buf, sizeof(buf)) < 0) {
            closesocket(s);
            if (g_sock == s) g_sock = INVALID_SOCKET;
            goto wait_reconnect;
        }

        char auth_pkt[512];
        int alen = snprintf(auth_pkt, sizeof(auth_pkt), "AUTH %s %s\n", g_username, g_password);
        SendAll(s, auth_pkt, alen);

        int auth_ok = 0;
        while (ReadLine(s, buf, sizeof(buf)) >= 0) {
            if (strstr(buf, "<success/>") || strstr(buf, "+OK")) {
                auth_ok = 1; break;
            }
            if (strstr(buf, "<failure/>") || strstr(buf, "not-authorized")) {
                auth_ok = 0; break;
            }
        }

        if (auth_ok) {
            g_connected = 1;
            retry_count = 0;
            SetStatusMsg("Connected & Synchronized.");

            char pres[256];
            int plen = snprintf(pres, sizeof(pres), "<presence><show>1</show></presence>\n");
            SendAll(s, pres, plen);
            JoinRoom(g_target);
        } else {
            SetStatusMsg("Authentication Failed. Check credentials.");
            closesocket(s);
            if (g_sock == s) g_sock = INVALID_SOCKET;
            goto wait_reconnect;
        }

        while (g_connected && g_sock == s && g_app_running) {
            if (ReadLine(s, buf, sizeof(buf)) < 0) break;

            // 1. INCOMING ATTACHMENT DOWNLOAD STREAM (FILE_DATA)
            if (strncmp(buf, "FILE_DATA ", 10) == 0) {
                char fname[256];
                int chunk_idx = 0, total_chunks = 1, chunk_size = 0;
                if (sscanf(buf, "FILE_DATA %255s %d %d %d", fname, &chunk_idx, &total_chunks, &chunk_size) == 4) {
                    char* cbuf = (char*)malloc(chunk_size > 0 ? chunk_size : 1);
                    int total_read = 0;
                    while (total_read < chunk_size) {
                        int r = recv(s, cbuf + total_read, chunk_size - total_read, 0);
                        if (r <= 0) break;
                        total_read += r;
                    }
                    if (g_download_save_path[0] != '\0') {
                        FILE* f = fopen(g_download_save_path, chunk_idx == 0 ? "wb" : "ab");
                        if (f) {
                            if (total_read > 0) fwrite(cbuf, 1, total_read, f);
                            fclose(f);
                        }
                    }
                    free(cbuf);

                    if (chunk_idx == total_chunks - 1) {
                        char done_msg[512];
                        snprintf(done_msg, sizeof(done_msg), "Downloaded attachment to: %s", g_download_save_path);
                        add_message(done_msg, MSG_SYS_OK);
                        SetStatusMsg(done_msg);
                    }
                }
                continue;
            }

            if (strstr(buf, "<message")) {
                char from[256] = "Peer", to[256] = "", id[64] = "", room_attr[256] = "", body[8192] = "";
                char* from_ptr = strstr(buf, "from=\"");
                if (from_ptr) sscanf(from_ptr, "from=\"%255[^\"]\"", from);
                char* to_ptr = strstr(buf, "to=\"");
                if (to_ptr) sscanf(to_ptr, "to=\"%255[^\"]\"", to);
                char* id_ptr = strstr(buf, "id=\"");
                if (id_ptr) sscanf(id_ptr, "id=\"%63[^\"]\"", id);
                char* r_ptr = strstr(buf, "room=\"");
                if (r_ptr) sscanf(r_ptr, "room=\"%255[^\"]\"", room_attr);

                char* start = strstr(buf, "<body>");
                char* end = strstr(buf, "</body>");
                if (start && end && end > start + 6) {
                    *end = '\0';
                    strncpy(body, start + 6, sizeof(body) - 1);
                }
                
                // 2. DIRECTORY SEARCH RESULTS
                if (strcmp(id, "search_res") == 0) {
                    if (hSearchDlg) {
                        SendDlgItemMessageA(hSearchDlg, 4003, LB_RESETCONTENT, 0, 0);
                        char* line = strtok(body, "\n");
                        int count = 0;
                        while (line) {
                            if (strncmp(line, "- ", 2) == 0) {
                                SendDlgItemMessageA(hSearchDlg, 4003, LB_ADDSTRING, 0, (LPARAM)(line + 2));
                                count++;
                            }
                            line = strtok(NULL, "\n");
                        }
                        if (count == 0) SendDlgItemMessageA(hSearchDlg, 4003, LB_ADDSTRING, 0, (LPARAM)"No users matched.");
                    }
                    continue;
                }

                // 3. INCOMING GROUP INVITATIONS
                if (strcmp(id, "invite_notify") == 0 || (CaseInsensitiveCompare(from, "Server") == 0 && strstr(body, "You have been added to "))) {
                    char invited_room[256] = {0};
                    if (room_attr[0] != '\0') {
                        strncpy(invited_room, room_attr, 255);
                    } else {
                        sscanf(body, "You have been added to %255s by", invited_room);
                    }

                    if (invited_room[0] != '\0') {
                        char display_room[260];
                        if (invited_room[0] == '#' && invited_room[1] != ' ')
                            snprintf(display_room, sizeof(display_room), "# %s", invited_room + 1);
                        else
                            strncpy(display_room, invited_room, 255);

                        BOOL exists = FALSE;
                        for (int i = 0; i < g_all_rooms_count; i++) {
                            char norm_existing[256];
                            if (strncmp(g_all_rooms[i], "# ", 2) == 0) snprintf(norm_existing, sizeof(norm_existing), "#%s", g_all_rooms[i] + 2);
                            else strncpy(norm_existing, g_all_rooms[i], 255);

                            if (CaseInsensitiveCompare(norm_existing, invited_room) == 0) exists = TRUE;
                        }
                        if (!exists && g_all_rooms_count < 64) {
                            strncpy(g_all_rooms[g_all_rooms_count++], display_room, 255);
                            SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)display_room);
                        }
                        // Always display the invite banner in the current chat view + alert user
                        add_message(body, MSG_SYS_OK);
                        SetStatusMsg(body);
                        if (g_enable_sound) PlaySoundA("SystemAsterisk", NULL, SND_ALIAS | SND_ASYNC);
                        if (g_enable_popup) {
                            ShowWindow(hMainWindow, SW_RESTORE);
                            SetForegroundWindow(hMainWindow);
                        }
                    }
                    continue;
                }

                int is_me = (CaseInsensitiveCompare(from, g_username) == 0);
                int bubble_type = is_me ? MSG_USER : MSG_PEER;
                if (CaseInsensitiveCompare(from, "Server") == 0) bubble_type = MSG_SYS_OK;

                // 4. ENSURE 1-ON-1 PEER EXISTS IN SIDEBAR
                if (!is_me && to[0] != '#' && CaseInsensitiveCompare(from, "Server") != 0) {
                    char dm_label[260];
                    snprintf(dm_label, sizeof(dm_label), "@ %s", from);
                    BOOL exists = FALSE;
                    for (int i = 0; i < g_all_rooms_count; i++) {
                        if (CaseInsensitiveCompare(g_all_rooms[i], dm_label) == 0) exists = TRUE;
                    }
                    if (!exists && g_all_rooms_count < 64) {
                        strncpy(g_all_rooms[g_all_rooms_count++], dm_label, 255);
                        SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)dm_label);
                    }
                }

                // Fire sound & window popup for ANY incoming peer message
                if (!is_me) {
                    if (g_enable_sound) PlaySoundA("SystemAsterisk", NULL, SND_ALIAS | SND_ASYNC);
                    if (g_enable_popup) {
                        ShowWindow(hMainWindow, SW_RESTORE);
                        SetForegroundWindow(hMainWindow);
                    }
                }
                
                BOOL show_it = FALSE;
                if (g_target[0] == '#') {
                    if (CaseInsensitiveCompare(to, g_target) == 0) show_it = TRUE;
                } else {
                    if (is_me && CaseInsensitiveCompare(to, g_target) == 0) show_it = TRUE;
                    else if (!is_me && CaseInsensitiveCompare(from, g_target) == 0) show_it = TRUE;
                }
                
                if (show_it) {
                    add_message_full(body, from, id, bubble_type);
                    scroll_y = -999999;
                    InvalidateRect(hChatView, NULL, TRUE);
                } else if (!is_me) {
                    char status_note[512];
                    snprintf(status_note, sizeof(status_note), "New message from %s (%s)", from, (to[0] == '#') ? to : "Direct Message");
                    SetStatusMsg(status_note);
                }
            }
        }

        if (g_sock == s) {
            g_connected = 0;
            g_sock = INVALID_SOCKET;
        }
        closesocket(s);

    wait_reconnect:
        if (!g_app_running) break;
        retry_count++;
        if (retry_count > 1) SetStatusMsg("Connection lost. Reconnecting...");
        WaitForSingleObject(g_hReconnectEvent, g_reconnect_s * 1000);
    }
    WSACleanup();
    return 0;
}

static HWND hInputDlg = NULL;
static LRESULT CALLBACK InputDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = GetModuleHandle(NULL);
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            HWND lbl = CreateWindowA("STATIC", g_input_ctx->prompt, WS_CHILD | WS_VISIBLE, 15, 15, 250, 20, hwnd, NULL, hInst, NULL);
            HWND ed = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 40, 250, 24, hwnd, (HMENU)3001, hInst, NULL);
            HWND btnOK = CreateWindowA("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 85, 80, 80, 30, hwnd, (HMENU)3002, hInst, NULL);
            HWND btnCancel = CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE, 175, 80, 80, 30, hwnd, (HMENU)3003, hInst, NULL);
            SendMessage(lbl, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(ed, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(btnOK, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(btnCancel, WM_SETFONT, (WPARAM)hFont, TRUE);
            SetFocus(ed);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 3002) {
                GetDlgItemTextA(hwnd, 3001, g_input_ctx->out_buf, g_input_ctx->buf_size);
                g_input_ctx->confirmed = 1;
                DestroyWindow(hwnd);
            } else if (LOWORD(wParam) == 3003) {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_DESTROY:
            EnableWindow(hMainWindow, TRUE);
            SetForegroundWindow(hMainWindow);
            hInputDlg = NULL;
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static int ShowInputDialog(HWND parent, const char* title, const char* prompt, char* out_buf, int buf_size) {
    if (hInputDlg) return 0;
    InputDialogCtx ctx = { title, prompt, out_buf, buf_size, 0 };
    g_input_ctx = &ctx;

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = InputDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "InputDlgClass";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    RECT rc; GetWindowRect(parent, &rc);
    int x = rc.left + (rc.right - rc.left - 300) / 2;
    int y = rc.top + (rc.bottom - rc.top - 160) / 2;

    EnableWindow(parent, FALSE);
    hInputDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "InputDlgClass", title,
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 x, y, 300, 160, parent, NULL, GetModuleHandle(NULL), NULL);

    MSG msg;
    while (hInputDlg && GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hInputDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return ctx.confirmed;
}

static LRESULT CALLBACK SearchDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = GetModuleHandle(NULL);
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            
            HWND lbl = CreateWindowA("STATIC", "Search (Name, Username, Email):", WS_CHILD | WS_VISIBLE, 15, 15, 250, 20, hwnd, NULL, hInst, NULL);
            HWND ed = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 40, 250, 24, hwnd, (HMENU)4001, hInst, NULL);
            HWND btnSearch = CreateWindowA("BUTTON", "Search", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 275, 39, 80, 26, hwnd, (HMENU)4002, hInst, NULL);
            HWND list = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "", WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL, 15, 75, 340, 150, hwnd, (HMENU)4003, hInst, NULL);
            
            HWND btnAdd = CreateWindowA("BUTTON", "Add to Room", WS_CHILD | WS_VISIBLE, 15, 235, 105, 30, hwnd, (HMENU)4005, hInst, NULL);
            HWND btnDM = CreateWindowA("BUTTON", "Direct Chat", WS_CHILD | WS_VISIBLE, 130, 235, 105, 30, hwnd, (HMENU)4006, hInst, NULL);
            HWND btnClose = CreateWindowA("BUTTON", "Close", WS_CHILD | WS_VISIBLE, 245, 235, 110, 30, hwnd, (HMENU)4004, hInst, NULL);
            
            HWND ctrls[] = {lbl, ed, btnSearch, list, btnAdd, btnDM, btnClose};
            for (int i = 0; i < 7; i++) SendMessage(ctrls[i], WM_SETFONT, (WPARAM)hFont, TRUE);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 4002) { // Execute Search
                char query[256];
                GetDlgItemTextA(hwnd, 4001, query, sizeof(query));
                if (g_connected && g_sock != INVALID_SOCKET) {
                    char stanza[512];
                    int len = snprintf(stanza, sizeof(stanza), "<iq type=\"get\"><query xmlns=\"jabber:iq:search\"><text>%s</text></query></iq>\n", query);
                    SendAll(g_sock, stanza, len);
                    
                    SendDlgItemMessageA(hwnd, 4003, LB_RESETCONTENT, 0, 0);
                    SendDlgItemMessageA(hwnd, 4003, LB_ADDSTRING, 0, (LPARAM)"Request sent to server...");
                }
            } else if (LOWORD(wParam) == 4005) { // Add User to Current Room
                int idx = (int)SendDlgItemMessageA(hwnd, 4003, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char sel_user[256];
                    SendDlgItemMessageA(hwnd, 4003, LB_GETTEXT, idx, (LPARAM)sel_user);
                    if (strcmp(sel_user, "No users matched.") != 0 && strcmp(sel_user, "Request sent to server...") != 0) {
                        if (g_target[0] != '#') {
                            MessageBoxA(hwnd, "Switch to a #room first to invite users to it.", "Error", MB_ICONWARNING | MB_OK);
                        } else {
                            char stanza[512];
                            int len = snprintf(stanza, sizeof(stanza), "<invite to=\"%s\" room=\"%s\"/>\n", sel_user, g_target);
                            SendAll(g_sock, stanza, len);
                            MessageBoxA(hwnd, "Invite dispatched.", "Success", MB_OK);
                        }
                    }
                }
            } else if (LOWORD(wParam) == 4006) { // Start 1-on-1 Direct Chat
                int idx = (int)SendDlgItemMessageA(hwnd, 4003, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char sel_user[256];
                    SendDlgItemMessageA(hwnd, 4003, LB_GETTEXT, idx, (LPARAM)sel_user);
                    if (strcmp(sel_user, "No users matched.") != 0 && strcmp(sel_user, "Request sent to server...") != 0) {
                        char dm_label[260];
                        snprintf(dm_label, sizeof(dm_label), "@ %s", sel_user);
                        BOOL exists = FALSE;
                        for (int i = 0; i < g_all_rooms_count; i++) {
                            if (CaseInsensitiveCompare(g_all_rooms[i], dm_label) == 0) exists = TRUE;
                        }
                        if (!exists && g_all_rooms_count < 64) {
                            strncpy(g_all_rooms[g_all_rooms_count++], dm_label, 255);
                            SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)dm_label);
                        }
                        strncpy(g_target, sel_user, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                        msg_count = 0;
                        InvalidateRect(hChatView, NULL, TRUE);
                        SetStatusMsg(dm_label);
                        DestroyWindow(hwnd);
                    }
                }
            } else if (LOWORD(wParam) == 4004) { // Close
                DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_DESTROY:
            EnableWindow(hMainWindow, TRUE);
            SetForegroundWindow(hMainWindow);
            hSearchDlg = NULL;
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}
static void ShowSearchDialog(HWND parent) {
    if (hSearchDlg) { SetForegroundWindow(hSearchDlg); return; }
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = SearchDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "SearchDlgClass";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    RECT rc; GetWindowRect(parent, &rc);
    int x = rc.left + (rc.right - rc.left - 380) / 2;
    int y = rc.top + (rc.bottom - rc.top - 315) / 2;

    EnableWindow(parent, FALSE);
    hSearchDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "SearchDlgClass", "Search Directory",
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 x, y, 380, 315, parent, NULL, GetModuleHandle(NULL), NULL);
}

// ============================================================================
// UI WINDOW & EVENT PROCEDURES
// ============================================================================
int hit_test_bubble_char(HDC hdc, int bubble_idx, POINT pt) {
    if (bubble_idx < 0 || bubble_idx >= msg_count) return 0;
    const char* text = chat_log[bubble_idx].text;
    RECT r = chat_log[bubble_idx].text_box;
    int max_w = r.right - r.left;
    if (max_w <= 0) return 0;

    WrappedLine lines[1024];
    int n_lines = compute_wrapped_lines(hdc, text, max_w, lines, 1024);
    if (n_lines <= 0) return 0;

    int rel_x = pt.x - r.left;
    int rel_y = pt.y - r.top;

    int line_idx = 0;
    if (rel_y < 0) {
        line_idx = 0;
        rel_x = 0;
    } else {
        line_idx = n_lines - 1;
        for (int i = 0; i < n_lines; i++) {
            if (rel_y >= lines[i].y_top && rel_y < lines[i].y_top + lines[i].line_height) {
                line_idx = i;
                break;
            }
        }
    }

    WrappedLine* wl = &lines[line_idx];
    if (rel_x <= 0 || wl->len == 0) return wl->start_idx;

    int dx[1024];
    int count = (wl->len < 1024) ? wl->len : 1024;
    int fit = 0;
    SIZE sz;
    GetTextExtentExPointA(hdc, text + wl->start_idx, count, 32767, &fit, dx, &sz);

    int prev_x = 0;
    for (int i = 0; i < count; i++) {
        int cur_x = dx[i];
        int mid_x = (prev_x + cur_x) / 2;
        if (rel_x < mid_x) return wl->start_idx + i;
        prev_x = cur_x;
    }
    return wl->start_idx + count;
}

void draw_bubble_text_and_selection(HDC hdc, int bubble_idx) {
    const char* text = chat_log[bubble_idx].text;
    RECT r = chat_log[bubble_idx].text_box;
    int max_w = r.right - r.left;

    WrappedLine lines[1024];
    int n_lines = compute_wrapped_lines(hdc, text, max_w, lines, 1024);

    int has_sel = (sel_bubble_idx == bubble_idx && sel_anchor_char >= 0 && sel_caret_char >= 0);
    int sel_min = 0, sel_max = 0;
    if (has_sel) {
        sel_min = (sel_anchor_char < sel_caret_char) ? sel_anchor_char : sel_caret_char;
        sel_max = (sel_anchor_char > sel_caret_char) ? sel_anchor_char : sel_caret_char;
    }

    COLORREF bg_col = color_peer;
    if (chat_log[bubble_idx].msg_type == MSG_USER) bg_col = color_user;
    else if (chat_log[bubble_idx].msg_type == MSG_SYS_OK) bg_col = color_sys_ok;
    else if (chat_log[bubble_idx].msg_type == MSG_SYS_ERR) bg_col = color_sys_err;
    
    int c_r = GetRValue(bg_col), c_g = GetGValue(bg_col), c_b = GetBValue(bg_col);
    float luma = 0.299f*c_r + 0.587f*c_g + 0.114f*c_b;
    
    COLORREF normal_text_col = (luma > 186.0f) ? RGB(0, 0, 0) : RGB(255, 255, 255);
    HBRUSH selBrush = CreateSolidBrush((luma > 186.0f) ? RGB(0, 120, 215) : RGB(255, 214, 10));

    for (int i = 0; i < n_lines; i++) {
        WrappedLine* wl = &lines[i];
        int line_start = wl->start_idx;
        int line_end = wl->start_idx + wl->len;
        int draw_y = r.top + wl->y_top;

        if (has_sel && sel_max > sel_min && sel_max > line_start && sel_min < line_end) {
            int hl_start = (sel_min > line_start) ? sel_min : line_start;
            int hl_end   = (sel_max < line_end)   ? sel_max : line_end;

            SIZE sz_pre = {0, 0}, sz_hl = {0, 0};
            if (hl_start > line_start) {
                GetTextExtentPoint32A(hdc, text + line_start, hl_start - line_start, &sz_pre);
            }
            GetTextExtentPoint32A(hdc, text + hl_start, hl_end - hl_start, &sz_hl);

            RECT hlRect = { r.left + sz_pre.cx, draw_y, r.left + sz_pre.cx + sz_hl.cx, draw_y + wl->line_height };
            FillRect(hdc, &hlRect, selBrush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, normal_text_col);
            if (hl_start > line_start) {
                TextOutA(hdc, r.left, draw_y, text + line_start, hl_start - line_start);
            }
            SetTextColor(hdc, (luma > 186.0f) ? RGB(255, 255, 255) : RGB(0, 0, 0));
            TextOutA(hdc, r.left + sz_pre.cx, draw_y, text + hl_start, hl_end - hl_start);
            SetTextColor(hdc, normal_text_col);
            if (line_end > hl_end) {
                TextOutA(hdc, r.left + sz_pre.cx + sz_hl.cx, draw_y, text + hl_end, line_end - line_end);
            }
        } else {
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, normal_text_col);
            if (wl->len > 0) {
                TextOutA(hdc, r.left, draw_y, text + line_start, wl->len);
            }
        }
    }
    DeleteObject(selBrush);
}

void show_bubble_context_menu(HWND hwnd, int msg_idx, POINT screen_pt) {
    HMENU hMenu = CreatePopupMenu();
    int has_range = (msg_idx >= 0 && sel_bubble_idx == msg_idx && sel_anchor_char != sel_caret_char && sel_anchor_char >= 0);

    if (msg_idx >= 0) {
        AppendMenuA(hMenu, has_range ? MF_STRING : (MF_STRING | MF_GRAYED), IDM_COPY_SEL, "Copy Selection\tCtrl+C");
        AppendMenuA(hMenu, MF_STRING, IDM_COPY_ALL, "Copy Entire Bubble");
        AppendMenuA(hMenu, MF_STRING, IDM_SEL_ALL, "Select All in Bubble\tCtrl+A");
        AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuA(hMenu, MF_STRING, IDM_DEL_MSG, "Delete Message");
        AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    }

    AppendMenuA(hMenu, MF_STRING, IDM_SERVER_CONFIG, "Server Connection Settings...");
    AppendMenuA(hMenu, MF_STRING, IDM_SAVE_PDF, "Save Chat to PDF");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, IDM_SET_COLOR_U, "Set User Bubble Color...");
    AppendMenuA(hMenu, MF_STRING, IDM_SET_COLOR_P, "Set Peer Bubble Color...");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, IDM_CLEAR_CHAT, "Clear Chat Log");

    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screen_pt.x, screen_pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);

    if (cmd == IDM_COPY_SEL && has_range) {
        int s_min = (sel_anchor_char < sel_caret_char) ? sel_anchor_char : sel_caret_char;
        int s_max = (sel_anchor_char > sel_caret_char) ? sel_anchor_char : sel_caret_char;
        copy_range_to_clipboard(hwnd, chat_log[msg_idx].text, s_min, s_max);
    } else if (cmd == IDM_COPY_ALL && msg_idx >= 0 && msg_idx < msg_count) {
        copy_range_to_clipboard(hwnd, chat_log[msg_idx].text, 0, (int)strlen(chat_log[msg_idx].text));
    } else if (cmd == IDM_SEL_ALL && msg_idx >= 0 && msg_idx < msg_count) {
        sel_bubble_idx = msg_idx;
        sel_anchor_char = 0;
        sel_caret_char = (int)strlen(chat_log[msg_idx].text);
        InvalidateRect(hwnd, NULL, FALSE);
    } else if (cmd == IDM_SERVER_CONFIG) {
        ShowServerConfigDialog(hMainWindow);
    } else if (cmd == IDM_SAVE_PDF) {
        save_chat_to_pdf(hwnd);
    } else if (cmd == IDM_SET_COLOR_U) {
        PickColor(hwnd, &color_user, "User");
    } else if (cmd == IDM_SET_COLOR_P) {
        PickColor(hwnd, &color_peer, "Peer");
    } else if (cmd == IDM_CLEAR_CHAT) {
        msg_count = 0; scroll_y = 0; InvalidateRect(hwnd, NULL, TRUE);
    } else if (cmd == IDM_DEL_MSG && msg_idx >= 0 && strlen(chat_log[msg_idx].msg_id) > 0) {
        MutateMessageRequest(chat_log[msg_idx].msg_id, 3, NULL);
    }
}

LRESULT CALLBACK ChatViewProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_LBUTTONDOWN: {
            SetFocus(hwnd);
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            int hit = -1;
            for (int i = 0; i < msg_count; i++) {
                if (PtInRect(&chat_log[i].hit_box, pt)) { hit = i; break; }
            }
            if (hit != -1) {
                if (chat_log[hit].msg_type == MSG_SYS_ERR) {
                    ShowServerConfigDialog(hMainWindow);
                    return 0;
                }
                // Check if this bubble is a clickable attachment
                char* att_ptr = strstr(chat_log[hit].text, "[Attachment: ");
                if (att_ptr) {
                    char fname[256] = "";
                    if (sscanf(att_ptr, "[Attachment: %255[^]]]", fname) == 1) {
                        char save_path[MAX_PATH];
                        strncpy(save_path, fname, MAX_PATH - 1);
                        save_path[MAX_PATH - 1] = '\0';

                        OPENFILENAMEA ofn = {0};
                        ofn.lStructSize = sizeof(ofn);
                        ofn.hwndOwner = hMainWindow;
                        ofn.lpstrFilter = "All Files (*.*)\0*.*\0";
                        ofn.lpstrFile = save_path;
                        ofn.nMaxFile = MAX_PATH;
                        ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
                        if (GetSaveFileNameA(&ofn)) {
                            strncpy(g_download_save_path, save_path, MAX_PATH - 1);
                            char req[512];
                            int rlen = snprintf(req, sizeof(req), "FILE_GET %s %s\n", g_target, fname);
                            SendAll(g_sock, req, rlen);
                            SetStatusMsg("Downloading attachment...");
                        }
                        return 0;
                    }
                }

                HDC hdc = GetDC(hwnd);
                HFONT hOld = (HFONT)SelectObject(hdc, hChatFont);
                int ch_idx = hit_test_bubble_char(hdc, hit, pt);
                SelectObject(hdc, hOld);
                ReleaseDC(hwnd, hdc);

                sel_bubble_idx = hit;
                sel_anchor_char = ch_idx;
                sel_caret_char = ch_idx;
                is_mouse_selecting = 1;
                SetCapture(hwnd);
            } else {
                sel_bubble_idx = -1;
                sel_anchor_char = -1;
                sel_caret_char = -1;
            }
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE: {
            if (is_mouse_selecting && sel_bubble_idx >= 0 && sel_bubble_idx < msg_count) {
                POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                HDC hdc = GetDC(hwnd);
                HFONT hOld = (HFONT)SelectObject(hdc, hChatFont);
                int ch_idx = hit_test_bubble_char(hdc, sel_bubble_idx, pt);
                SelectObject(hdc, hOld);
                ReleaseDC(hwnd, hdc);

                if (ch_idx != sel_caret_char) {
                    sel_caret_char = ch_idx;
                    InvalidateRect(hwnd, NULL, FALSE);
                }
            }
            return 0;
        }
        case WM_LBUTTONUP: {
            if (is_mouse_selecting) { is_mouse_selecting = 0; ReleaseCapture(); }
            return 0;
        }
        case WM_RBUTTONUP: {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            int hit = -1;
            for (int i = 0; i < msg_count; i++) {
                if (PtInRect(&chat_log[i].hit_box, pt)) { hit = i; break; }
            }
            POINT screen_pt = pt;
            ClientToScreen(hwnd, &screen_pt);
            if (hit != -1) sel_bubble_idx = hit;
            show_bubble_context_menu(hwnd, hit, screen_pt);
            return 0;
        }
        case WM_VSCROLL: {
            int action = LOWORD(wParam);
            if (action == SB_LINEUP) scroll_y += 40;
            else if (action == SB_LINEDOWN) scroll_y -= 40;
            else if (action == SB_THUMBTRACK) {
                SCROLLINFO si = { sizeof(si), SIF_TRACKPOS };
                GetScrollInfo(hwnd, SB_VERT, &si);
                scroll_y = -si.nTrackPos;
            }
            if (scroll_y > 0) scroll_y = 0;
            if (scroll_y < -(total_height - visible_space) && total_height > visible_space)
                scroll_y = -(total_height - visible_space);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        case WM_MOUSEWHEEL: {
            scroll_y += (GET_WHEEL_DELTA_WPARAM(wParam) > 0) ? 40 : -40;
            if (scroll_y > 0) scroll_y = 0;
            if (scroll_y < -(total_height - visible_space) && total_height > visible_space)
                scroll_y = -(total_height - visible_space);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT clientRect; GetClientRect(hwnd, &clientRect);
            int win_width = clientRect.right - clientRect.left;
            visible_space = clientRect.bottom - clientRect.top;

            HDC hdcMem = CreateCompatibleDC(hdc);
            HBITMAP hbmMem = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
            HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbmMem);

            HBRUSH bgBrush = CreateSolidBrush(RGB(242, 242, 247));
            FillRect(hdcMem, &clientRect, bgBrush);
            HBRUSH brushUser = CreateSolidBrush(color_user);
            HBRUSH brushPeer = CreateSolidBrush(color_peer);
            HBRUSH brushSysOK = CreateSolidBrush(color_sys_ok);
            HBRUSH brushSysErr = CreateSolidBrush(color_sys_err);

            HFONT hOldFont = (HFONT)SelectObject(hdcMem, hChatFont);
            TEXTMETRICA tm; GetTextMetricsA(hdcMem, &tm);
            int lh = tm.tmHeight;

            int y_cursor = 20, bubble_padding = 12, max_bubble_w = (win_width * 7) / 10;
            if (max_bubble_w < 120) max_bubble_w = 120;
            total_height = 20;

            for (int i = 0; i < msg_count; i++) {
                int n_lines = compute_wrapped_lines(hdcMem, chat_log[i].text, max_bubble_w, NULL, 0);
                total_height += (n_lines * lh) + (bubble_padding * 2) + 25;
            }

            if (scroll_y < -(total_height - visible_space) && total_height > visible_space)
                scroll_y = -(total_height - visible_space);
            if (total_height <= visible_space || scroll_y > 0) scroll_y = 0;
            y_cursor += scroll_y;

            HFONT hSmallFont = CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
                                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                           DEFAULT_PITCH | FF_SWISS, "Segoe UI");

            for (int i = 0; i < msg_count; i++) {
                WrappedLine lines[1024];
                int n_lines = compute_wrapped_lines(hdcMem, chat_log[i].text, max_bubble_w, lines, 1024);
                int max_line_px = 45;
                for (int l = 0; l < n_lines; l++) {
                    SIZE sz = {0, 0};
                    if (lines[l].len > 0) GetTextExtentPoint32A(hdcMem, chat_log[i].text + lines[l].start_idx, lines[l].len, &sz);
                    if (sz.cx > max_line_px) max_line_px = sz.cx;
                }

                int b_width = max_line_px + (bubble_padding * 2);
                int b_height = (n_lines * lh) + (bubble_padding * 2);

                RECT bubbleRect = (chat_log[i].msg_type == MSG_USER)
                    ? (RECT){win_width - b_width - 25, y_cursor, win_width - 25, y_cursor + b_height}
                    : (RECT){25, y_cursor, 25 + b_width, y_cursor + b_height};

                RECT drawRect = { bubbleRect.left + bubble_padding, bubbleRect.top + bubble_padding, bubbleRect.right - bubble_padding, bubbleRect.bottom - bubble_padding };

                chat_log[i].hit_box = bubbleRect;
                chat_log[i].text_box = drawRect;

                SelectObject(hdcMem, GetStockObject(NULL_PEN));
                HBRUSH currentBrush = brushPeer;
                if (chat_log[i].msg_type == MSG_USER) currentBrush = brushUser;
                else if (chat_log[i].msg_type == MSG_SYS_OK) currentBrush = brushSysOK;
                else if (chat_log[i].msg_type == MSG_SYS_ERR) currentBrush = brushSysErr;

                if (i == g_strobe_idx && (g_strobe_ticks % 2 != 0)) {
                    HBRUSH strobeBrush = CreateSolidBrush(RGB(255, 235, 59));
                    SelectObject(hdcMem, strobeBrush);
                    RoundRect(hdcMem, bubbleRect.left, bubbleRect.top, bubbleRect.right, bubbleRect.bottom, 20, 20);
                    DeleteObject(strobeBrush);
                } else {
                    SelectObject(hdcMem, currentBrush);
                    RoundRect(hdcMem, bubbleRect.left, bubbleRect.top, bubbleRect.right, bubbleRect.bottom, 20, 20);
                }

                POINT tail[3];
                if (chat_log[i].msg_type == MSG_USER) {
                    tail[0].x = bubbleRect.right - 5;  tail[0].y = bubbleRect.bottom - 20;
                    tail[1].x = bubbleRect.right - 5;  tail[1].y = bubbleRect.bottom - 5;
                    tail[2].x = bubbleRect.right + 10; tail[2].y = bubbleRect.bottom - 5;
                } else {
                    tail[0].x = bubbleRect.left + 5;   tail[0].y = bubbleRect.bottom - 20;
                    tail[1].x = bubbleRect.left + 5;   tail[1].y = bubbleRect.bottom - 5;
                    tail[2].x = bubbleRect.left - 10;  tail[2].y = bubbleRect.bottom - 5;
                }
                Polygon(hdcMem, tail, 3);

                draw_bubble_text_and_selection(hdcMem, i);

                char time_str[32];
                format_timestamp(chat_log[i].timestamp, time_str, sizeof(time_str));

                HFONT hOldSmall = (HFONT)SelectObject(hdcMem, hSmallFont);
                SetBkMode(hdcMem, TRANSPARENT);
                SetTextColor(hdcMem, RGB(140, 140, 145));

                SIZE tsz;
                GetTextExtentPoint32A(hdcMem, time_str, (int)strlen(time_str), &tsz);

                if (chat_log[i].msg_type == MSG_USER) {
                    TextOutA(hdcMem, bubbleRect.right - tsz.cx - 4, bubbleRect.bottom + 2, time_str, (int)strlen(time_str));
                } else {
                    TextOutA(hdcMem, bubbleRect.left + 4, bubbleRect.bottom + 2, time_str, (int)strlen(time_str));
                }

                SelectObject(hdcMem, hOldSmall);
                y_cursor += b_height + 25;
            }

            DeleteObject(hSmallFont);
            BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, hdcMem, 0, 0, SRCCOPY);
            SelectObject(hdcMem, hbmOld); SelectObject(hdcMem, hOldFont);
            DeleteObject(hbmMem); DeleteDC(hdcMem);
            DeleteObject(bgBrush); DeleteObject(brushUser); DeleteObject(brushPeer); DeleteObject(brushSysOK); DeleteObject(brushSysErr);

            SCROLLINFO si = { sizeof(SCROLLINFO), SIF_RANGE | SIF_PAGE | SIF_POS, 0, total_height, (UINT)visible_space, -scroll_y, 0 };
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
            EndPaint(hwnd, &ps);
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Intercept VK_RETURN properly without beeping
LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        char buf[4096]; 
        GetWindowTextA(hwnd, buf, 4096);
        if (strlen(buf) > 0) {
            add_message(buf, MSG_USER);
            SendTextMessage(g_target, buf);
            SetWindowTextA(hwnd, "");
        }
        return 0;
    }
    if (msg == WM_CHAR && wParam == VK_RETURN) {
        return 0;
    }
    return CallWindowProc(OldEditProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            GetModuleFileNameA(NULL, ini_path, MAX_PATH);
            char *ls = strrchr(ini_path, '\\');
            if (ls) *(ls + 1) = '\0';
            strcat(ini_path, "chatclient.ini");

            GetPrivateProfileStringA("Server", "IP", "127.0.0.1", g_server_ip, sizeof(g_server_ip), ini_path);
            g_server_port = GetPrivateProfileIntA("Server", "Port", 5222, ini_path);
            GetPrivateProfileStringA("Server", "User", "admin", g_username, sizeof(g_username), ini_path);
            GetPrivateProfileStringA("Server", "Pass", "password", g_password, sizeof(g_password), ini_path);
            g_reconnect_s = GetPrivateProfileIntA("Server", "Reconnect", 10, ini_path);
            color_user = GetPrivateProfileIntA("Colors", "User", RGB(10, 132, 255), ini_path);
            color_peer = GetPrivateProfileIntA("Colors", "Peer", RGB(229, 229, 234), ini_path);

            g_hReconnectEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

            HMENU hMenuBar = CreateMenu();
            HMENU hConnMenu = CreatePopupMenu();
            AppendMenuA(hConnMenu, MF_STRING, IDM_SERVER_CONFIG, "Server Settings...");
            AppendMenuA(hConnMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(hConnMenu, MF_STRING, IDM_NEW_CHAT, "Create New Chat Room...");
            AppendMenuA(hConnMenu, MF_STRING, IDM_ADD_USER, "Add User to Current Chat...");
            AppendMenuA(hConnMenu, MF_STRING, IDM_SEARCH_USERS, "Search Directory...");
            AppendMenuA(hConnMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(hConnMenu, MF_STRING, IDM_SAVE_PDF, "Export Chat to PDF");
            AppendMenuA(hConnMenu, MF_STRING, IDM_TOGGLE_STARTUP, "Start With Windows");
            AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hConnMenu, "Connection");
            SetMenu(hwnd, hMenuBar);

            DragAcceptFiles(hwnd, TRUE);
            hChatFont = CreateFont(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                   DEFAULT_PITCH | FF_SWISS, "Segoe UI");

            hRoomSearch = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "Search chats...", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 150, 25, hwnd, (HMENU)ID_ROOM_SEARCH, GetModuleHandle(NULL), NULL);
            hChatSearch = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "Search messages...", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 150, 0, 350, 25, hwnd, (HMENU)ID_CHAT_SEARCH, GetModuleHandle(NULL), NULL);
            hStatusBar = CreateWindowEx(0, "STATIC", " Ready", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUS_BAR, GetModuleHandle(NULL), NULL);
            
            SendMessage(hRoomSearch, WM_SETFONT, (WPARAM)hChatFont, TRUE);
            SendMessage(hChatSearch, WM_SETFONT, (WPARAM)hChatFont, TRUE);

            hLeftPane = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", "", 
                                       WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
                                       0, 25, 150, 525, hwnd, (HMENU)ID_LEFT_PANE, GetModuleHandle(NULL), NULL);
            SendMessage(hLeftPane, WM_SETFONT, (WPARAM)hChatFont, TRUE);
            
            for (int i = 0; i < g_all_rooms_count; i++) {
                SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)g_all_rooms[i]);
            }
            SendMessage(hLeftPane, LB_SETCURSEL, 0, 0);
            strcpy(g_target, "#general");

            hChatView = CreateWindowEx(0, "ChatCanvasClass", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL,
                                       150, 25, 350, 525, hwnd, NULL, GetModuleHandle(NULL), NULL);

            hEdit = CreateWindowEx(0, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                   160, 10, 330, 30, hwnd, (HMENU)ID_EDIT, GetModuleHandle(NULL), NULL);
            SendMessage(hEdit, WM_SETFONT, (WPARAM)hChatFont, TRUE);
            OldEditProc = (WNDPROC)SetWindowLongPtr(hEdit, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);

            g_app_running = 1;
            g_net_thread = CreateThread(NULL, 0, NetworkWorkerThread, NULL, 0, NULL);
            return 0;
        }
        case WM_UPDATE_CHAT: {
            InvalidateRect(hChatView, NULL, FALSE);
            return 0;
        }
        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            char filepath[MAX_PATH];
            DragQueryFileA(hDrop, 0, filepath, MAX_PATH);
            DragFinish(hDrop);
            SendFileTransfer(g_target, filepath);
            return 0;
        }
        case WM_TIMER: {
            if (wParam == 1001) {
                KillTimer(hwnd, 1001);
                char query[256];
                GetWindowTextA(hRoomSearch, query, sizeof(query));
                
                SendMessage(hLeftPane, LB_RESETCONTENT, 0, 0);
                for (int i = 0; i < g_all_rooms_count; i++) {
                    if (strlen(query) == 0 || strcmp(query, "Search chats...") == 0 || StrStrIA(g_all_rooms[i], query)) {
                        SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)g_all_rooms[i]);
                    }
                }
            } 
            else if (wParam == 1002) {
                KillTimer(hwnd, 1002);
                char query[256];
                GetWindowTextA(hChatSearch, query, sizeof(query));
                if (strlen(query) > 0 && strcmp(query, "Search messages...") != 0) {
                    for (int i = 0; i < msg_count; i++) {
                        if (StrStrIA(chat_log[i].text, query)) {
                            scroll_y = -(chat_log[i].hit_box.top) + (visible_space / 2);
                            if (scroll_y > 0) scroll_y = 0;
                            g_strobe_idx = i;
                            g_strobe_ticks = 6; 
                            SetTimer(hwnd, 1003, 150, NULL);
                            InvalidateRect(hChatView, NULL, TRUE);
                            break;
                        }
                    }
                }
            }
            else if (wParam == 1003) {
                g_strobe_ticks--;
                InvalidateRect(hChatView, NULL, TRUE);
                if (g_strobe_ticks <= 0) {
                    g_strobe_idx = -1;
                    KillTimer(hwnd, 1003);
                }
            }
            return 0;
        }
        case WM_COMMAND: {
            WORD wmId = LOWORD(wParam);
            WORD wmEvent = HIWORD(wParam);

            if (wmEvent == EN_SETFOCUS) {
                if (wmId == ID_ROOM_SEARCH || wmId == ID_CHAT_SEARCH) {
                    char buf[256];
                    GetWindowTextA((HWND)lParam, buf, sizeof(buf));
                    if (strcmp(buf, "Search chats...") == 0 || strcmp(buf, "Search messages...") == 0) {
                        SetWindowTextA((HWND)lParam, "");
                    }
                }
            }
            else if (wmEvent == EN_KILLFOCUS) {
                if (wmId == ID_ROOM_SEARCH) {
                    char buf[256];
                    GetWindowTextA((HWND)lParam, buf, sizeof(buf));
                    if (strlen(buf) == 0) SetWindowTextA((HWND)lParam, "Search chats...");
                } else if (wmId == ID_CHAT_SEARCH) {
                    char buf[256];
                    GetWindowTextA((HWND)lParam, buf, sizeof(buf));
                    if (strlen(buf) == 0) SetWindowTextA((HWND)lParam, "Search messages...");
                }
            }
            else if (wmEvent == EN_CHANGE) {
                if (wmId == ID_ROOM_SEARCH) {
                    KillTimer(hwnd, 1001);
                    SetTimer(hwnd, 1001, 500, NULL);
                } else if (wmId == ID_CHAT_SEARCH) {
                    KillTimer(hwnd, 1002);
                    SetTimer(hwnd, 1002, 500, NULL);
                }
            } 
            else if (wmId == ID_LEFT_PANE && wmEvent == LBN_SELCHANGE) {
                int idx = (int)SendMessage(hLeftPane, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char room_name[256];
                    SendMessageA(hLeftPane, LB_GETTEXT, idx, (LPARAM)room_name);
                    if (strncmp(room_name, "# ", 2) == 0) {
                        snprintf(g_target, sizeof(g_target), "#%s", room_name + 2);
                    } else if (strncmp(room_name, "@ ", 2) == 0) {
                        strncpy(g_target, room_name + 2, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                    } else {
                        strncpy(g_target, room_name, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                    }
                    
                    msg_count = 0; 
                    InvalidateRect(hChatView, NULL, TRUE);
                    // Fetch history for BOTH #rooms and 1-on-1 direct chats
                    JoinRoom(g_target);
                }
            } 
            else if (wmId == IDM_SERVER_CONFIG) {
                ShowServerConfigDialog(hwnd);
            } 
            else if (wmId == IDM_SAVE_PDF) {
                save_chat_to_pdf(hwnd);
            } 
            else if (wmId == IDM_TOGGLE_STARTUP) {
                HMENU menu = GetMenu(hwnd);
                UINT state = GetMenuState(menu, IDM_TOGGLE_STARTUP, MF_BYCOMMAND);
                if (state & MF_CHECKED) {
                    CheckMenuItem(menu, IDM_TOGGLE_STARTUP, MF_UNCHECKED);
                    ToggleRunAtStartup(FALSE);
                } else {
                    CheckMenuItem(menu, IDM_TOGGLE_STARTUP, MF_CHECKED);
                    ToggleRunAtStartup(TRUE);
                }
            }
            else if (wmId == IDM_NEW_CHAT) {
                char room_name[256] = "";
                if (ShowInputDialog(hwnd, "Create New Chat Room", "Enter room name (e.g. #marketing):", room_name, sizeof(room_name))) {
                    if (strlen(room_name) > 0) {
                        char target[256], display_room[260];
                        if (room_name[0] != '#') snprintf(target, sizeof(target), "#%s", room_name);
                        else strncpy(target, room_name, sizeof(target) - 1);
                        snprintf(display_room, sizeof(display_room), "# %s", target + 1);
                        
                        BOOL exists = FALSE;
                        for (int i = 0; i < g_all_rooms_count; i++) {
                            if (CaseInsensitiveCompare(g_all_rooms[i], display_room) == 0 ||
                                CaseInsensitiveCompare(g_all_rooms[i], target) == 0) exists = TRUE;
                        }
                        if (!exists && g_all_rooms_count < 64) {
                            strncpy(g_all_rooms[g_all_rooms_count++], display_room, 255);
                            SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)display_room);
                        }
                        
                        strcpy(g_target, target);
                        msg_count = 0;
                        JoinRoom(g_target);
                        InvalidateRect(hChatView, NULL, TRUE);
                    }
                }
            }
            else if (wmId == IDM_ADD_USER) {
                if (g_target[0] != '#') {
                    MessageBoxA(hwnd, "You can only invite users to a group chat room.", "Error", MB_ICONWARNING | MB_OK);
                } else {
                    char target_user[256] = "";
                    if (ShowInputDialog(hwnd, "Add User to Chat", "Enter username to invite:", target_user, sizeof(target_user))) {
                        if (strlen(target_user) > 0 && g_connected && g_sock != INVALID_SOCKET) {
                            char stanza[512];
                            int len = snprintf(stanza, sizeof(stanza), "<invite to=\"%s\" room=\"%s\"/>\n", target_user, g_target);
                            SendAll(g_sock, stanza, len);
                        }
                    }
                }
            }
            else if (wmId == IDM_SEARCH_USERS) {
                ShowSearchDialog(hwnd);
            }
            return 0;
        }
        case WM_SIZE: {
            int width = LOWORD(lParam), height = HIWORD(lParam);
            int bar_h = 40, sb_h = 25, search_h = 25;
            int chat_h = (height > bar_h + sb_h) ? (height - bar_h - sb_h) : 0;

            MoveWindow(hStatusBar, 0, height - sb_h, width, sb_h, TRUE);
            MoveWindow(hRoomSearch, 0, 0, 150, search_h, TRUE);
            MoveWindow(hLeftPane, 0, search_h, 150, chat_h - search_h + bar_h, TRUE);
            MoveWindow(hChatSearch, 150, 0, width - 150, search_h, TRUE);
            MoveWindow(hChatView, 150, search_h, width - 150, chat_h - search_h, TRUE);
            MoveWindow(hEdit, 160, height - sb_h - 35, width - 170, 30, TRUE);
            InvalidateRect(hChatView, NULL, TRUE);
            return 0;
        }
        case WM_MOUSEWHEEL: {
            return SendMessage(hChatView, uMsg, wParam, lParam);
        }
        case WM_DESTROY:
            g_app_running = 0;
            g_connected = 0;
            if (g_sock != INVALID_SOCKET) closesocket(g_sock);
            
            if (g_hReconnectEvent) {
                SetEvent(g_hReconnectEvent);
                if (g_net_thread) WaitForSingleObject(g_net_thread, 1000);
                CloseHandle(g_hReconnectEvent);
            }
            
            if (hChatFont) DeleteObject(hChatFont);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    WNDCLASS wcChat = {0};
    wcChat.style = CS_DBLCLKS;
    wcChat.lpfnWndProc = ChatViewProc;
    wcChat.hInstance = hInstance;
    wcChat.lpszClassName = "ChatCanvasClass";
    wcChat.hCursor = LoadCursor(NULL, IDC_IBEAM);
    RegisterClass(&wcChat);

    const char CLASS_NAME[] = "ChatClientClass";
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(242, 242, 247));
    RegisterClass(&wc);

    hMainWindow = CreateWindowEx(0, CLASS_NAME, "Enterprise Chat Client",
                                 WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 650, 650,
                                 NULL, NULL, hInstance, NULL);
    if (hMainWindow == NULL) return 0;
    ShowWindow(hMainWindow, nCmdShow);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
