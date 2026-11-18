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
#define IDM_COPY_SEL       2001
#define IDM_COPY_ALL       2002
#define IDM_SEL_ALL        2003
#define IDM_SAVE_PDF       2004
#define IDM_CLEAR_CHAT     2005
#define IDM_SET_COLOR_U    2007
#define IDM_SET_COLOR_P    2008
#define IDM_JOIN_ROOM      2009
#define IDM_EDIT_MSG       2010
#define IDM_DEL_MSG        2011
#define IDM_SERVER_CONFIG  2012
#define IDM_NEW_CHAT       2013
#define IDM_ADD_USER       2014
#define IDM_SEARCH_USERS   2015
#define IDM_TOGGLE_STARTUP 2016
#define IDM_EDIT_VCARD     2017
#define IDM_KICK_USER      2018
#define IDM_TOGGLE_PIN_CUR 2019
#define ID_CHK_PINNED      2020
#define IDM_NEW_DM         2021
#define MSG_USER          0
#define MSG_PEER          1
#define MSG_SYS_OK        2
#define MSG_SYS_ERR       3
#define WM_UPDATE_CHAT    (WM_APP + 1)
// ============================================================================
// DYNAMIC SERVER & CONNECTION CONFIGURATION DIALOG
// ============================================================================
#define DLG_EDIT_IP       3001
#define DLG_EDIT_PORT     3002
#define DLG_EDIT_USER     3003
#define DLG_EDIT_PASS     3004
#define DLG_BTN_SAVE      3006
#define DLG_BTN_CANC      3007
#define DLG_CHK_STARTUP   3005
// Much lighter error hue
COLORREF color_user    = RGB(210, 230, 255); 


// Much lighter user bubble hue
COLORREF color_peer    = RGB(240, 240, 245); 
// Much lighter peer bubble hue
COLORREF color_sys_ok  = RGB(215, 245, 215); 
// Much lighter success hue
COLORREF color_sys_err = RGB(255, 215, 215); 
// Much lighter error hue

typedef struct {
    char user[256];
    int state; // 0 = offline, 1 = online, 2 = away
} PeerPresence;

typedef struct {
    const char* title;
    const char* prompt;
    char* out_buf;
    int buf_size;
    int confirmed;
} InputDialogCtx;

typedef struct {
    char text[262144];
    char msg_id[64];
    char sender[256];
    int msg_type;
    int status;
    time_t timestamp;
    RECT hit_box;
    RECT text_box;
} ChatMsg;

typedef struct {
    int start_idx;
    int len;
    int y_top;
    int line_height;
} WrappedLine;

typedef struct { char* data; int len; int cap; } Stream;

typedef struct {
    char target[256];
    char filepath[MAX_PATH];
} UploadTask;

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
WNDPROC OldLeftPaneProc = NULL;
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

char g_fullname[256] = "";
char g_email[256]    = "";

// --- Search, Notification & Startup Globals ---
int g_strobe_idx = -1;
int g_strobe_ticks = 0;
char g_all_rooms[64][256] = {"#general", "#developers", "#announcements"};
int g_all_rooms_count = 0;

// ============================================================================
// CLIENT SIDE: chatclient.c
// ============================================================================

int g_room_synced[64] = {0};
int g_room_pinned[64] = {0};
int g_filter_pinned_only = 0;
HWND hPinFilterChk = NULL;

BOOL g_enable_sound = TRUE;
BOOL g_enable_popup = TRUE;
char g_chat_search[256] = "";
volatile int g_app_running = 1;
int g_reconnect_s = 10;
HANDLE g_hReconnectEvent = NULL;

static HWND hInputDlg = NULL;
static PeerPresence g_presences[128];
static int g_presence_count = 0;
static int g_last_search_idx = -1;
static WNDPROC OldChatSearchProc = NULL;
static CRITICAL_SECTION g_send_cs;
static BOOL g_send_cs_init = FALSE;

static InputDialogCtx* g_input_ctx = NULL;
char g_download_save_path[MAX_PATH] = "";
HWND hConfigDlg = NULL;
HWND hVCardDlg = NULL;

// --- New Global Variables for vCard ---
char g_phone[256]    = "";
char g_title[256]    = "";
char g_org[256]      = "";

// --- New Global Variables ---
char g_last_notif_room[256] = "";

int g_room_unread[64] = {0};
// --- Forward Declarations ---
void add_message(const char* text, int msg_type);
void add_message_full(const char* text, const char* sender, const char* msg_id, int msg_type, int status);
void save_chat_to_pdf(HWND hwnd);
void ShowServerConfigDialog(HWND hwnd);
void ShowVCardDialog(HWND hwnd);
DWORD WINAPI NetworkWorkerThread(LPVOID lpParam);
int SendAll(SOCKET sock, const char* buf, int len);
void JoinRoom(const char* room_name);
void SetStatusMsg(const char* msg);
void RefreshLeftPane(void);
void NormalizeRoomKey(const char* src, char* dst, int max_len);
void SaveRoomPinState(int room_idx);
void LoadPinnedSettings(void);
int EnsureRoomInList(const char* room, BOOL save);
void RemoveRoomFromList(const char* room);
void GenerateClientMsgID(char* out_id);
int CaseInsensitiveCompare(const char* a, const char* b);
void ExecuteNextMessageSearch(HWND hwnd);
void ToggleRunAtStartup(BOOL enable);
BOOL IsRunAtStartupEnabled(void);
void TrimString(char* s);

int hit_test_bubble_char(HDC hdc, int bubble_idx, POINT pt);
void show_bubble_context_menu(HWND hwnd, int msg_idx, POINT screen_pt);
int compute_wrapped_lines(HDC hdc, const char* text, int max_width, WrappedLine* out_lines, int max_lines);
static void GetTextExtentUTF8(HDC hdc, const char* utf8, int byte_len, SIZE* sz);
void draw_bubble_text_and_selection(HDC hdc, int bubble_idx);
void format_timestamp(time_t t, char* out, int max_len);
static void TextOutW_UTF8(HDC hdc, int x, int y, const char* utf8, int byte_len);
void copy_range_to_clipboard(HWND hwnd, const char* src, int start_idx, int end_idx);
void PickColor(HWND hwnd, COLORREF* current_color, const char* key);
void MutateMessageRequest(const char* msg_id, int action, const char* new_content);
static LRESULT CALLBACK VCardDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
// Tracks unacknowledged background chats

void ClearRoomUnread(const char* target) {
    char norm_target[256];
    NormalizeRoomKey(target, norm_target, sizeof(norm_target));
    for (int i = 0; i < g_all_rooms_count; i++) {
        char k[256];
        NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
        
        const char* check_k = k;
        if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
        else if (check_k[0] == '@') check_k += 1;
        else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
        else if (check_k[0] == '#') check_k += 1;
        
        const char* check_t = norm_target;
        if (strncmp(check_t, "@ ", 2) == 0) check_t += 2;
        else if (check_t[0] == '@') check_t += 1;
        else if (strncmp(check_t, "# ", 2) == 0) check_t += 2;
        else if (check_t[0] == '#') check_t += 1;
        
        if (CaseInsensitiveCompare(check_k, check_t) == 0) {
            g_room_unread[i] = 0;
            break;
        }
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

            HBRUSH bgBrush = CreateSolidBrush(RGB(250, 250, 245)); // Off-white chat background
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

            HFONT hSmallFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                           OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                           DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

            for (int i = 0; i < msg_count; i++) {
                WrappedLine lines[1024];
                int n_lines = compute_wrapped_lines(hdcMem, chat_log[i].text, max_bubble_w, lines, 1024);
                int max_line_px = 45;
                for (int l = 0; l < n_lines; l++) {
                    SIZE sz = {0, 0};
                    if (lines[l].len > 0) GetTextExtentUTF8(hdcMem, chat_log[i].text + lines[l].start_idx, lines[l].len, &sz);
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

                int bubble_top = y_cursor;
                int bubble_bottom = y_cursor + b_height;
                BOOL is_visible = (bubble_bottom >= 0 && bubble_top <= visible_space);

                if (is_visible && chat_log[i].msg_type == MSG_PEER && chat_log[i].status < 2) {
                    chat_log[i].status = 2;
                    if (g_connected && g_sock != INVALID_SOCKET && chat_log[i].msg_id[0] != '\0') {
                        char v_pkt[256];
                        const char* v_target = (g_target[0] == '#') ? g_target : chat_log[i].sender;
                        int vlen = snprintf(v_pkt, sizeof(v_pkt), "<viewed id=\"%s\" to=\"%s\"/>\n", chat_log[i].msg_id, v_target);
                        SendAll(g_sock, v_pkt, vlen);
                    }
                }

                SelectObject(hdcMem, GetStockObject(NULL_PEN));
                HBRUSH currentBrush = brushPeer;
                if (chat_log[i].msg_type == MSG_USER) currentBrush = brushUser;
                else if (chat_log[i].msg_type == MSG_SYS_OK) currentBrush = brushSysOK;
                else if (chat_log[i].msg_type == MSG_SYS_ERR) currentBrush = brushSysErr;

                HBRUSH strobeBrush = NULL;
                if (chat_log[i].msg_type == MSG_PEER && chat_log[i].status < 2) {
                    DWORD ticks = GetTickCount();
                    if ((ticks / 500) % 2 == 0) {
                        strobeBrush = CreateSolidBrush(RGB(255, 235, 59));
                        currentBrush = strobeBrush;
                    }
                } else if (i == g_strobe_idx && (g_strobe_ticks % 2 != 0)) {
                    strobeBrush = CreateSolidBrush(RGB(255, 235, 59));
                    currentBrush = strobeBrush;
                }

                SelectObject(hdcMem, currentBrush);
                RoundRect(hdcMem, bubbleRect.left, bubbleRect.top, bubbleRect.right, bubbleRect.bottom, 20, 20);
                
                if (strobeBrush) DeleteObject(strobeBrush);

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

                char time_str[32], meta_str[128];
                format_timestamp(chat_log[i].timestamp, time_str, sizeof(time_str));

                if (chat_log[i].msg_type == MSG_USER) {
                    const char* receipt = (chat_log[i].status >= 2) ? "\xE2\x9C\x93\xE2\x9C\x93 Viewed" : (chat_log[i].status == 1 ? "\xE2\x9C\x93 Sent" : "Sending...");
                    snprintf(meta_str, sizeof(meta_str), "%s  %s", time_str, receipt);
                } else if (strlen(chat_log[i].sender) > 0) {
                    snprintf(meta_str, sizeof(meta_str), "%s \xE2\x80\xA2 %s", chat_log[i].sender, time_str);
                } else {
                    snprintf(meta_str, sizeof(meta_str), "%s", time_str);
                }

                HFONT hOldSmall = (HFONT)SelectObject(hdcMem, hSmallFont);
                SetBkMode(hdcMem, TRANSPARENT);
                SetTextColor(hdcMem, (chat_log[i].msg_type == MSG_USER && chat_log[i].status >= 2) ? RGB(10, 132, 255) : RGB(140, 140, 145));

                SIZE tsz = {0, 0};
                GetTextExtentUTF8(hdcMem, meta_str, (int)strlen(meta_str), &tsz);

                if (chat_log[i].msg_type == MSG_USER) {
                    TextOutW_UTF8(hdcMem, bubbleRect.right - tsz.cx - 4, bubbleRect.bottom + 2, meta_str, (int)strlen(meta_str));
                } else {
                    TextOutW_UTF8(hdcMem, bubbleRect.left + 4, bubbleRect.bottom + 2, meta_str, (int)strlen(meta_str));
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
                GetTextExtentUTF8(hdc, text + line_start, hl_start - line_start, &sz_pre);
            }
            GetTextExtentUTF8(hdc, text + hl_start, hl_end - hl_start, &sz_hl);

            RECT hlRect = { r.left + sz_pre.cx, draw_y, r.left + sz_pre.cx + sz_hl.cx, draw_y + wl->line_height };
            FillRect(hdc, &hlRect, selBrush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, normal_text_col);
            if (hl_start > line_start) {
                TextOutW_UTF8(hdc, r.left, draw_y, text + line_start, hl_start - line_start);
            }
            SetTextColor(hdc, (luma > 186.0f) ? RGB(255, 255, 255) : RGB(0, 0, 0));
            TextOutW_UTF8(hdc, r.left + sz_pre.cx, draw_y, text + hl_start, hl_end - hl_start);
            SetTextColor(hdc, normal_text_col);
            if (line_end > hl_end) {
                TextOutW_UTF8(hdc, r.left + sz_pre.cx + sz_hl.cx, draw_y, text + hl_end, line_end - hl_end);
            }
        } else {
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, normal_text_col);
            if (wl->len > 0) {
                TextOutW_UTF8(hdc, r.left, draw_y, text + line_start, wl->len);
            }
        }
    }
    DeleteObject(selBrush);
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

static LRESULT CALLBACK InputDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = GetModuleHandle(NULL);
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            HWND lbl = CreateWindowA("STATIC", g_input_ctx->prompt, WS_CHILD | WS_VISIBLE, 15, 15, 300, 20, hwnd, NULL, hInst, NULL);
            HWND ed = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 15, 40, 300, 24, hwnd, (HMENU)3001, hInst, NULL);
            HWND btnOK = CreateWindowA("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 115, 80, 80, 30, hwnd, (HMENU)3002, hInst, NULL);
            HWND btnCancel = CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE, 205, 80, 80, 30, hwnd, (HMENU)3003, hInst, NULL);
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

// Add this globally next to g_room_pinned

void LoadRoomList(void) {
    char rooms_str[8192] = "";
    GetPrivateProfileStringA("Settings", "Rooms", "#general", rooms_str, sizeof(rooms_str), ini_path);
    g_all_rooms_count = 0;
    char* token = strtok(rooms_str, ",");
    while (token && g_all_rooms_count < 64) {
        TrimString(token);
        if (strlen(token) > 0) {
            BOOL dup = FALSE;
            char tk_norm[256];
            NormalizeRoomKey(token, tk_norm, sizeof(tk_norm));
            const char* check_tk = tk_norm;
            if (strncmp(check_tk, "@ ", 2) == 0) check_tk += 2;
            else if (check_tk[0] == '@') check_tk += 1;
            else if (strncmp(check_tk, "# ", 2) == 0) check_tk += 2;
            else if (check_tk[0] == '#') check_tk += 1;

            for (int i = 0; i < g_all_rooms_count; i++) {
                char k[256];
                NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
                const char* check_k = k;
                if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
                else if (check_k[0] == '@') check_k += 1;
                else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
                else if (check_k[0] == '#') check_k += 1;
                
                if (CaseInsensitiveCompare(check_k, check_tk) == 0) { 
                    dup = TRUE;
                    if ((token[0] == '@' || token[0] == '#') && g_all_rooms[i][0] != '@' && g_all_rooms[i][0] != '#') {
                        strncpy(g_all_rooms[i], token, 255);
                    }
                    break; 
                }
            }
            if (!dup) {
                strncpy(g_all_rooms[g_all_rooms_count], token, 255);
                g_room_synced[g_all_rooms_count] = 0; 
                g_all_rooms_count++;
            }
        }
        token = strtok(NULL, ",");
    }
}

LRESULT CALLBACK LeftPaneDrawProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_MEASUREITEM) {
        MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
        if (mis) mis->itemHeight = 22;
        return TRUE;
    }
    if (msg == WM_DRAWITEM) {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        if (dis && dis->itemID != (UINT)-1) {
            char item_text[320] = "";
            SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)item_text);

            int is_selected = (dis->itemState & ODS_SELECTED);
            
            char clean_text[320];
            strncpy(clean_text, item_text, sizeof(clean_text) - 1);
            clean_text[sizeof(clean_text) - 1] = '\0';
            char* bracket = strstr(clean_text, " [Online]");
            if (!bracket) bracket = strstr(clean_text, " [Away]");
            if (!bracket) bracket = strstr(clean_text, " [Offline]");
            if (bracket) *bracket = '\0';

            char norm_item[256], norm_target[256];
            NormalizeRoomKey(clean_text, norm_item, sizeof(norm_item));
            NormalizeRoomKey(g_target, norm_target, sizeof(norm_target));

            int is_current = (CaseInsensitiveCompare(norm_item, norm_target) == 0 ||
                              (norm_item[0] == '@' && CaseInsensitiveCompare(norm_item + 1, norm_target) == 0));

            int is_pinned = 0;
            for (int i = 0; i < g_all_rooms_count; i++) {
                char k[256];
                NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
                if (CaseInsensitiveCompare(k, norm_item) == 0 || (norm_item[0] == '@' && CaseInsensitiveCompare(k + 1, norm_item + 1) == 0)) {
                    if (g_room_pinned[i]) is_pinned = 1;
                    break;
                }
            }

            HBRUSH bg = CreateSolidBrush(is_selected ? RGB(0, 120, 215) : (is_current ? RGB(230, 240, 255) : RGB(255, 255, 255)));
            FillRect(dis->hDC, &dis->rcItem, bg);
            DeleteObject(bg);

            SetBkMode(dis->hDC, TRANSPARENT);
            SetTextColor(dis->hDC, is_selected ? RGB(255, 255, 255) : RGB(0, 0, 0));

            HFONT hFontItem = CreateFontA(16, 0, 0, 0, (is_pinned || is_current) ? FW_BOLD : FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            HGDIOBJ oldFont = SelectObject(dis->hDC, hFontItem);

            RECT rc = dis->rcItem;
            rc.left += 6;
            DrawTextA(dis->hDC, item_text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

            SelectObject(dis->hDC, oldFont);
            DeleteObject(hFontItem);
            return TRUE;
        }
    }
    return CallWindowProc(OldLeftPaneProc, hwnd, msg, wParam, lParam);
}

void SaveRoomList(void) {
    char rooms_str[8192] = "";
    for (int i = 0; i < g_all_rooms_count; i++) {
        strcat(rooms_str, g_all_rooms[i]);
        if (i < g_all_rooms_count - 1) strcat(rooms_str, ",");
    }
    WritePrivateProfileStringA("Settings", "Rooms", rooms_str, ini_path);
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

    AppendMenuA(hMenu, MF_STRING, IDM_SERVER_CONFIG, "Settings");
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

void ShowVCardDialog(HWND hwnd) {
    if (hVCardDlg) { SetForegroundWindow(hVCardDlg); return; }
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = VCardDlgProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "VCardDlgClass";
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    RECT rc; GetWindowRect(hwnd, &rc);
    int x = rc.left + (rc.right - rc.left - 330) / 2;
    int y = rc.top + (rc.bottom - rc.top - 260) / 2;

    EnableWindow(hwnd, FALSE);
    hVCardDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "VCardDlgClass", "Edit Profile (vCard)",
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 x, y, 330, 260, hwnd, NULL, GetModuleHandle(NULL), NULL);
}

static void SanitizeClientText(char* s) {
    if (!s) return;
    for (char* p = s; *p; p++) {
        if (*p == '\r' || *p == '\n') *p = ' ';
    }
    char* bad;
    while ((bad = strstr(s, "</body>")) != NULL) {
        memcpy(bad, "[/body]", 7);
    }
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
            if (LOWORD(wParam) == 4002) {
                char query[256];
                GetDlgItemTextA(hwnd, 4001, query, sizeof(query));
                if (g_connected && g_sock != INVALID_SOCKET) {
                    char stanza[512];
                    int len = snprintf(stanza, sizeof(stanza), "<iq type=\"get\"><query xmlns=\"jabber:iq:search\"><text>%s</text></query></iq>\n", query);
                    SendAll(g_sock, stanza, len);
                    
                    SendDlgItemMessageA(hwnd, 4003, LB_RESETCONTENT, 0, 0);
                    SendDlgItemMessageA(hwnd, 4003, LB_ADDSTRING, 0, (LPARAM)"Request sent to server...");
                }
            } else if (LOWORD(wParam) == 4005) {
                int idx = (int)SendDlgItemMessageA(hwnd, 4003, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char sel_user[256];
                    SendDlgItemMessageA(hwnd, 4003, LB_GETTEXT, idx, (LPARAM)sel_user);
                    if (strcmp(sel_user, "No users matched.") != 0 && strcmp(sel_user, "Request sent to server...") != 0) {
                        char clean_user[256];
                        if (strncmp(sel_user, "- ", 2) == 0) strcpy(clean_user, sel_user + 2);
                        else strcpy(clean_user, sel_user);
                        char* space = strchr(clean_user, ' ');
                        if (space) *space = '\0';

                        if (g_target[0] != '#') {
                            MessageBoxA(hwnd, "Switch to a #room first to invite users to it.", "Error", MB_ICONWARNING | MB_OK);
                        } else {
                            char stanza[512];
                            int len = snprintf(stanza, sizeof(stanza), "<invite to=\"%s\" room=\"%s\"/>\n", clean_user, g_target);
                            SendAll(g_sock, stanza, len);
                            MessageBoxA(hwnd, "Invite dispatched.", "Success", MB_OK);
                        }
                    }
                }
            } else if (LOWORD(wParam) == 4006) {
                int idx = (int)SendDlgItemMessageA(hwnd, 4003, LB_GETCURSEL, 0, 0);
                if (idx != LB_ERR) {
                    char sel_user[256];
                    SendDlgItemMessageA(hwnd, 4003, LB_GETTEXT, idx, (LPARAM)sel_user);
                    if (strcmp(sel_user, "No users matched.") != 0 && strcmp(sel_user, "Request sent to server...") != 0) {
                        char clean_user[256];
                        if (strncmp(sel_user, "- ", 2) == 0) strcpy(clean_user, sel_user + 2);
                        else strcpy(clean_user, sel_user);
                        char* space = strchr(clean_user, ' ');
                        if (space) *space = '\0';

                        char dm_label[260];
                        snprintf(dm_label, sizeof(dm_label), "@ %s", clean_user);
                        EnsureRoomInList(dm_label, TRUE);
                        strncpy(g_target, clean_user, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                        msg_count = 0;
                        ClearRoomUnread(g_target);
                        RefreshLeftPane();
                        InvalidateRect(hChatView, NULL, TRUE);
                        JoinRoom(g_target);
                        DestroyWindow(hwnd);
                    }
                }
            } else if (LOWORD(wParam) == 4004) {
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
    int x = rc.left + (rc.right - rc.left - 330) / 2;
    int y = rc.top + (rc.bottom - rc.top - 160) / 2;

    EnableWindow(parent, FALSE);
    hInputDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "InputDlgClass", title,
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 x, y, 330, 160, parent, NULL, GetModuleHandle(NULL), NULL);

    MSG msg;
    while (hInputDlg && GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hInputDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return ctx.confirmed;
}

void TrimString(char* s) {
    char* p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
}

void NormalizeRoomKey(const char* src, char* dst, int max_len) {
    if (!src || !dst || max_len <= 0) return;
    int i = 0;
    while (*src && i < max_len - 1) {
        dst[i++] = tolower((unsigned char)*src);
        src++;
    }
    dst[i] = '\0';
}

void SaveRoomPinState(int room_idx) {
    if (room_idx < 0 || room_idx >= g_all_rooms_count) return;
    char key[256];
    snprintf(key, sizeof(key), "Pin_%s", g_all_rooms[room_idx]);
    WritePrivateProfileStringA("PinnedRooms", key, g_room_pinned[room_idx] ? "1" : "0", ini_path);
}

void LoadPinnedSettings(void) {
    g_filter_pinned_only = GetPrivateProfileIntA("Settings", "FilterPinnedOnly", 0, ini_path);
    for (int i = 0; i < g_all_rooms_count; i++) {
        char key[256];
        snprintf(key, sizeof(key), "Pin_%s", g_all_rooms[i]);
        g_room_pinned[i] = GetPrivateProfileIntA("PinnedRooms", key, 0, ini_path);
    }
}

int EnsureRoomInList(const char* room, BOOL save) {
    if (!room || room[0] == '\0') return -1;
    
    char formatted_room[256];
    if (room[0] == '@' && room[1] == ' ' && room[2] == '#') {
        strncpy(formatted_room, room + 2, sizeof(formatted_room) - 1);
    } else if (room[0] == '@' && room[1] == '#') {
        strncpy(formatted_room, room + 1, sizeof(formatted_room) - 1);
    } else {
        strncpy(formatted_room, room, sizeof(formatted_room) - 1);
    }
    formatted_room[255] = '\0';
    
    char norm[256];
    NormalizeRoomKey(formatted_room, norm, sizeof(norm));
    
    for (int i = 0; i < g_all_rooms_count; i++) {
        char k[256];
        NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
        
        if (CaseInsensitiveCompare(k, norm) == 0) return i;
        
        const char* check_k = k;
        if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
        else if (check_k[0] == '@') check_k += 1;
        else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
        else if (check_k[0] == '#') check_k += 1;
        
        const char* check_norm = norm;
        if (strncmp(check_norm, "@ ", 2) == 0) check_norm += 2;
        else if (check_norm[0] == '@') check_norm += 1;
        else if (strncmp(check_norm, "# ", 2) == 0) check_norm += 2;
        else if (check_norm[0] == '#') check_norm += 1;
        
        if (CaseInsensitiveCompare(check_k, check_norm) == 0) {
            if ((formatted_room[0] == '@' || formatted_room[0] == '#') && g_all_rooms[i][0] != '@' && g_all_rooms[i][0] != '#') {
                strncpy(g_all_rooms[i], formatted_room, sizeof(g_all_rooms[i]) - 1);
                if (save) SaveRoomList();
                RefreshLeftPane();
            }
            return i;
        }
    }
    if (g_all_rooms_count < 64) {
        strncpy(g_all_rooms[g_all_rooms_count], formatted_room, sizeof(g_all_rooms[g_all_rooms_count]) - 1);
        g_room_synced[g_all_rooms_count] = 1; 
        g_all_rooms_count++;
        if (save) SaveRoomList();
        RefreshLeftPane();
        return g_all_rooms_count - 1;
    }
    return -1;
}

void RemoveRoomFromList(const char* room) {
    if (!room) return;
    char norm[256];
    NormalizeRoomKey(room, norm, sizeof(norm));
    int found = -1;
    for (int i = 0; i < g_all_rooms_count; i++) {
        char k[256];
        NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
        
        const char* check_k = k;
        if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
        else if (check_k[0] == '@') check_k += 1;
        else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
        else if (check_k[0] == '#') check_k += 1;

        const char* check_norm = norm;
        if (strncmp(check_norm, "@ ", 2) == 0) check_norm += 2;
        else if (check_norm[0] == '@') check_norm += 1;
        else if (strncmp(check_norm, "# ", 2) == 0) check_norm += 2;
        else if (check_norm[0] == '#') check_norm += 1;

        if (CaseInsensitiveCompare(check_k, check_norm) == 0) { found = i; break; }
    }
    if (found >= 0) {
        for (int i = found; i < g_all_rooms_count - 1; i++) {
            strcpy(g_all_rooms[i], g_all_rooms[i + 1]);
            g_room_pinned[i] = g_room_pinned[i + 1];
            g_room_synced[i] = g_room_synced[i + 1];
            g_room_unread[i] = g_room_unread[i + 1];
        }
        g_all_rooms_count--;
        SaveRoomList();
        RefreshLeftPane();
    }
}

void GenerateClientMsgID(char* out_id) {
    static unsigned long long counter = 0;
    snprintf(out_id, 64, "msg_%lu_%llu", (unsigned long)time(NULL), ++counter);
}

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

BOOL IsRunAtStartupEnabled(void) {
    HKEY hKey;
    BOOL enabled = FALSE;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        DWORD type = REG_SZ, size = sizeof(path);
        if (RegQueryValueExA(hKey, "EnterpriseChatClient", NULL, &type, (BYTE*)path, &size) == ERROR_SUCCESS) {
            enabled = TRUE;
        }
        RegCloseKey(hKey);
    }
    return enabled;
}

int CaseInsensitiveCompare(const char* a, const char* b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return *a - *b;
        a++; b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

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

            HWND btnSave = CreateWindowA("BUTTON", "Save Connect", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 40, 160, 110, 30, hwnd, (HMENU)DLG_BTN_SAVE, hInst, NULL);
            HWND btnCanc = CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE, 160, 160, 100, 30, hwnd, (HMENU)DLG_BTN_CANC, hInst, NULL);
            
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
    if (!msg) return;
    char clean[512];
    // Add spaces for padding so it's not too close to the edge
    snprintf(clean, sizeof(clean), "  %s", msg);
    if (hStatusBar) SetWindowTextA(hStatusBar, clean);
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
    hConfigDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "ServerConfigClass", "Settings",
                                 WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 x, y, 300, 235, hwnd, NULL, GetModuleHandle(NULL), NULL);
}

void SendTextMessage(const char* target, const char* text) {
    if (!g_connected || g_sock == INVALID_SOCKET) {
        SetStatusMsg("Error: Not connected to chat server.");
        return;
    }
    char clean_text[4096];
    strncpy(clean_text, text, sizeof(clean_text) - 1);
    clean_text[sizeof(clean_text) - 1] = '\0';
    SanitizeClientText(clean_text);

    char msg_id[64];
    GenerateClientMsgID(msg_id);
    add_message_full(clean_text, g_username, msg_id, MSG_USER, 0);

    char stanza[8192];
    int len = snprintf(stanza, sizeof(stanza), 
        "<message to=\"%s\" id=\"%s\"><body>%s</body></message>\n", target, msg_id, clean_text);
    SendAll(g_sock, stanza, len);
}

LRESULT CALLBACK EditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        char buf[4096]; 
        GetWindowTextA(hwnd, buf, 4096);
        TrimString(buf);
        if (strlen(buf) > 0) {
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

LRESULT CALLBACK ChatSearchSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
        ExecuteNextMessageSearch(hMainWindow);
        return 0;
    }
    if (msg == WM_CHAR && wParam == VK_RETURN) return 0;
    return CallWindowProc(OldChatSearchProc, hwnd, msg, wParam, lParam);
}

void ExecuteNextMessageSearch(HWND hwnd) {
    char query[256];
    GetWindowTextA(hChatSearch, query, sizeof(query));
    if (strlen(query) == 0 || strcmp(query, "Search messages...") == 0 || msg_count <= 0) return;

    int start = (g_last_search_idx + 1) % msg_count;
    for (int step = 0; step < msg_count; step++) {
        int i = (start + step) % msg_count;
        if (StrStrIA(chat_log[i].text, query)) {
            g_last_search_idx = i;
            int doc_y = chat_log[i].hit_box.top - scroll_y;
            scroll_y = -(doc_y) + (visible_space / 2);
            if (scroll_y > 0) scroll_y = 0;
            g_strobe_idx = i;
            g_strobe_ticks = 6;
            SetTimer(hwnd, 1003, 150, NULL);
            InvalidateRect(hChatView, NULL, TRUE);
            return;
        }
    }
}

static DWORD WINAPI FileUploadThread(LPVOID lpParam) {
    UploadTask* task = (UploadTask*)lpParam;
    FILE* f = fopen(task->filepath, "rb");
    if (!f) {
        SetStatusMsg("Error: Could not open file for transfer.");
        free(task);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    const char* raw_name = strrchr(task->filepath, '\\');
    raw_name = raw_name ? raw_name + 1 : task->filepath;

    char fname[256];
    strncpy(fname, raw_name, sizeof(fname) - 1);
    fname[sizeof(fname) - 1] = '\0';
    for (char* p = fname; *p; p++) {
        if (*p == ' ') *p = '_';
    }

    int chunk_size = 4096;
    int total_chunks = (int)((fsize + chunk_size - 1) / chunk_size);
    if (total_chunks == 0) total_chunks = 1;

    SetStatusMsg("Uploading attachment in background...");

    for (int i = 0; i < total_chunks && g_connected && g_sock != INVALID_SOCKET; i++) {
        char cbuf[4096];
        int r = (int)fread(cbuf, 1, chunk_size, f);
        if (r < 0) r = 0;

        char header[512];
        int hlen = snprintf(header, sizeof(header), "FILE_CHUNK %s %s %d %d %d\n", task->target, fname, i, total_chunks, r);

        if (!g_send_cs_init) {
            InitializeCriticalSection(&g_send_cs);
            g_send_cs_init = TRUE;
        }
        EnterCriticalSection(&g_send_cs);
        int total = 0;
        while (total < hlen) {
            int s = send(g_sock, header + total, hlen - total, 0);
            if (s <= 0) break;
            total += s;
        }
        int btotal = 0;
        while (btotal < r) {
            int s = send(g_sock, cbuf + btotal, r - btotal, 0);
            if (s <= 0) break;
            btotal += s;
        }
        LeaveCriticalSection(&g_send_cs);
    }
    fclose(f);
    SetStatusMsg("Attachment upload complete.");
    free(task);
    return 0;
}

static void GetTextExtentUTF8(HDC hdc, const char* utf8, int byte_len, SIZE* sz) {
    sz->cx = 0; sz->cy = 0;
    if (!utf8 || byte_len <= 0) return;
    WCHAR wbuf[4096];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, byte_len, wbuf, 4095);
    if (wlen <= 0) wlen = MultiByteToWideChar(CP_ACP, 0, utf8, byte_len, wbuf, 4095);
    if (wlen > 0) GetTextExtentPoint32W(hdc, wbuf, wlen, sz);
}

static int GetUserPresence(const char* user) {
    for (int i = 0; i < g_presence_count; i++) {
        if (CaseInsensitiveCompare(g_presences[i].user, user) == 0) {
            return g_presences[i].state;
        }
    }
    return 0;
}

LRESULT CALLBACK LeftPaneSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_RBUTTONUP) {
        POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        DWORD item = (DWORD)SendMessage(hwnd, LB_ITEMFROMPOINT, 0, MAKELPARAM(pt.x, pt.y));
        if (HIWORD(item) == 0) {
            int lb_idx = LOWORD(item);
            SendMessage(hwnd, LB_SETCURSEL, lb_idx, 0);
            char item_text[320], norm_key[256];
            SendMessageA(hwnd, LB_GETTEXT, lb_idx, (LPARAM)item_text);
            char* bracket = strstr(item_text, " [Offline]");
            if (!bracket) bracket = strstr(item_text, " [Away]");
            if (!bracket) bracket = strstr(item_text, " [Online]");
            if (bracket) *bracket = '\0';
            
            NormalizeRoomKey(item_text, norm_key, sizeof(norm_key));

            int room_idx = -1;
            for (int i = 0; i < g_all_rooms_count; i++) {
                char k[256];
                NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
                
                const char* check_k = k;
                if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
                else if (check_k[0] == '@') check_k += 1;
                else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
                else if (check_k[0] == '#') check_k += 1;
                
                const char* check_norm = norm_key;
                if (strncmp(check_norm, "@ ", 2) == 0) check_norm += 2;
                else if (check_norm[0] == '@') check_norm += 1;
                else if (strncmp(check_norm, "# ", 2) == 0) check_norm += 2;
                else if (check_norm[0] == '#') check_norm += 1;

                if (CaseInsensitiveCompare(check_k, check_norm) == 0) { room_idx = i; break; }
            }

            if (room_idx >= 0) {
                POINT spt = pt;
                ClientToScreen(hwnd, &spt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenuA(hMenu, MF_STRING, 1, g_room_pinned[room_idx] ? "Unpin Channel" : "Pin Channel");
                AppendMenuA(hMenu, MF_STRING, 2, "Delete Channel (Mod)");
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, spt.x, spt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                if (cmd == 1) {
                    g_room_pinned[room_idx] = !g_room_pinned[room_idx];
                    SaveRoomPinState(room_idx);
                    RefreshLeftPane();
                } else if (cmd == 2) {
                    if (g_connected && g_sock != INVALID_SOCKET) {
                        char stanza[512];
                        snprintf(stanza, sizeof(stanza), "<destroy room=\"%s\"/>\n", g_all_rooms[room_idx]);
                        SendAll(g_sock, stanza, (int)strlen(stanza));
                    }
                    RemoveRoomFromList(g_all_rooms[room_idx]);
                }
            }
        }
        return 0;
    }
    return CallWindowProc(OldLeftPaneProc, hwnd, msg, wParam, lParam);
}

void RefreshLeftPane(void) {
    if (!hLeftPane) return;
    char query[256] = "";
    if (hRoomSearch) GetWindowTextA(hRoomSearch, query, sizeof(query));
    if (strcmp(query, "Search chats...") == 0) query[0] = '\0';

    SendMessage(hLeftPane, LB_RESETCONTENT, 0, 0);
    for (int i = 0; i < g_all_rooms_count; i++) {
        if (g_filter_pinned_only && !g_room_pinned[i] && strlen(query) == 0) continue;
        if (strlen(query) > 0 && !StrStrIA(g_all_rooms[i], query)) continue;

        char norm_key[256];
        NormalizeRoomKey(g_all_rooms[i], norm_key, sizeof(norm_key));

        const char* pres_tag = "";
        if (norm_key[0] == '@') {
            const char* un = norm_key + 1;
            if (*un == ' ') un++;
            int st = GetUserPresence(un);
            
            const char* target_un = g_target;
            if (strncmp(target_un, "@ ", 2) == 0) target_un += 2;
            else if (target_un[0] == '@') target_un += 1;

            if (st == 0 && !g_room_pinned[i] && CaseInsensitiveCompare(target_un, un) != 0) continue;
            
            pres_tag = (st == 0) ? " [Offline]" : (st == 2 ? " [Away]" : "");
        }

        char item_text[320];
        snprintf(item_text, sizeof(item_text), "%s%s", g_all_rooms[i], pres_tag);
        SendMessageA(hLeftPane, LB_ADDSTRING, 0, (LPARAM)item_text);
    }
}

static void SetUserPresence(const char* user, int state) {
    if (!user || user[0] == '\0') return;
    for (int i = 0; i < g_presence_count; i++) {
        if (CaseInsensitiveCompare(g_presences[i].user, user) == 0) {
            g_presences[i].state = state;
            return;
        }
    }
    if (g_presence_count < 128) {
        strncpy(g_presences[g_presence_count].user, user, 255);
        g_presences[g_presence_count].user[255] = '\0';
        g_presences[g_presence_count].state = state;
        g_presence_count++;
    }
}

static void TextOutW_UTF8(HDC hdc, int x, int y, const char* utf8, int byte_len) {
    if (!utf8 || byte_len <= 0) return;
    WCHAR wbuf[4096];
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, byte_len, wbuf, 4095);
    if (wlen <= 0) wlen = MultiByteToWideChar(CP_ACP, 0, utf8, byte_len, wbuf, 4095);
    if (wlen > 0) TextOutW(hdc, x, y, wbuf, wlen);
}

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
    add_message_full(text, "", "", msg_type, 0);
}

void add_message_full(const char* text, const char* sender, const char* msg_id, int msg_type, int status) {
    for (int i = 0; i < msg_count; i++) {
        if (msg_id[0] != '\0' && strcmp(chat_log[i].msg_id, msg_id) == 0) {
            chat_log[i].status = status;
            if (msg_type != chat_log[i].msg_type && msg_type == MSG_USER) {
                chat_log[i].msg_type = MSG_USER;
            }
            if (hMainWindow) PostMessage(hMainWindow, WM_UPDATE_CHAT, 0, 0);
            return;
        }
    }
    if (msg_count < MAX_MSGS) {
        strncpy(chat_log[msg_count].text, text, sizeof(chat_log[msg_count].text) - 1);
        chat_log[msg_count].text[sizeof(chat_log[msg_count].text) - 1] = '\0';
        strncpy(chat_log[msg_count].sender, sender, sizeof(chat_log[msg_count].sender) - 1);
        strncpy(chat_log[msg_count].msg_id, msg_id, sizeof(chat_log[msg_count].msg_id) - 1);
        chat_log[msg_count].msg_type = msg_type;
        chat_log[msg_count].status = status;
        chat_log[msg_count].timestamp = time(NULL);
        SetRect(&chat_log[msg_count].hit_box, 0, 0, 0, 0);
        SetRect(&chat_log[msg_count].text_box, 0, 0, 0, 0);
        msg_count++;
    }
    scroll_y = -999999;
    if (hMainWindow) {
        PostMessage(hMainWindow, WM_UPDATE_CHAT, 0, 0);
        if (msg_type == MSG_PEER && status < 2) {
            SetTimer(hMainWindow, 1005, 500, NULL);
        }
    }
}

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
    if (win_width < 400) win_width = 500;
    HDC hdc = GetDC(hwnd);
    HFONT hOldFont = (HFONT)SelectObject(hdc, hChatFont);
    TEXTMETRICA tm; GetTextMetricsA(hdc, &tm);
    int lh = tm.tmHeight;

    int y_cursor = 20, bubble_padding = 12, max_bubble_w = (win_width * 7) / 10;
    if (max_bubble_w < 120) max_bubble_w = 120;

    int pdf_total_height = 20;
    for (int i = 0; i < msg_count; i++) {
        int n_lines = compute_wrapped_lines(hdc, chat_log[i].text, max_bubble_w, NULL, 0);
        pdf_total_height += (n_lines * lh) + (bubble_padding * 2) + 30;
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
            if (lines[l].len > 0) GetTextExtentUTF8(hdc, chat_log[i].text + lines[l].start_idx, lines[l].len, &sz);
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
                unsigned char ch = (unsigned char)lbuf[c];
                if (ch >= 128) {
                    if ((ch & 0xC0) == 0xC0) esc[e_idx++] = '*';
                    continue;
                }
                if (ch == '(' || ch == ')' || ch == '\\') esc[e_idx++] = '\\';
                esc[e_idx++] = (char)ch;
            }
            esc[e_idx] = '\0';

            float text_y = (float)(pdf_total_height - (bRect.top + bubble_padding + l * lh + lh - 4)); 
            s_app(&s, "BT /F1 %d Tf %.2f %.2f Td (%s) Tj ET\n", 12, (float)(bRect.left + bubble_padding), text_y, esc);
        }

        char time_str[32], meta_str[128];
        format_timestamp(chat_log[i].timestamp, time_str, sizeof(time_str));
        if (chat_log[i].msg_type == MSG_USER) {
            const char* rec = (chat_log[i].status >= 2) ? "[Viewed]" : (chat_log[i].status == 1 ? "[Sent]" : "[Sending]");
            snprintf(meta_str, sizeof(meta_str), "%s %s", time_str, rec);
        } else if (strlen(chat_log[i].sender) > 0) {
            snprintf(meta_str, sizeof(meta_str), "%s - %s", chat_log[i].sender, time_str);
        } else {
            snprintf(meta_str, sizeof(meta_str), "%s", time_str);
        }
        s_app(&s, "0.5 0.5 0.55 rg BT /F1 9 Tf %.2f %.2f Td (%s) Tj ET\n",
              (float)(bRect.left + 4), pdf_y_bottom - 12.0f, meta_str);

        y_cursor += b_height + 30;
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

int SendAll(SOCKET sock, const char* buf, int len) {
    if (!g_send_cs_init) {
        InitializeCriticalSection(&g_send_cs);
        g_send_cs_init = TRUE;
    }
    EnterCriticalSection(&g_send_cs);
    int total = 0;
    while (total < len) {
        int r = send(sock, buf + total, len - total, 0);
        if (r <= 0) {
            LeaveCriticalSection(&g_send_cs);
            return -1;
        }
        total += r;
    }
    LeaveCriticalSection(&g_send_cs);
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

void SendFileTransfer(const char* target, const char* filepath) {
    if (!g_connected || g_sock == INVALID_SOCKET) {
        SetStatusMsg("Error: Not connected to chat server.");
        return;
    }
    UploadTask* task = (UploadTask*)calloc(1, sizeof(UploadTask));
    if (!task) return;
    strncpy(task->target, target, sizeof(task->target) - 1);
    strncpy(task->filepath, filepath, sizeof(task->filepath) - 1);
    HANDLE hTh = CreateThread(NULL, 0, FileUploadThread, task, 0, NULL);
    if (hTh) CloseHandle(hTh);
}

void JoinRoom(const char* room_name) {
    if (!g_connected || g_sock == INVALID_SOCKET) return;
    char stanza[512];
    int len = snprintf(stanza, sizeof(stanza), "<join room=\"%s\"/>\n", room_name);
    SendAll(g_sock, stanza, len);
    strncpy(g_target, room_name, sizeof(g_target) - 1);
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
            SetStatusMsg("  Connected");

            for (int i = 0; i < g_all_rooms_count; i++) g_room_synced[i] = 0;

            char pres[256];
            int plen = snprintf(pres, sizeof(pres), "<presence><show>1</show></presence>\n");
            SendAll(s, pres, plen);
            if (strlen(g_fullname) > 0 || strlen(g_email) > 0 || strlen(g_phone) > 0 || strlen(g_title) > 0 || strlen(g_org) > 0) {
                char vc[1024];
                int vlen = snprintf(vc, sizeof(vc), "<vcard name=\"%s\" email=\"%s\" phone=\"%s\" title=\"%s\" org=\"%s\"/>\n", g_fullname, g_email, g_phone, g_title, g_org);
                SendAll(s, vc, vlen);
            }
            JoinRoom(g_target);
        } else {
            SetStatusMsg("Authentication Failed. Check credentials.");
            closesocket(s);
            if (g_sock == s) g_sock = INVALID_SOCKET;
            goto wait_reconnect;
        }

        while (g_connected && g_sock == s && g_app_running) {
            if (ReadLine(s, buf, sizeof(buf)) < 0) break;

            if (strncmp(buf, "<message", 8) == 0 && !strstr(buf, "</message>")) {
                char temp[4096];
                while (!strstr(buf, "</message>") && ReadLine(s, temp, sizeof(temp)) >= 0) {
                    if (strlen(buf) + strlen(temp) < sizeof(buf) - 2) {
                        strcat(buf, "\n");
                        strcat(buf, temp);
                    } else break;
                }
            }

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

            if (strstr(buf, "<presence")) {
                char p_from[256] = "";
                int p_state = 1;
                char* fp = strstr(buf, "from=\"");
                if (fp) {
                    sscanf(fp, "from=\"%255[^\"]\"", p_from);
                    char* slash = strchr(p_from, '/');
                    if (slash) *slash = '\0';
                }
                char* sp = strstr(buf, "<show>");
                if (sp) {
                    sscanf(sp, "<show>%d</show>", &p_state);
                } else if (strstr(buf, "type=\"unavailable\"")) {
                    p_state = 0;
                }
                
                if (p_from[0] != '\0') {
                    SetUserPresence(p_from, p_state);
                    RefreshLeftPane();
                }
                continue;
            }

            if (strstr(buf, "<ack ")) {
                char ack_id[64] = "";
                int st = 1;
                char* ip = strstr(buf, "id=\"");
                if (ip) sscanf(ip, "id=\"%63[^\"]\"", ack_id);
                char* sp = strstr(buf, "status=\"");
                if (sp) sscanf(sp, "status=\"%d\"", &st);
                if (ack_id[0] != '\0') {
                    for (int i = 0; i < msg_count; i++) {
                        if (strcmp(chat_log[i].msg_id, ack_id) == 0) {
                            if (st > chat_log[i].status) chat_log[i].status = st;
                            PostMessage(hMainWindow, WM_UPDATE_CHAT, 0, 0);
                            break;
                        }
                    }
                }
                continue;
            }

            if (strstr(buf, "<mutate ")) {
                char m_id[64] = "", m_to[256] = "", m_body[4096] = "";
                int act = 0;
                char* ip = strstr(buf, "id=\"");
                if (ip) sscanf(ip, "id=\"%63[^\"]\"", m_id);
                char* ap = strstr(buf, "action=\"");
                if (ap) sscanf(ap, "action=\"%d\"", &act);
                char* tp = strstr(buf, "to=\"");
                if (tp) sscanf(tp, "to=\"%255[^\"]\"", m_to);
                char* bs = strstr(buf, "<body>");
                char* be = strstr(buf, "</body>");
                if (bs && be && be > bs + 6) {
                    *be = '\0';
                    strncpy(m_body, bs + 6, sizeof(m_body) - 1);
                }

                for (int i = 0; i < msg_count; i++) {
                    if (strcmp(chat_log[i].msg_id, m_id) == 0) {
                        if (act == 3) {
                            for (int j = i; j < msg_count - 1; j++) chat_log[j] = chat_log[j + 1];
                            msg_count--;
                        } else if (act == 1 || act == 4) {
                            strncpy(chat_log[i].text, m_body, sizeof(chat_log[i].text) - 1);
                        }
                        PostMessage(hMainWindow, WM_UPDATE_CHAT, 0, 0);
                        break;
                    }
                }
                continue;
            }

            if (strstr(buf, "<message")) {
                char header[2048] = "";
                char* start = strstr(buf, "<body>");
                if (start) {
                    int hlen = start - buf;
                    if (hlen >= sizeof(header)) hlen = sizeof(header) - 1;
                    strncpy(header, buf, hlen);
                    header[hlen] = '\0';
                } else {
                    strncpy(header, buf, sizeof(header) - 1);
                }

                char from[256] = "Peer", to[256] = "", id[64] = "", room_attr[256] = "", body[8192] = "";
                int msg_status = 1;
                
                char* from_ptr = strstr(header, "from=\"");
                if (from_ptr) {
                    sscanf(from_ptr, "from=\"%255[^\"]\"", from);
                    char* slash = strchr(from, '/');
                    if (slash) *slash = '\0';
                }
                char* to_ptr = strstr(header, "to=\"");
                if (to_ptr) {
                    sscanf(to_ptr, "to=\"%255[^\"]\"", to);
                    char* slash = strchr(to, '/');
                    if (slash) *slash = '\0';
                }
                char* id_ptr = strstr(header, "id=\"");
                if (id_ptr) sscanf(id_ptr, "id=\"%63[^\"]\"", id);
                char* r_ptr = strstr(header, "room=\"");
                if (r_ptr) sscanf(r_ptr, "room=\"%255[^\"]\"", room_attr);
                char* st_ptr = strstr(header, "status=\"");
                if (st_ptr) sscanf(st_ptr, "status=\"%d\"", &msg_status);

                char* end = strstr(buf, "</body>");
                if (start && end && end > start + 6) {
                    *end = '\0';
                    strncpy(body, start + 6, sizeof(body) - 1);
                }

                if (strcmp(id, "verify_users_res") == 0) {
                    if (strlen(body) == 0) {
                        MessageBoxA(hMainWindow, "None of the specified users exist on the server.", "Not Found", MB_OK);
                    } else {
                        char tmp_body[4096];
                        strncpy(tmp_body, body, sizeof(tmp_body) - 1);
                        tmp_body[sizeof(tmp_body) - 1] = '\0';

                        char* token = strtok(tmp_body, ",");
                        BOOL joined_any = FALSE;
                        while (token) {
                            TrimString(token);
                            if (strlen(token) > 0) {
                                char dm_label[260];
                                snprintf(dm_label, sizeof(dm_label), "@ %s", token);
                                int idx = EnsureRoomInList(dm_label, TRUE);
                                if (idx >= 0) {
                                    g_room_synced[idx] = 1;
                                    g_room_unread[idx] = 0;
                                }
                                strncpy(g_target, token, sizeof(g_target) - 1);
                                g_target[sizeof(g_target) - 1] = '\0';
                                joined_any = TRUE;
                            }
                            token = strtok(NULL, ",");
                        }
                        if (joined_any) {
                            msg_count = 0;
                            ClearRoomUnread(g_target);
                            RefreshLeftPane();
                            InvalidateRect(hChatView, NULL, TRUE);
                            JoinRoom(g_target);
                        }
                    }
                    continue;
                }
                
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

                if (strcmp(id, "room_sync") == 0 && room_attr[0] != '\0') {
                    char r_label[260];
                    if (room_attr[0] == '@' || room_attr[0] == '#') {
                        strncpy(r_label, room_attr, sizeof(r_label) - 1);
                    } else if (strstr(body, "Synced DM")) {
                        snprintf(r_label, sizeof(r_label), "@ %s", room_attr);
                    } else {
                        snprintf(r_label, sizeof(r_label), "#%s", room_attr);
                    }
                    r_label[sizeof(r_label) - 1] = '\0';
                    
                    int idx = EnsureRoomInList(r_label, TRUE);
                    if (idx >= 0) g_room_synced[idx] = 1;
                    continue;
                }

                if (strcmp(id, "room_sync_complete") == 0) {
                    for (int i = g_all_rooms_count - 1; i >= 0; i--) {
                        if (g_room_synced[i] == 0) {
                            char norm_target[256];
                            NormalizeRoomKey(g_target, norm_target, sizeof(norm_target));
                            char k[256];
                            NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
                            
                            const char* check_k = k;
                            if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
                            else if (check_k[0] == '@') check_k += 1;
                            else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
                            else if (check_k[0] == '#') check_k += 1;

                            const char* check_t = norm_target;
                            if (strncmp(check_t, "@ ", 2) == 0) check_t += 2;
                            else if (check_t[0] == '@') check_t += 1;
                            else if (strncmp(check_t, "# ", 2) == 0) check_t += 2;
                            else if (check_t[0] == '#') check_t += 1;

                            if (CaseInsensitiveCompare(check_k, check_t) == 0) {
                                strcpy(g_target, "#general");
                                msg_count = 0;
                            }
                            RemoveRoomFromList(g_all_rooms[i]);
                        }
                    }
                    int gen_idx = EnsureRoomInList("#general", TRUE);
                    if (gen_idx >= 0) g_room_synced[gen_idx] = 1;
                    
                    RefreshLeftPane();
                    continue;
                }

                if (strcmp(id, "kick_notify") == 0) {
                    if (room_attr[0] != '\0') {
                        char r_label[260];
                        if (room_attr[0] == '@' || room_attr[0] == '#') {
                            strncpy(r_label, room_attr, sizeof(r_label) - 1);
                        } else {
                            snprintf(r_label, sizeof(r_label), "#%s", room_attr);
                        }
                        r_label[sizeof(r_label) - 1] = '\0';
                        RemoveRoomFromList(r_label);
                        if (CaseInsensitiveCompare(g_target, r_label) == 0) {
                            strcpy(g_target, "#general");
                            msg_count = 0;
                            JoinRoom(g_target);
                        }
                    }
                    SetStatusMsg(body);
                    continue;
                }

                if (strcmp(id, "invite_notify") == 0 || (CaseInsensitiveCompare(from, "Server") == 0 && strstr(body, "You have been added to "))) {
                    char invited_room[256] = {0};
                    if (room_attr[0] != '\0') strncpy(invited_room, room_attr, 255);
                    else sscanf(body, "You have been added to %255s by", invited_room);

                    if (invited_room[0] != '\0') {
                        char r_label[260];
                        if (invited_room[0] == '@' || invited_room[0] == '#') {
                            strncpy(r_label, invited_room, sizeof(r_label) - 1);
                        } else {
                            snprintf(r_label, sizeof(r_label), "#%s", invited_room);
                        }
                        r_label[sizeof(r_label) - 1] = '\0';
                        EnsureRoomInList(r_label, TRUE);
                        SetStatusMsg(body);
                        if (msg_status < 2) {
                            static DWORD last_inv_snd = 0;
                            DWORD now = GetTickCount();
                            if (now - last_inv_snd > 1500) {
                                if (g_enable_sound) PlaySoundA("SystemAsterisk", NULL, SND_ALIAS | SND_ASYNC);
                                last_inv_snd = now;
                            }
                            if (g_enable_popup) {
                                ShowWindow(hMainWindow, SW_RESTORE);
                                SetForegroundWindow(hMainWindow);
                            }
                        }
                    }
                    continue;
                }

                if (CaseInsensitiveCompare(from, "Server") == 0 && (strstr(body, "vCard") || strstr(body, "vcard"))) {
                    continue; 
                }

                if (body[0] == '\0') continue;

                int is_me = (CaseInsensitiveCompare(from, g_username) == 0);
                int is_to_me = (CaseInsensitiveCompare(to, g_username) == 0);

                if (to[0] != '\0' && to[0] != '#' && room_attr[0] == '\0' && CaseInsensitiveCompare(from, "Server") != 0) {
                    if (!is_me && !is_to_me) continue;
                }

                int bubble_type = is_me ? MSG_USER : MSG_PEER;
                if (CaseInsensitiveCompare(from, "Server") == 0) bubble_type = MSG_SYS_OK;

                if (!is_me && to[0] != '#' && CaseInsensitiveCompare(from, "Server") != 0) {
                    char dm_label[260];
                    snprintf(dm_label, sizeof(dm_label), "@ %s", from);
                    EnsureRoomInList(dm_label, TRUE);
                }

                if (!is_me && msg_status < 2) {
                    static DWORD last_msg_snd = 0;
                    DWORD now = GetTickCount();
                    if (now - last_msg_snd > 1000) {
                        if (g_enable_sound) PlaySoundA("SystemAsterisk", NULL, SND_ALIAS | SND_ASYNC);
                        last_msg_snd = now;
                    }
                    if (g_enable_popup) {
                        ShowWindow(hMainWindow, SW_RESTORE);
                        SetForegroundWindow(hMainWindow);
                    }
                }
                
                BOOL show_it = FALSE;
                if (CaseInsensitiveCompare(from, "Server") == 0 && CaseInsensitiveCompare(to, g_username) == 0) {
                    show_it = TRUE;
                } else if (g_target[0] == '#') {
                    if (CaseInsensitiveCompare(to, g_target) == 0) show_it = TRUE;
                } else {
                    if (is_me && CaseInsensitiveCompare(to, g_target) == 0) show_it = TRUE;
                    else if (!is_me && CaseInsensitiveCompare(from, g_target) == 0) show_it = TRUE;
                }
                
                if (show_it) {
                    add_message_full(body, from, id, bubble_type, msg_status);
                    scroll_y = -999999;
                    if (!is_me) {
                        g_strobe_idx = msg_count - 1;
                        g_strobe_ticks = 6;
                        if (hMainWindow) SetTimer(hMainWindow, 1003, 150, NULL);
                    }
                    InvalidateRect(hChatView, NULL, TRUE);
                } else if (!is_me) {
                    char status_note[512];
                    snprintf(status_note, sizeof(status_note), "  New message from %s (%s) [Click here to open]", from, (to[0] == '#') ? to : "Direct Message");
                    SetStatusMsg(status_note);
                    
                    strncpy(g_last_notif_room, (to[0] == '#') ? to : from, sizeof(g_last_notif_room) - 1);
                    g_last_notif_room[sizeof(g_last_notif_room) - 1] = '\0';
                    
                    char r_label[260];
                    if (to[0] == '#') snprintf(r_label, sizeof(r_label), "%s", to);
                    else snprintf(r_label, sizeof(r_label), "@ %s", from);
                    
                    int r_idx = EnsureRoomInList(r_label, TRUE);
                    if (r_idx >= 0) g_room_unread[r_idx] = 1;
                    RefreshLeftPane();
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

static LRESULT CALLBACK VCardDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HINSTANCE hInst = GetModuleHandle(NULL);
            HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
            
            HWND lbl1 = CreateWindowA("STATIC", "Full Name:", WS_CHILD | WS_VISIBLE, 15, 18, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edName = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_fullname, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 15, 180, 24, hwnd, (HMENU)5001, hInst, NULL);
            
            HWND lbl2 = CreateWindowA("STATIC", "Email:", WS_CHILD | WS_VISIBLE, 15, 53, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edEmail = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_email, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 50, 180, 24, hwnd, (HMENU)5002, hInst, NULL);
            
            HWND lbl3 = CreateWindowA("STATIC", "Phone:", WS_CHILD | WS_VISIBLE, 15, 88, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edPhone = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_phone, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 85, 180, 24, hwnd, (HMENU)5005, hInst, NULL);
            
            HWND lbl4 = CreateWindowA("STATIC", "Title:", WS_CHILD | WS_VISIBLE, 15, 123, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edTitle = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_title, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 120, 180, 24, hwnd, (HMENU)5006, hInst, NULL);
            
            HWND lbl5 = CreateWindowA("STATIC", "Org:", WS_CHILD | WS_VISIBLE, 15, 158, 90, 20, hwnd, NULL, hInst, NULL);
            HWND edOrg = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_org, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 155, 180, 24, hwnd, (HMENU)5007, hInst, NULL);

            HWND btnSave = CreateWindowA("BUTTON", "Save", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 60, 195, 80, 30, hwnd, (HMENU)5003, hInst, NULL);
            HWND btnCanc = CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE, 150, 195, 80, 30, hwnd, (HMENU)5004, hInst, NULL);
            
            HWND ctrls[] = {lbl1, edName, lbl2, edEmail, lbl3, edPhone, lbl4, edTitle, lbl5, edOrg, btnSave, btnCanc};
            for (int i = 0; i < 12; i++) SendMessage(ctrls[i], WM_SETFONT, (WPARAM)hFont, TRUE);
            return 0;
        }
        case WM_COMMAND: {
            if (LOWORD(wParam) == 5003) {
                GetDlgItemTextA(hwnd, 5001, g_fullname, sizeof(g_fullname));
                GetDlgItemTextA(hwnd, 5002, g_email, sizeof(g_email));
                GetDlgItemTextA(hwnd, 5005, g_phone, sizeof(g_phone));
                GetDlgItemTextA(hwnd, 5006, g_title, sizeof(g_title));
                GetDlgItemTextA(hwnd, 5007, g_org, sizeof(g_org));

                WritePrivateProfileStringA("Profile", "FullName", g_fullname, ini_path);
                WritePrivateProfileStringA("Profile", "Email", g_email, ini_path);
                WritePrivateProfileStringA("Profile", "Phone", g_phone, ini_path);
                WritePrivateProfileStringA("Profile", "Title", g_title, ini_path);
                WritePrivateProfileStringA("Profile", "Org", g_org, ini_path);
                
                if (g_connected && g_sock != INVALID_SOCKET) {
                    char vc[1024];
                    int vlen = snprintf(vc, sizeof(vc), "<vcard name=\"%s\" email=\"%s\" phone=\"%s\" title=\"%s\" org=\"%s\"/>\n", g_fullname, g_email, g_phone, g_title, g_org);
                    SendAll(g_sock, vc, vlen);
                }
                DestroyWindow(hwnd);
            } else if (LOWORD(wParam) == 5004) {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        case WM_DESTROY:
            EnableWindow(hMainWindow, TRUE);
            SetForegroundWindow(hMainWindow);
            hVCardDlg = NULL;
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Setup boilerplate left identical
            GetModuleFileNameA(NULL, ini_path, MAX_PATH);
            char *ls = strrchr(ini_path, '\\');
            if (ls) *(ls + 1) = '\0';
            strcat(ini_path, "chatclient.ini");

            GetPrivateProfileStringA("Server", "IP", "127.0.0.1", g_server_ip, sizeof(g_server_ip), ini_path);
            g_server_port = GetPrivateProfileIntA("Server", "Port", 5222, ini_path);
            GetPrivateProfileStringA("Server", "User", "admin", g_username, sizeof(g_username), ini_path);
            GetPrivateProfileStringA("Server", "Pass", "password", g_password, sizeof(g_password), ini_path);
            
            GetPrivateProfileStringA("Profile", "FullName", "", g_fullname, sizeof(g_fullname), ini_path);
            GetPrivateProfileStringA("Profile", "Email", "", g_email, sizeof(g_email), ini_path);
            GetPrivateProfileStringA("Profile", "Phone", "", g_phone, sizeof(g_phone), ini_path);
            GetPrivateProfileStringA("Profile", "Title", "", g_title, sizeof(g_title), ini_path);
            GetPrivateProfileStringA("Profile", "Org", "", g_org, sizeof(g_org), ini_path);
            
            g_reconnect_s = GetPrivateProfileIntA("Server", "Reconnect", 10, ini_path);
            color_user = GetPrivateProfileIntA("Colors", "User", RGB(210, 230, 255), ini_path);
            color_peer = GetPrivateProfileIntA("Colors", "Peer", RGB(240, 240, 245), ini_path);
            
            LoadRoomList();
            LoadPinnedSettings();

            g_hReconnectEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

            HMENU hMenuBar = CreateMenu();
            HMENU hConnMenu = CreatePopupMenu();
            AppendMenuA(hConnMenu, MF_STRING, IDM_SERVER_CONFIG, "Settings");
            AppendMenuA(hConnMenu, MF_STRING, IDM_SEARCH_USERS, "Search Directory...");
            AppendMenuA(hConnMenu, MF_STRING, IDM_EDIT_VCARD, "Edit Profile (vCard)...");
            AppendMenuA(hConnMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(hConnMenu, MF_STRING, IDM_SAVE_PDF, "Export Chat to PDF");

            HMENU hActionMenu = CreatePopupMenu();
            AppendMenuA(hActionMenu, MF_STRING, IDM_NEW_CHAT, "Create New Chat Room (Moderators)...");
            AppendMenuA(hActionMenu, MF_STRING, IDM_NEW_DM, "Open Direct Chat...");
            AppendMenuA(hActionMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(hActionMenu, MF_STRING, IDM_ADD_USER, "Add User to Current Chat...");
            AppendMenuA(hActionMenu, MF_STRING, IDM_KICK_USER, "Remove User from Current Chat...");
            AppendMenuA(hActionMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuA(hActionMenu, MF_STRING, IDM_TOGGLE_PIN_CUR, "Pin / Unpin Current Chat");
            AppendMenuA(hActionMenu, MF_STRING, 2022, "Delete Current Channel");

            AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hConnMenu, "Connection");
            AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hActionMenu, "Actions");
            SetMenu(hwnd, hMenuBar);

            DragAcceptFiles(hwnd, TRUE);
            hChatFont = CreateFontW(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                                    DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

            hRoomSearch = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "Search chats...", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 150, 25, hwnd, (HMENU)ID_ROOM_SEARCH, GetModuleHandle(NULL), NULL);
            hPinFilterChk = CreateWindowEx(0, "BUTTON", "Pinned Only", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, 25, 150, 22, hwnd, (HMENU)ID_CHK_PINNED, GetModuleHandle(NULL), NULL);
            SendMessage(hPinFilterChk, BM_SETCHECK, g_filter_pinned_only ? BST_CHECKED : BST_UNCHECKED, 0);

            hChatSearch = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "Search messages...", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 150, 0, 350, 25, hwnd, (HMENU)ID_CHAT_SEARCH, GetModuleHandle(NULL), NULL);
            OldChatSearchProc = (WNDPROC)SetWindowLongPtr(hChatSearch, GWLP_WNDPROC, (LONG_PTR)ChatSearchSubclassProc);

            hStatusBar = CreateWindowEx(0, "STATIC", "  Ready", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOTIFY, 0, 0, 0, 0, hwnd, (HMENU)ID_STATUS_BAR, GetModuleHandle(NULL), NULL);
            
            SendMessage(hRoomSearch, WM_SETFONT, (WPARAM)hChatFont, TRUE);
            SendMessage(hPinFilterChk, WM_SETFONT, (WPARAM)hChatFont, TRUE);
            SendMessage(hChatSearch, WM_SETFONT, (WPARAM)hChatFont, TRUE);

            hLeftPane = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", "", 
                                       WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS,
                                       0, 47, 150, 503, hwnd, (HMENU)ID_LEFT_PANE, GetModuleHandle(NULL), NULL);
            SendMessage(hLeftPane, WM_SETFONT, (WPARAM)hChatFont, TRUE);
            OldLeftPaneProc = (WNDPROC)SetWindowLongPtr(hLeftPane, GWLP_WNDPROC, (LONG_PTR)LeftPaneSubclassProc);
            
            RefreshLeftPane();
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
        case WM_MEASUREITEM: {
            MEASUREITEMSTRUCT* mis = (MEASUREITEMSTRUCT*)lParam;
            if (mis && mis->CtlID == ID_LEFT_PANE) mis->itemHeight = 22;
            return TRUE;
        }
        case WM_DRAWITEM: {
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            if (dis && dis->CtlID == ID_LEFT_PANE && dis->itemID != (UINT)-1) {
                char item_text[320] = "";
                SendMessageA(dis->hwndItem, LB_GETTEXT, dis->itemID, (LPARAM)item_text);

                int is_selected = (dis->itemState & ODS_SELECTED);
                
                char clean_text[320];
                strncpy(clean_text, item_text, sizeof(clean_text) - 1);
                clean_text[sizeof(clean_text) - 1] = '\0';
                char* bracket = strstr(clean_text, " [Offline]");
                if (!bracket) bracket = strstr(clean_text, " [Away]");
                if (!bracket) bracket = strstr(clean_text, " [Online]");
                if (bracket) *bracket = '\0';

                char norm_item[256], norm_target[256];
                NormalizeRoomKey(clean_text, norm_item, sizeof(norm_item));
                NormalizeRoomKey(g_target, norm_target, sizeof(norm_target));

                const char* check_item = norm_item;
                if (strncmp(check_item, "@ ", 2) == 0) check_item += 2;
                else if (check_item[0] == '@') check_item += 1;
                else if (strncmp(check_item, "# ", 2) == 0) check_item += 2;
                else if (check_item[0] == '#') check_item += 1;

                const char* check_target = norm_target;
                if (strncmp(check_target, "@ ", 2) == 0) check_target += 2;
                else if (check_target[0] == '@') check_target += 1;
                else if (strncmp(check_target, "# ", 2) == 0) check_target += 2;
                else if (check_target[0] == '#') check_target += 1;

                int is_current = (CaseInsensitiveCompare(check_item, check_target) == 0);

                int is_pinned = 0;
                int is_unread = 0;
                for (int i = 0; i < g_all_rooms_count; i++) {
                    char k[256];
                    NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
                    
                    const char* check_k = k;
                    if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
                    else if (check_k[0] == '@') check_k += 1;
                    else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
                    else if (check_k[0] == '#') check_k += 1;

                    if (CaseInsensitiveCompare(check_k, check_item) == 0) {
                        if (g_room_pinned[i]) is_pinned = 1;
                        if (g_room_unread[i]) is_unread = 1;
                        break;
                    }
                }

                HBRUSH bg = CreateSolidBrush(is_selected ? RGB(0, 120, 215) : (is_current ? RGB(230, 240, 255) : RGB(255, 255, 255)));
                FillRect(dis->hDC, &dis->rcItem, bg);
                DeleteObject(bg);

                SetBkMode(dis->hDC, TRANSPARENT);
                SetTextColor(dis->hDC, is_selected ? RGB(255, 255, 255) : RGB(0, 0, 0));

                HFONT hFontItem = CreateFontA(16, 0, 0, 0, (is_pinned || is_current || is_unread) ? FW_BOLD : FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, "Segoe UI");
                HGDIOBJ oldFont = SelectObject(dis->hDC, hFontItem);

                RECT rc = dis->rcItem;
                rc.left += 6;
                DrawTextA(dis->hDC, item_text, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

                SelectObject(dis->hDC, oldFont);
                DeleteObject(hFontItem);
                return TRUE;
            }
            break;
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
                RefreshLeftPane();
            } 
            else if (wParam == 1002) {
                KillTimer(hwnd, 1002);
                g_last_search_idx = -1;
                ExecuteNextMessageSearch(hwnd);
            }
            else if (wParam == 1003) {
                g_strobe_ticks--;
                InvalidateRect(hChatView, NULL, TRUE);
                if (g_strobe_ticks <= 0) {
                    g_strobe_idx = -1;
                    KillTimer(hwnd, 1003);
                }
            }
            else if (wParam == 1005) {
                BOOL has_unviewed = FALSE;
                for (int i = 0; i < msg_count; i++) {
                    if (chat_log[i].msg_type == MSG_PEER && chat_log[i].status < 2) {
                        has_unviewed = TRUE; break;
                    }
                }
                if (has_unviewed) InvalidateRect(hChatView, NULL, FALSE);
                else KillTimer(hwnd, 1005);
            }
            return 0;
        }
        case WM_COMMAND: {
            WORD wmId = LOWORD(wParam);
            WORD wmEvent = HIWORD(wParam);

            if (wmId == ID_CHK_PINNED && wmEvent == BN_CLICKED) {
                g_filter_pinned_only = (SendMessage(hPinFilterChk, BM_GETCHECK, 0, 0) == BST_CHECKED);
                WritePrivateProfileStringA("Settings", "FilterPinnedOnly", g_filter_pinned_only ? "1" : "0", ini_path);
                RefreshLeftPane();
                return 0;
            }
            
            else if (wmId == ID_STATUS_BAR && wmEvent == STN_CLICKED) {
                if (g_last_notif_room[0] != '\0') {
                    if (g_last_notif_room[0] != '#') {
                        char dm_label[260];
                        snprintf(dm_label, sizeof(dm_label), "@ %s", g_last_notif_room);
                        EnsureRoomInList(dm_label, TRUE);
                    } else {
                        EnsureRoomInList(g_last_notif_room, TRUE);
                    }
                    strncpy(g_target, g_last_notif_room, sizeof(g_target) - 1);
                    g_target[sizeof(g_target) - 1] = '\0';
                    msg_count = 0;
                    ClearRoomUnread(g_target);
                    RefreshLeftPane();
                    InvalidateRect(hChatView, NULL, TRUE);
                    JoinRoom(g_target);
                    g_last_notif_room[0] = '\0';
                    SetStatusMsg("  Ready");
                }
            }

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
                    char raw_item[320];
                    SendMessageA(hLeftPane, LB_GETTEXT, idx, (LPARAM)raw_item);
                    char* bracket = strstr(raw_item, " [Offline]");
                    if (!bracket) bracket = strstr(raw_item, " [Away]");
                    if (!bracket) bracket = strstr(raw_item, " [Online]");
                    if (bracket) *bracket = '\0';

                    const char* p = raw_item;
                    if (p[0] == '#') {
                        if (strncmp(p, "# ", 2) == 0) p += 2;
                        else p += 1;
                        snprintf(g_target, sizeof(g_target), "#%s", p);
                    } else if (strncmp(p, "@ ", 2) == 0) {
                        strncpy(g_target, p + 2, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                    } else if (p[0] == '@') {
                        strncpy(g_target, p + 1, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                    } else {
                        strncpy(g_target, p, sizeof(g_target) - 1);
                        g_target[sizeof(g_target) - 1] = '\0';
                    }
                    
                    msg_count = 0; 
                    ClearRoomUnread(g_target);
                    RefreshLeftPane();
                    InvalidateRect(hChatView, NULL, TRUE);
                    JoinRoom(g_target);
                }
            } 
            else if (wmId == IDM_SERVER_CONFIG) {
                ShowServerConfigDialog(hwnd);
            }
            else if (wmId == IDM_SAVE_PDF) {
                save_chat_to_pdf(hwnd);
            }
            else if (wmId == IDM_EDIT_VCARD) {
                ShowVCardDialog(hwnd);
            }
            else if (wmId == IDM_TOGGLE_PIN_CUR) {
                char cur_key[256];
                NormalizeRoomKey(g_target, cur_key, sizeof(cur_key));
                for (int i = 0; i < g_all_rooms_count; i++) {
                    char k[256];
                    NormalizeRoomKey(g_all_rooms[i], k, sizeof(k));
                    
                    const char* check_k = k;
                    if (strncmp(check_k, "@ ", 2) == 0) check_k += 2;
                    else if (check_k[0] == '@') check_k += 1;
                    else if (strncmp(check_k, "# ", 2) == 0) check_k += 2;
                    else if (check_k[0] == '#') check_k += 1;

                    const char* check_cur = cur_key;
                    if (strncmp(check_cur, "@ ", 2) == 0) check_cur += 2;
                    else if (check_cur[0] == '@') check_cur += 1;
                    else if (strncmp(check_cur, "# ", 2) == 0) check_cur += 2;
                    else if (check_cur[0] == '#') check_cur += 1;

                    if (CaseInsensitiveCompare(check_k, check_cur) == 0) {
                        g_room_pinned[i] = !g_room_pinned[i];
                        SaveRoomPinState(i);
                        RefreshLeftPane();
                        break;
                    }
                }
            }
            else if (wmId == 2022) { 
                if (g_target[0] == '#') {
                    if (g_connected && g_sock != INVALID_SOCKET) {
                        char stanza[512];
                        snprintf(stanza, sizeof(stanza), "<destroy room=\"%s\"/>\n", g_target);
                        SendAll(g_sock, stanza, (int)strlen(stanza));
                    }
                    RemoveRoomFromList(g_target);
                    strcpy(g_target, "#general");
                    msg_count = 0;
                    JoinRoom(g_target);
                    RefreshLeftPane();
                } else {
                    RemoveRoomFromList(g_target);
                    strcpy(g_target, "#general");
                    msg_count = 0;
                    JoinRoom(g_target);
                    RefreshLeftPane();
                }
            }
            else if (wmId == IDM_NEW_CHAT) {
                char room_input[1024] = "";
                if (ShowInputDialog(hwnd, "Create New Chat Room(s)", "Enter room name(s) separated by commas (e.g. #sales, #marketing):", room_input, sizeof(room_input))) {
                    char* token = strtok(room_input, ",");
                    while (token) {
                        TrimString(token);
                        if (strlen(token) > 0) {
                            char target[256];
                            if (token[0] != '#') snprintf(target, sizeof(target), "#%s", token);
                            else strncpy(target, token, sizeof(target) - 1);
                            EnsureRoomInList(target, TRUE);
                        }
                        token = strtok(NULL, ",");
                    }
                    RefreshLeftPane();
                }
            }
            else if (wmId == IDM_NEW_DM) {
                char peer_input[1024] = "";
                if (ShowInputDialog(hwnd, "Open Direct Chat(s)", "Enter username(s) separated by commas:", peer_input, sizeof(peer_input))) {
                    TrimString(peer_input);
                    if (strlen(peer_input) > 0) {
                        if (g_connected && g_sock != INVALID_SOCKET) {
                            char stanza[8192];
                            int len = snprintf(stanza, sizeof(stanza), "<message to=\"Server\" id=\"verify_users\"><body>%s</body></message>\n", peer_input);
                            SendAll(g_sock, stanza, len);
                        } else {
                            MessageBoxA(hwnd, "Must be connected to server to verify and create direct chats.", "Error", MB_ICONWARNING | MB_OK);
                        }
                    }
                }
            }
            else if (wmId == IDM_ADD_USER) {
                if (g_target[0] != '#') {
                    MessageBoxA(hwnd, "You can only invite users to a group chat room.", "Error", MB_ICONWARNING | MB_OK);
                } else {
                    char users_input[1024] = "";
                    if (ShowInputDialog(hwnd, "Add User(s) to Chat", "Enter username(s) separated by commas:", users_input, sizeof(users_input))) {
                        char* token = strtok(users_input, ",");
                        while (token) {
                            TrimString(token);
                            if (strlen(token) > 0 && g_connected && g_sock != INVALID_SOCKET) {
                                char stanza[512];
                                int len = snprintf(stanza, sizeof(stanza), "<invite to=\"%s\" room=\"%s\"/>\n", token, g_target);
                                SendAll(g_sock, stanza, len);
                            }
                            token = strtok(NULL, ",");
                        }
                    }
                }
            }
            else if (wmId == IDM_KICK_USER) {
                if (g_target[0] != '#') {
                    MessageBoxA(hwnd, "You can only remove users from a group chat room.", "Error", MB_ICONWARNING | MB_OK);
                } else {
                    char target_user[256] = "";
                    if (ShowInputDialog(hwnd, "Remove User from Chat", "Enter username to remove:", target_user, sizeof(target_user))) {
                        TrimString(target_user);
                        if (strlen(target_user) > 0 && g_connected && g_sock != INVALID_SOCKET) {
                            char stanza[512];
                            int len = snprintf(stanza, sizeof(stanza), "<kick to=\"%s\" room=\"%s\"/>\n", target_user, g_target);
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
            int bar_h = 40, sb_h = 25, search_h = 25, pin_h = 22;
            int chat_h = (height > bar_h + sb_h) ? (height - bar_h - sb_h) : 0;

            MoveWindow(hStatusBar, 0, height - sb_h, width, sb_h, TRUE);
            MoveWindow(hRoomSearch, 0, 0, 150, search_h, TRUE);
            MoveWindow(hPinFilterChk, 4, search_h, 146, pin_h, TRUE);
            MoveWindow(hLeftPane, 0, search_h + pin_h, 150, chat_h - search_h - pin_h + bar_h, TRUE);
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
    wc.hbrBackground = CreateSolidBrush(RGB(250, 250, 245)); // Off-white app background
    RegisterClass(&wc);

    hMainWindow = CreateWindowEx(0, CLASS_NAME, "Enterprise Chat Client",
                                 WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 650, 650,
                                 NULL, NULL, hInstance, NULL);
    if (hMainWindow == NULL) return 0;
    ShowWindow(hMainWindow, nCmdShow);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(hInputDlg, &msg) && !IsDialogMessage(hConfigDlg, &msg) && !IsDialogMessage(hSearchDlg, &msg) && !IsDialogMessage(hVCardDlg, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return (int)msg.wParam;
}
