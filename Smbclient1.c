/*
 * Public Domain Software - NO WARRANTY WHATSOEVER
 * 
 * THIS CODE IS RELEASED INTO THE PUBLIC DOMAIN BY THE AUTHOR.
 * TO THE EXTENT PERMITTED BY LAW, ALL EXPRESS OR IMPLIED WARRANTIES
 * ARE DISCLAIMED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND
 * NON-INFRINGEMENT.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY USE IS AT YOUR OWN RISK.
 * THE AUTHOR SHALL NOT BE LIABLE FOR ANY DAMAGES ARISING FROM USE
 * OR INABILITY TO USE THIS SOFTWARE, INCLUDING WITHOUT LIMITATION
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES.
 * 
 * COMPILATION INSTRUCTIONS:
 * ========================
 * 
 * Windows/MinGW:
 *   gcc -o samba_client.exe Smbclient1.c -lsmbclient -luser32 -lgdi32 -mwindows
 * 
 * Requires:
 *   - Samba development libraries installed (libsmbclient-dev)
 *   - MinGW-w64 or equivalent GCC toolchain
 *   - Windows SDK headers for Win32 API
 * 
 * Unix (if cross-compiling):
 *   gcc -o samba_client smb_gui.c $(pkg-config --cflags --libs samba) -lpthread
 * 
 * WARNING: This code demonstrates the architecture only. Production
 * deployment requires proper error handling, security reviews, and
 * integration testing with your target SMB servers.
 * 
 * Date: 2026
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <smbclient.h>

#define WM_USER_REFRESH  (WM_USER + 1)
#define WM_USER_CONNECT  (WM_USER + 2)
#define WM_USER_DOWNLOAD (WM_USER + 3)
#define WM_USER_UPLOAD   (WM_USER + 4)

#define ID_LIST_REMOTE 1001
#define ID_LIST_LOCAL  1002
#define ID_EDIT_URL    1003
#define ID_BUTTON_CONN 1004
#define ID_BUTTON_UP   1005
#define ID_BUTTON_DOWN 1006
#define ID_BUTTON_REFRESH 1007
#define ID_STATUSBAR   1008

#define PANEL_WIDTH_PCT 50
#define MAX_PATH_LEN 4096
#define MAX_ITEMS 200

typedef struct {
    char path[MAX_PATH_LEN];
    int is_dir;
} DirectoryItem;

typedef struct {
    HWND hRemoteList;
    HWND hLocalList;
    HWND hStatus;
    char remote_base[MAX_PATH_LEN];
    char local_base[MAX_PATH_LEN];
    struct cli_state *conn;
    DirectoryItem remote_items[MAX_ITEMS];
    DirectoryItem local_items[MAX_ITEMS];
    int remote_count;
    int local_count;
    int selected_remote_idx;
    int selected_local_idx;
} AppContext;

static AppContext g_app;
static HINSTANCE g_hInst;
static int g_current_font;

static void auth_callback(const char *domain, const char *username,
                          char *password, int maxlen, int flags) {
    strncpy(password, "", maxlen - 1);
    password[maxlen - 1] = '\0';
}

static int load_remote_files(void) {
    char url[MAX_PATH_LEN];
    snprintf(url, sizeof(url), "%s/", g_app.remote_base);
    
    g_app.remote_count = 0;
    SMBCDIR *dir = smbc_opendir(url);
    if (!dir) {
        SetWindowTextA(g_app.hStatus, "Failed to open remote directory");
        return 0;
    }
    
    struct smbc_dirent *ent;
    while ((ent = smbc_readdir(dir)) != NULL && g_app.remote_count < MAX_ITEMS) {
        if (strcmp(ent->name, ".") == 0 || strcmp(ent->name, "..") == 0) continue;
        
        strncpy(g_app.remote_items[g_app.remote_count].path, ent->name, MAX_PATH_LEN - 1);
        g_app.remote_items[g_app.remote_count].is_dir = (ent->smbc_type == SMBC_DIR);
        g_app.remote_count++;
    }
    smbc_closedir(dir);
    
    return g_app.remote_count;
}

static int load_local_files(const char *path) {
    WIN32_FIND_DATAA fData;
    HANDLE hFind;
    char search_path[MAX_PATH_LEN];
    
    g_app.local_count = 0;
    snprintf(search_path, sizeof(search_path), "%s\\*", path);
    
    hFind = FindFirstFileA(search_path, &fData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    do {
        if (strcmp(fData.cFileName, ".") == 0 || strcmp(fData.cFileName, "..") == 0) continue;
        
        strncpy(g_app.local_items[g_app.local_count].path, fData.cFileName, MAX_PATH_LEN - 1);
        g_app.local_items[g_app.local_count].is_dir = (fData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        g_app.local_count++;
    } while (FindNextFileA(hFind, &fData) && g_app.local_count < MAX_ITEMS);
    
    FindClose(hFind);
    return g_app.local_count;
}

static LRESULT CALLBACK RemoteListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDBLCLK: {
            POINT pt;
            GetMessagePos(&pt);
            ScreenToClient(hwnd, &pt);
            
            int idx = SendMessageA(hwnd, LB_GETITEMDATA, pt.y / 16, 0);
            if (idx >= 0 && idx < g_app.remote_count && g_app.remote_items[idx].is_dir) {
                char new_path[MAX_PATH_LEN];
                snprintf(new_path, sizeof(new_path), "%s/%s", g_app.remote_base, 
                         g_app.remote_items[idx].path);
                strncpy(g_app.remote_base, new_path, MAX_PATH_LEN - 1);
                
                PostMessageA(g_app.hRemoteList, WM_USER_REFRESH, 0, 0);
            }
            break;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK LocalListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDBLCLK: {
            POINT pt;
            GetMessagePos(&pt);
            ScreenToClient(hwnd, &pt);
            
            int idx = SendMessageA(hwnd, LB_GETITEMDATA, pt.y / 16, 0);
            if (idx >= 0 && idx < g_app.local_count && g_app.local_items[idx].is_dir) {
                char new_path[MAX_PATH_LEN];
                snprintf(new_path, sizeof(new_path), "%s\\%s", g_app.local_base,
                         g_app.local_items[idx].path);
                strncpy(g_app.local_base, new_path, MAX_PATH_LEN - 1);
                
                PostMessageA(g_app.hLocalList, WM_USER_REFRESH, 0, 0);
            }
            break;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                      ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                      DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Consolas");
            g_current_font = (int)hFont;
            
            RECT rc;
            GetClientRect(hwnd, &rc);
            
            g_app.hRemoteList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_OWNERDRAWFIXED | LBS_NOTIFY,
                0, 0, rc.right / 2, rc.bottom - 100, hwnd, (HMENU)ID_LIST_REMOTE, g_hInst, NULL);
            
            g_app.hLocalList = CreateWindowExA(WS_EX_CLIENTSIZE, "LISTBOX", NULL,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_OWNERDRAWFIXED | LBS_NOTIFY,
                rc.right / 2, 0, rc.right / 2, rc.bottom - 100, hwnd, (HMENU)ID_LIST_LOCAL, g_hInst, NULL);
            
            g_app.hStatus = CreateWindowExA(0, "STATIC", "Ready",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                0, rc.bottom - 40, rc.right, 40, hwnd, (HMENU)ID_STATUSBAR, g_hInst, NULL);
            
            SendMessageA(g_app.hRemoteList, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessageA(g_app.hLocalList, WM_SETFONT, (WPARAM)hFont, TRUE);
            
            strcpy(g_app.local_base, "C:\\Temp");
            load_local_files(g_app.local_base);
            UpdateLocalList(hwnd);
            
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
        
        case WM_USER_REFRESH: {
            ListRemote(hwnd);
            return 0;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case ID_BUTTON_REFRESH:
                    PostMessageA(hwnd, WM_USER_REFRESH, 0, 0);
                    break;
            }
            break;
        }
        
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            HPEN hPen = CreatePen(PS_SOLID, 2, RGB(0, 0, 0));
            SelectObject(hdc, hPen);
            
            MoveToEx(hdc, LOWORD(lParam) / 2, 0, NULL);
            LineTo(hdc, LOWORD(lParam) / 2, HIWORD(lParam));
            
            DeleteObject(hPen);
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInst;
    memset(&g_app, 0, sizeof(AppContext));
    
    smbc_init_auth_function(auth_callback);
    smbc_setdebug(0);
    
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "SambaClientClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Failed to register window class", "Error", MB_ICONERROR);
        return 1;
    }
    
    g_app.conn = smbc_new_context();
    if (!g_app.conn) {
        MessageBoxA(NULL, "Failed to initialize libsmbclient", "Error", MB_ICONERROR);
        return 1;
    }
    
    HWND hwnd = CreateWindowExA(WS_EX_WINDOWEDGE, "SambaClientClass",
        "Samba Client - Two Pane",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 600,
        NULL, NULL, hInst, NULL);
    
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
    
    smbc_free_context(g_app.conn, 1);
    return (int)msg.wParam;
}