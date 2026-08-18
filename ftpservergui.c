/*
 * THIS CODE IS RELEASED INTO THE PUBLIC DOMAIN.
 * 
 * DISCLAIMER:
 * This software is provided "as is", without warranty of any kind, express or implied.
 * It is NOT fit for any purpose, especially not for production use or secure environments.
 * The author assumes no responsibility for any damage, data loss, or security 
 * breaches caused by the use of this code. Use at your own risk.
 * 
 * COMPILE INSTRUCTIONS:
 * gcc ftpservergui.c -o ftpservergui.exe -lws2_32 -lcomctl32 -lgdi32
 */

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

#define ID_TRAY_EXIT 1001
#define ID_TRAY_START 1002
#define ID_TRAY_STOP 1003
#define ID_TRAY_SETTINGS 1004
#define ID_BTN_START_STOP 2001
#define ID_EDIT_PORT 2002

// Global State
HWND hSettingsWnd;
HWND hStatusBtn, hIpLabel, hPortEdit;
int g_port = 21;
BOOL g_running = FALSE;
HANDLE g_serverThread = NULL;
SOCKET g_server_socket = INVALID_SOCKET;
NOTIFYICONDATA nid = {0};

// FTP Logic functions (from previous step)
SOCKET data_socket = INVALID_SOCKET;

void setup_passive_socket() {
    struct sockaddr_in data_addr = { AF_INET, 0, INADDR_ANY };
    data_socket = socket(AF_INET, SOCK_STREAM, 0);
    bind(data_socket, (struct sockaddr*)&data_addr, sizeof(data_addr));
    listen(data_socket, 1);
}

void send_pasv_response(SOCKET control_socket) {
    struct sockaddr_in addr;
// Before
//socklen_t len = sizeof(addr);

// After
int len = sizeof(addr);

    getsockname(data_socket, (struct sockaddr*)&addr, &len);
    unsigned short port = ntohs(addr.sin_port);
    unsigned char *ip = (unsigned char *)&addr.sin_addr;
    char response[128];
    sprintf(response, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
            ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xFF);
    send(control_socket, response, (int)strlen(response), 0);
}

void send_binary_file(SOCKET control_socket, char *filename) {
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    SOCKET client_data_conn = accept(data_socket, (struct sockaddr*)&client_addr, &addr_len);
    if (client_data_conn == INVALID_SOCKET) {
        send(control_socket, "425 Can't open data connection\r\n", 31, 0);
        return;
    }
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        send(control_socket, "550 File not found\r\n", 21, 0);
        closesocket(client_data_conn);
        return;
    }
    send(control_socket, "150 Opening BINARY mode data connection\r\n", 41, 0);
    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, 1024, fp)) > 0) {
        send(client_data_conn, file_buffer, (int)bytes_read, 0);
    }
    fclose(fp);
    closesocket(client_data_conn);
    send(control_socket, "226 Transfer complete\r\n", 23, 0);
}

void handle_client(SOCKET client_socket) {
    char buffer[1024];
    int bytes_received;
    send(client_socket, "220 Welcome to Win32 FTP\r\n", 25, 0);
    while ((bytes_received = recv(client_socket, buffer, 1023, 0)) > 0) {
        buffer[bytes_received] = '\0';
        if (strncmp(buffer, "USER", 4) == 0) send(client_socket, "331 Password required\r\n", 23, 0);
        else if (strncmp(buffer, "PASS", 4) == 0) send(client_socket, "230 Logged in\r\n", 15, 0);
        else if (strncmp(buffer, "PASV", 4) == 0) { setup_passive_socket(); send_pasv_response(client_socket); }
        else if (strncmp(buffer, "RETR", 4) == 0) { char fn[256]; sscanf(buffer + 5, "%s", fn); send_binary_file(client_socket, fn); }
        else if (strncmp(buffer, "QUIT", 4) == 0) { send(client_socket, "221 Goodbye\r\n", 14, 0); break; }
        else send(client_socket, "502 Not implemented\r\n", 22, 0);
    }
    closesocket(client_socket);
}

// Background Thread for Server
DWORD WINAPI ServerThreadProc(LPVOID param) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    g_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = { AF_INET, htons(g_port), INADDR_ANY };
    
    if (bind(g_server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        g_running = FALSE;
        return 0;
    }
    
    listen(g_server_socket, 3);
    
    while (g_running) {
        struct timeval tv = {0, 500000}; // 0.5s timeout to check g_running
        setsockopt(g_server_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
        
        SOCKET client_socket = accept(g_server_socket, NULL, NULL);
        if (client_socket != INVALID_SOCKET) {
            handle_client(client_socket);
        }
    }
    
    closesocket(g_server_socket);
    WSACleanup();
    return 0;
}

// GUI Helpers
void UpdateUI() {
    if (!hStatusBtn) return;
// Before
//SendMessage(hStatusBtn, BM_SETTEXT, 0, g_running ? (LPARAM)"STOP SERVER" : (LPARAM)"START SERVER");
// After
SendMessage(hStatusBtn, WM_SETTEXT, 0, g_running ? (LPARAM)"STOP SERVER" : (LPARAM)"START SERVER");
    SendMessage(hStatusBtn, WM_SETTEXT, 0, 0); // Trigger repaint
    // Simple color update (Requires custom drawing, using basic text for brevity)
    if (g_running) {
        SetWindowText(hStatusBtn, "STOP SERVER");
    } else {
        SetWindowText(hStatusBtn, "START SERVER");
    }
}

LRESULT CALLBACK SettingsWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
            hStatusBtn = CreateWindow("BUTTON", "START SERVER", WS_VISIBLE | WS_CHILD, 20, 20, 150, 30, hwnd, (HMENU)ID_BTN_START_STOP, NULL, NULL);
            hIpLabel = CreateWindow("STATIC", "Bound to: 0.0.0.0", WS_VISIBLE | WS_CHILD, 20, 60, 200, 20, hwnd, NULL, NULL, NULL);
            CreateWindow("STATIC", "Port:", WS_VISIBLE | WS_CHILD, 20, 90, 50, 20, hwnd, NULL, NULL, NULL);
            hPortEdit = CreateWindow("EDIT", "21", WS_VISIBLE | WS_CHILD | WS_BORDER, 70, 90, 60, 20, hwnd, (HMENU)ID_EDIT_PORT, NULL, NULL);
            UpdateUI();
            break;
        case WM_COMMAND:
            if (LOWORD(wp) == ID_BTN_START_STOP) {
                if (!g_running) {
                    g_running = TRUE;
                    g_serverThread = CreateThread(NULL, 0, ServerThreadProc, NULL, 0, NULL);
                } else {
                    g_running = FALSE;
                    if (g_serverThread) WaitForSingleObject(g_serverThread, INFINITE);
                    g_serverThread = NULL;
                }
                UpdateUI();
            }
            if (HIWORD(wp) == EN_CHANGE && LOWORD(wp) == ID_EDIT_PORT) {
                char buf[10];
                GetWindowText(hPortEdit, buf, 10);
                g_port = atoi(buf);
                if (g_running) { // Restart server to apply port change
                    g_running = FALSE;
                    if (g_serverThread) { closesocket(g_server_socket); WaitForSingleObject(g_serverThread, INFINITE); }
                    g_running = TRUE;
                    g_serverThread = CreateThread(NULL, 0, ServerThreadProc, NULL, 0, NULL);
                }
            }
            break;
        case WM_DESTROY:
            ShowWindow(GetParent(hwnd), SW_SHOW); // Return to hidden state
            DestroyWindow(hwnd);
            break;
        default: return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE:
// Before
//nid.cbSize = sizeof(N own);
// After
nid.cbSize = sizeof(NOTIFYICONDATA); 
// Alternatively: nid.cbSize = sizeof(nid);
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_USER + 1;
            nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);
            strcpy(nid.szTip, "FTP Server");
            Shell_NotifyIcon(NIM_ADD, &nid);
            break;
        case WM_USER + 1: // Tray event
            if (LOWORD(lp) == WM_RBUTTONUP) {
                POINT pt; GetCursorPos(&pt);
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING, ID_TRAY_START, "Start");
                AppendMenu(hMenu, MF_STRING, ID_TRAY_STOP, "Stop");
                AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenu(hMenu, MF_STRING, ID_TRAY_SETTINGS, "Settings");
                AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit");
                
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
            break;
        case WM_COMMAND:
            if (LOWORD(wp) == ID_TRAY_START) {
                g_running = TRUE;
                g_serverThread = CreateThread(NULL, 0, ServerThreadProc, NULL, 0, NULL);
            } else if (LOWORD(wp) == ID_TRAY_STOP) {
                g_running = FALSE;
                if (g_serverThread) WaitForSingleObject(g_serverThread, INFINITE);
            } else if (LOWORD(wp) == ID_TRAY_SETTINGS) {
                hSettingsWnd = CreateWindow("SettingsClass", "FTP Settings", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 250, 180, NULL, NULL, GetModuleHandle(NULL), NULL);
            } else if (LOWORD(wp) == ID_TRAY_EXIT) {
                PostQuitMessage(0);
            }
            break;
        case WM_DESTROY:
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            break;
        default: return DefWindowProc(hwnd, msg, wp, lp);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    WNDCLASS wc = {0}, swc = {0};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "MainClass";
    RegisterClass(&wc);

    swc.lpfnWndProc = SettingsWndProc;
    swc.hInstance = hInst;
    swc.lpszClassName = "SettingsClass";
    swc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClass(&swc);

    // Start hidden
    HWND hwnd = CreateWindow("MainClass", "FTP Server", 0, 0, 0, 0, 0, NULL, NULL, hInst, NULL);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
