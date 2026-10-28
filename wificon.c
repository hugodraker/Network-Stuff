/*
 * File: wificon.c
 * Description: Win32 Native Wi-Fi Manager for Windows LiveCD / WinPE.
 *              - Windows 11 Inspired UI with large GDI Green Wi-Fi Waves.
 *              - Keyboard Navigation (Up/Down Arrows & Enter to connect).
 *              - Flyout behavior (Hides when focus is lost).
 *              - Disconnect, Advanced Properties (with all bound IP addresses), and Forget buttons.
 *              - Automatically fetches and copies saved Wi-Fi passwords to clipboard.
 * License: Released into the Public Domain.
 * 
 * Compile using:
 * gcc -Os -s -o wificon.exe wificon.c -mwindows -lwlanapi -luser32 -lgdi32 -lshell32 -liphlpapi -lws2_32 -lwininet
 */

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // Required for GetAdaptersAddresses
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <wlanapi.h>
#include <windot11.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <math.h>
#define WM_USER_TRAY         (WM_USER + 1)
#define WM_USER_SHOW_MANAGER (WM_USER + 2)
#define ID_TRAY_EXIT         9999
#define ID_BTN_CONNECT_ENTER 9998
// Globals
HANDLE hWlan = NULL;
GUID wlanGuid;
HWND hMainWnd = NULL;
HWND hPassEdit = NULL;
NOTIFYICONDATA nid;
WNDPROC OldEditProc;

HFONT hFontLarge, hFontNormal, hFontSmall;
BOOL g_bShowingDialog = FALSE; 
DWORD g_dwLastHideTime = 0;
BOOL g_bCaptivePortal = FALSE;
char g_szCurrentSSID[64] = {0};

#define MAX_NETWORKS 150
typedef struct {
    char ssid[64];
    int signal;
    BOOL isSecure;
    BOOL isConnected;
    int authAlg;
    int cipherAlg;
} WiFiNetwork;

WiFiNetwork networks[MAX_NETWORKS];
int numNetworks = 0;

// UI State
int scrollY = 0;
int hoverIndex = -1;
int selectedIndex = -1;
int hoverButton = 0; // 0=None, 1=Connect/Disconnect, 3=Refresh, 4=Properties, 5=Forget

// Layout constants
#define WND_WIDTH 340
#define WND_HEIGHT 520
#define HEADER_HEIGHT 65
#define ITEM_NORMAL_H 60
#define ITEM_EXPAND_H 150
#define ITEM_EXPAND_CONN_H 115 
// Theme Colors (Win 11 Light)
#define CLR_BG        RGB(243, 243, 243)
#define CLR_HEADER    RGB(255, 255, 255)
#define CLR_HOVER     RGB(235, 235, 235)
#define CLR_SELECTED  RGB(249, 249, 249)
#define CLR_TEXT      RGB(20, 20, 20)
#define CLR_TEXT_MUT  RGB(100, 100, 100)
#define CLR_ACCENT    RGB(0, 120, 212) 
#define CLR_ACCENT_HV RGB(0, 90, 158)
#define CLR_WARN      RGB(200, 60, 60)
#define CLR_WARN_HV   RGB(170, 40, 40)
#define CLR_BTN_NORM  RGB(225, 225, 225)
#define CLR_BTN_HOVER RGB(205, 205, 205)
#define WM_USER_UPDATE_WIFI (WM_USER + 3)
const wchar_t *wpa2_template =
    L"<?xml version=\"1.0\"?>\n"
    L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
    L"  <name>%ls</name>\n"
    L"  <SSIDConfig><SSID><name>%ls</name></SSID></SSIDConfig>\n"
    L"  <connectionType>ESS</connectionType>\n"
    L"  <connectionMode>auto</connectionMode>\n"
    L"  <MSM><security><authEncryption>\n"
    L"    <authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX>\n"
    L"  </authEncryption><sharedKey>\n"
    L"    <keyType>passPhrase</keyType><protected>false</protected><keyMaterial>%ls</keyMaterial>\n"
    L"  </sharedKey></security></MSM>\n"
    L"</WLANProfile>";

const wchar_t *open_template =
    L"<?xml version=\"1.0\"?>\n"
    L"<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
    L"  <name>%ls</name>\n"
    L"  <SSIDConfig><SSID><name>%ls</name></SSID></SSIDConfig>\n"
    L"  <connectionType>ESS</connectionType>\n"
    L"  <connectionMode>auto</connectionMode>\n"
    L"  <MSM><security><authEncryption>\n"
    L"    <authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX>\n"
    L"  </authEncryption></security></MSM>\n"
    L"</WLANProfile>";

void WINAPI WlanNotificationCallback(PWLAN_NOTIFICATION_DATA data, PVOID context) {
    if (data->NotificationSource == WLAN_NOTIFICATION_SOURCE_ACM) {
        if (data->NotificationCode == wlan_notification_acm_connection_complete ||
            data->NotificationCode == wlan_notification_acm_disconnected) {
            PostMessage((HWND)context, WM_USER_UPDATE_WIFI, 0, 0);
        }
    }
}

DWORD WINAPI CheckCaptivePortalThread(LPVOID lpParam) {
    HINTERNET hInternet = InternetOpenA("WinPEWifi", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hUrl = InternetOpenUrlA(hInternet, "http://www.msftconnecttest.com/connecttest.txt", NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
        if (hUrl) {
            char buf[64] = {0};
            DWORD bytesRead = 0;
            InternetReadFile(hUrl, buf, sizeof(buf) - 1, &bytesRead);
            if (bytesRead > 0 && strstr(buf, "Microsoft Connect Test") != NULL) {
                g_bCaptivePortal = FALSE;
            } else {
                g_bCaptivePortal = TRUE;
            }
            InternetCloseHandle(hUrl);
        } else {
            g_bCaptivePortal = TRUE;
        }
        InternetCloseHandle(hInternet);
        
        if (g_bCaptivePortal) {
            ShellExecuteA(NULL, "open", "http://www.msftconnecttest.com/redirect", NULL, NULL, SW_SHOWNORMAL);
        }
    }
    if (hMainWnd) InvalidateRect(hMainWnd, NULL, FALSE);
    return 0;
}
// --- Core Wi-Fi ---

void ConnectNetwork(const char* ssid, const char* password) {
    wchar_t wSsid[256] = {0};
    MultiByteToWideChar(CP_UTF8, 0, ssid, -1, wSsid, 256);
    wchar_t wProfileXml[2048] = {0};
    
    if (password && strlen(password) > 0) {
        wchar_t wPass[65] = {0};
        MultiByteToWideChar(CP_UTF8, 0, password, -1, wPass, 65);
        swprintf(wProfileXml, 2048, wpa2_template, wSsid, wSsid, wPass);
    } else {
        swprintf(wProfileXml, 2048, open_template, wSsid, wSsid);
    }

    DWORD dwReason = 0;
    WlanSetProfile(hWlan, &wlanGuid, 0, wProfileXml, NULL, TRUE, NULL, &dwReason);

    WLAN_CONNECTION_PARAMETERS params;
    memset(&params, 0, sizeof(params));
    params.wlanConnectionMode = wlan_connection_mode_profile;
    params.strProfile = wSsid;
    params.dot11BssType = dot11_BSS_type_infrastructure;
    
    WlanConnect(hWlan, &wlanGuid, &params, NULL);
}

void ScanNetworks() {
    numNetworks = 0;
    PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
    if (WlanGetAvailableNetworkList(hWlan, &wlanGuid, 0, NULL, &pBssList) == ERROR_SUCCESS) {
        for (DWORD i = 0; i < pBssList->dwNumberOfItems && numNetworks < MAX_NETWORKS; i++) {
            if (pBssList->Network[i].dot11Ssid.uSSIDLength == 0) continue;
            
            char ssid[64] = {0};
            memcpy(ssid, pBssList->Network[i].dot11Ssid.ucSSID, pBssList->Network[i].dot11Ssid.uSSIDLength);
            
            BOOL exists = FALSE;
            for (int j = 0; j < numNetworks; j++) {
                if (strcmp(networks[j].ssid, ssid) == 0) { exists = TRUE; break; }
            }
            if (!exists) {
                strcpy(networks[numNetworks].ssid, ssid);
                networks[numNetworks].signal = pBssList->Network[i].wlanSignalQuality;
                networks[numNetworks].isSecure = (pBssList->Network[i].dot11DefaultAuthAlgorithm != 1); 
                networks[numNetworks].isConnected = (pBssList->Network[i].dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED);
                networks[numNetworks].authAlg = pBssList->Network[i].dot11DefaultAuthAlgorithm;
                networks[numNetworks].cipherAlg = pBssList->Network[i].dot11DefaultCipherAlgorithm;
                numNetworks++;
            }
        }
        WlanFreeMemory(pBssList);
    }
}

const char* GetAuthString(int alg) {
    switch(alg) {
        case 1: return "Open";
        case 2: return "Shared";
        case 3: return "WPA";
        case 4: return "WPA-PSK";
        case 6: return "WPA2";
        case 7: return "WPA2-PSK";
        case 8: return "WPA3";
        default: return "Unknown";
    }
}

const char* GetCipherString(int alg) {
    switch(alg) {
        case 0x00: return "None";
        case 0x01: return "WEP (40-bit)";
        case 0x02: return "TKIP";
        case 0x04: return "AES (CCMP)";
        case 0x05: return "WEP (104-bit)";
        case 0x101: return "WEP";
        default: return "Unknown";
    }
}

void GetAdapterIpAddresses(const GUID* pGuid, char* outStr, int maxLen) {
    outStr[0] = '\0';
    
    char targetGuidStr[64];
    sprintf(targetGuidStr, "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        pGuid->Data1, pGuid->Data2, pGuid->Data3,
        pGuid->Data4[0], pGuid->Data4[1], pGuid->Data4[2], pGuid->Data4[3],
        pGuid->Data4[4], pGuid->Data4[5], pGuid->Data4[6], pGuid->Data4[7]);

    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (!pAddresses) {
        snprintf(outStr, maxLen, "Memory Error");
        return;
    }

    DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
        if (!pAddresses) {
            snprintf(outStr, maxLen, "Memory Error");
            return;
        }
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &outBufLen);
    }

    if (dwRetVal == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        BOOL found = FALSE;
        while (pCurrAddresses) {
            if (pCurrAddresses->AdapterName && strcasecmp(pCurrAddresses->AdapterName, targetGuidStr) == 0) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                char ipList[512] = "";
                while (pUnicast) {
                    SOCKADDR* sa = pUnicast->Address.lpSockaddr;
                    char ipStr[INET6_ADDRSTRLEN] = {0};
                    if (sa->sa_family == AF_INET) {
                        InetNtopA(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), ipStr, sizeof(ipStr));
                    } else if (sa->sa_family == AF_INET6) {
                        InetNtopA(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), ipStr, sizeof(ipStr));
                    }
                    if (ipStr[0] != '\0') {
                        if (ipList[0] != '\0') strcat(ipList, ", ");
                        strcat(ipList, ipStr);
                    }
                    pUnicast = pUnicast->Next;
                }
                if (ipList[0] != '\0') {
                    snprintf(outStr, maxLen, "%s", ipList);
                } else {
                    snprintf(outStr, maxLen, "None (Not assigned)");
                }
                found = TRUE;
                break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
        if (!found) {
            snprintf(outStr, maxLen, "Not active / No IP");
        }
    } else {
        snprintf(outStr, maxLen, "Unavailable");
    }

    free(pAddresses);
}

HICON CreateWaveTrayIcon(int signal, BOOL connected) {
    HDC hScreenDC = GetDC(NULL);
    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 16;
    bmi.bmiHeader.biHeight = -16;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    DWORD* pPixels = NULL;
    HBITMAP hbmp = CreateDIBSection(hScreenDC, &bmi, DIB_RGB_COLORS, (void**)&pPixels, NULL, 0);
    memset(pPixels, 0, 16 * 16 * 4); 

    // Traditional Wi-Fi tier thresholds:
    // Dot: connected
    // Bar 1: >= 25%
    // Bar 2: >= 50%
    // Bar 3: >= 75%
    int tier = 0;
    if (connected) {
        if (signal >= 75) tier = 3;
        else if (signal >= 50) tier = 2;
        else if (signal >= 25) tier = 1;
        else tier = 0; // Dot only
    }

    const float cx = 7.5f;
    const float cy = 13.5f; // Center of the base dot

    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            float dx = (float)x - cx;
            float dy = (float)y - cy; // dy <= 0 is upwards
            float dist = sqrtf(dx * dx + dy * dy);

            float alpha = 0.0f;
            int barIndex = -1; // -1: none, 0: dot, 1: inner arc, 2: middle arc, 3: outer arc

            // 1. Base dot: small filled circle
            if (dist <= 2.2f) {
                barIndex = 0;
                if (dist <= 1.4f) alpha = 1.0f;
                else alpha = 1.0f - (dist - 1.4f) / 0.8f;
            } 
            // 2. Concentric arcs: confined to a symmetric 90-degree fan (|dx| <= -dy)
            else if (dy < -0.2f) {
                // Angular anti-aliased edge cutoff along the 45-degree ray lines
                float edgeDist = (-dy - fabsf(dx)) * 0.7071f; // Orthogonal distance to diagonal edge
                float edgeFactor = 0.0f;
                if (edgeDist >= 0.5f) edgeFactor = 1.0f;
                else if (edgeDist > -0.5f) edgeFactor = edgeDist + 0.5f;

                if (edgeFactor > 0.0f) {
                    float radialAlpha = 0.0f;

                    // Inner Arc (Bar 1) - Center radius ~5.0
                    if (dist >= 3.8f && dist <= 6.2f) {
                        barIndex = 1;
                        radialAlpha = 1.0f - fabsf(dist - 5.0f) / 1.2f;
                    }
                    // Middle Arc (Bar 2) - Center radius ~8.5
                    else if (dist >= 7.3f && dist <= 9.7f) {
                        barIndex = 2;
                        radialAlpha = 1.0f - fabsf(dist - 8.5f) / 1.2f;
                    }
                    // Outer Arc (Bar 3) - Center radius ~12.0
                    else if (dist >= 10.8f && dist <= 13.2f) {
                        barIndex = 3;
                        radialAlpha = 1.0f - fabsf(dist - 12.0f) / 1.2f;
                    }

                    if (radialAlpha > 0.0f) {
                        alpha = radialAlpha * edgeFactor;
                    }
                }
            }

            if (alpha > 0.0f) {
                if (alpha > 1.0f) alpha = 1.0f;

                // Active segments light up in green; inactive or disconnected remain soft gray
                BOOL isLit = connected && (barIndex <= tier);

                BYTE r = isLit ? 0x10 : 0x77;
                BYTE g = isLit ? 0xB9 : 0x77;
                BYTE b = isLit ? 0x81 : 0x77;
                BYTE a = (BYTE)(alpha * 255.0f);

                // Premultiplied alpha required by Windows 32-bit DIB icons
                r = (r * a) / 255;
                g = (g * a) / 255;
                b = (b * a) / 255;

                pPixels[y * 16 + x] = ((DWORD)a << 24) | ((DWORD)r << 16) | ((DWORD)g << 8) | b;
            }
        }
    }

    BYTE maskBits[32] = {0};
    HBITMAP hbmMask = CreateBitmap(16, 16, 1, 1, maskBits);
    ICONINFO ii = { TRUE, 0, 0, hbmMask, hbmp };
    HICON hIcon = CreateIconIndirect(&ii);

    DeleteObject(hbmMask);
    DeleteObject(hbmp);
    ReleaseDC(NULL, hScreenDC);
    return hIcon;
}
void UpdateTrayIcon() {
    DWORD connectInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
    PWLAN_CONNECTION_ATTRIBUTES pConnectInfo = NULL;
    BOOL connected = FALSE;
    int signal = -1;
    
    if (WlanQueryInterface(hWlan, &wlanGuid, wlan_intf_opcode_current_connection, NULL, &connectInfoSize, (PVOID*)&pConnectInfo, NULL) == ERROR_SUCCESS) {
        if (pConnectInfo->isState == wlan_interface_state_connected) {
            connected = TRUE;
            signal = pConnectInfo->wlanAssociationAttributes.wlanSignalQuality;
            char ssid[64] = {0};
            memcpy(ssid, pConnectInfo->wlanAssociationAttributes.dot11Ssid.ucSSID, pConnectInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength);
            
            // New Portal Check Trigger
            if (strcmp(g_szCurrentSSID, ssid) != 0) {
                strcpy(g_szCurrentSSID, ssid);
                g_bCaptivePortal = FALSE;
                CreateThread(NULL, 0, CheckCaptivePortalThread, NULL, 0, NULL);
            }

            if (g_bCaptivePortal) {
                wsprintf(nid.szTip, L"Action Required: %hs\nSignal: %d%%", ssid, signal);
            } else {
                wsprintf(nid.szTip, L"Connected: %hs\nSignal: %d%%", ssid, signal);
            }
        }
        WlanFreeMemory(pConnectInfo);
    }
    
    if (!connected) {
        g_szCurrentSSID[0] = '\0';
        g_bCaptivePortal = FALSE;
        wcscpy(nid.szTip, L"Wi-Fi Not Connected");
        signal = -1; 
    }

    HICON hOld = nid.hIcon;
    nid.hIcon = CreateWaveTrayIcon(signal, connected);
    Shell_NotifyIcon(NIM_MODIFY, &nid);
    if (hOld) DestroyIcon(hOld);
}

// --- Keyboard Subclassing ---
LRESULT CALLBACK EditSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_KEYDOWN) {
        if (wParam == VK_UP || wParam == VK_DOWN) {
            SendMessage(GetParent(hWnd), uMsg, wParam, lParam);
            return 0; 
        }
        if (wParam == VK_RETURN) {
            SendMessage(GetParent(hWnd), WM_COMMAND, MAKEWPARAM(ID_BTN_CONNECT_ENTER, 0), 0);
            return 0;
        }
    }
    return CallWindowProc(OldEditProc, hWnd, uMsg, wParam, lParam);
}

// --- Positioning & Custom Draw Helpers ---

void PositionWindow(HWND hwnd) {
    RECT workArea;
    SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0); 
    int x = workArea.right - WND_WIDTH - 12;
    int y = workArea.bottom - WND_HEIGHT - 12;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    SetWindowPos(hwnd, HWND_TOPMOST, x, y, WND_WIDTH, WND_HEIGHT, SWP_NOZORDER | SWP_NOSIZE);
}

void DrawWaveIconUI(HDC hdc, int cx, int cy, int signal) {
    HBRUSH hBr = CreateSolidBrush(RGB(16, 185, 129)); 
    HBRUSH hBrMut = CreateSolidBrush(RGB(210, 210, 210));
    HPEN hPen = CreatePen(PS_SOLID, 3, RGB(16, 185, 129));
    HPEN hPenMut = CreatePen(PS_SOLID, 3, RGB(210, 210, 210));
    
    RECT dotRect = {cx - 2, cy - 3, cx + 3, cy + 2};
    FillRect(hdc, &dotRect, (signal >= 0) ? hBr : hBrMut);
    
    SelectObject(hdc, (signal >= 25) ? hPen : hPenMut);
    Arc(hdc, cx - 6, cy - 6, cx + 6, cy + 6, cx + 6, cy - 6, cx - 6, cy - 6);
    
    SelectObject(hdc, (signal >= 50) ? hPen : hPenMut);
    Arc(hdc, cx - 12, cy - 12, cx + 12, cy + 12, cx + 12, cy - 12, cx - 12, cy - 12);
    
    SelectObject(hdc, (signal >= 75) ? hPen : hPenMut);
    Arc(hdc, cx - 18, cy - 18, cx + 18, cy + 18, cx + 18, cy - 18, cx - 18, cy - 18);
    
    DeleteObject(hPen);
    DeleteObject(hPenMut);
    DeleteObject(hBr);
    DeleteObject(hBrMut);
}

void DrawSolidRect(HDC hdc, int x, int y, int w, int h, COLORREF col) {
    RECT r = {x, y, x+w, y+h};
    HBRUSH br = CreateSolidBrush(col);
    FillRect(hdc, &r, br);
    DeleteObject(br);
}

void DrawRoundRect(HDC hdc, int x, int y, int w, int h, int rad, COLORREF col) {
    HBRUSH br = CreateSolidBrush(col);
    HPEN pen = CreatePen(PS_SOLID, 1, col);
    HBRUSH oldBr = (HBRUSH)SelectObject(hdc, br);
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    RoundRect(hdc, x, y, x+w, y+h, rad, rad);
    SelectObject(hdc, oldBr);
    SelectObject(hdc, oldPen);
    DeleteObject(br);
    DeleteObject(pen);
}

// --- Layout & Paint ---

void UpdateEditControlLayout() {
    if (selectedIndex == -1) {
        ShowWindow(hPassEdit, SW_HIDE);
        return;
    }

    int currentY = HEADER_HEIGHT - scrollY;
    for (int i = 0; i < numNetworks; i++) {
        int itemH = (i == selectedIndex) ? (networks[i].isConnected ? ITEM_EXPAND_CONN_H : ITEM_EXPAND_H) : ITEM_NORMAL_H;
        
        if (i == selectedIndex) {
            if (networks[i].isConnected) {
                ShowWindow(hPassEdit, SW_HIDE);
            } else {
                int editY = currentY + 85;
                if (editY < HEADER_HEIGHT || editY + 28 > WND_HEIGHT) {
                    ShowWindow(hPassEdit, SW_HIDE);
                } else {
                    MoveWindow(hPassEdit, 20, editY, 195, 28, TRUE);
                    ShowWindow(hPassEdit, SW_SHOW);
                }
            }
            return;
        }
        currentY += itemH;
    }
}

void PaintUI(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    
    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP memBitmap = CreateCompatibleBitmap(hdc, WND_WIDTH, WND_HEIGHT);
    SelectObject(memDC, memBitmap);
    
    DrawSolidRect(memDC, 0, 0, WND_WIDTH, WND_HEIGHT, CLR_BG);
    SetBkMode(memDC, TRANSPARENT);
    
    int currentY = HEADER_HEIGHT - scrollY;
    for (int i = 0; i < numNetworks; i++) {
        int itemH = (i == selectedIndex) ? (networks[i].isConnected ? ITEM_EXPAND_CONN_H : ITEM_EXPAND_H) : ITEM_NORMAL_H;
        
        if (currentY + itemH > HEADER_HEIGHT && currentY < WND_HEIGHT) {
            
            COLORREF bgCol = CLR_BG;
            if (i == selectedIndex) bgCol = CLR_SELECTED;
            else if (i == hoverIndex) bgCol = CLR_HOVER;
            
            if (bgCol != CLR_BG) {
                DrawRoundRect(memDC, 5, currentY, WND_WIDTH - 10, itemH, 10, bgCol);
            }

            DrawWaveIconUI(memDC, 28, currentY + 30, networks[i].signal);

            SetTextColor(memDC, networks[i].isConnected ? CLR_ACCENT : CLR_TEXT);
            SelectObject(memDC, hFontNormal);
            TextOutA(memDC, 60, currentY + 18, networks[i].ssid, strlen(networks[i].ssid));
            
if (networks[i].isConnected) {
                SetTextColor(memDC, g_bCaptivePortal ? CLR_WARN : CLR_TEXT_MUT);
                SelectObject(memDC, hFontSmall);
                if (g_bCaptivePortal) {
                    TextOutA(memDC, WND_WIDTH - 110, currentY + 22, "Action Needed", 13);
                } else {
                    TextOutA(memDC, WND_WIDTH - 90, currentY + 22, "Connected", 9);
                }
            }

            if (i == selectedIndex) {
                SetTextColor(memDC, CLR_TEXT);
                SelectObject(memDC, hFontNormal);
                
                if (networks[i].isConnected) {
                    COLORREF btnCol1 = (hoverButton == 1) ? CLR_WARN_HV : CLR_WARN;
                    DrawRoundRect(memDC, 20, currentY + 65, 95, 32, 8, btnCol1);
                    SetTextColor(memDC, RGB(255, 255, 255));
                    RECT btnTxtR1 = {20, currentY + 65, 115, currentY + 97};
                    DrawTextA(memDC, "Disconnect", -1, &btnTxtR1, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                    COLORREF btnCol4 = (hoverButton == 4) ? CLR_BTN_HOVER : CLR_BTN_NORM;
                    DrawRoundRect(memDC, 122, currentY + 65, 95, 32, 8, btnCol4);
                    SetTextColor(memDC, CLR_TEXT);
                    RECT btnTxtR4 = {122, currentY + 65, 217, currentY + 97};
                    DrawTextA(memDC, "Properties", -1, &btnTxtR4, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                    COLORREF btnCol5 = (hoverButton == 5) ? CLR_BTN_HOVER : CLR_BTN_NORM;
                    DrawRoundRect(memDC, 224, currentY + 65, 95, 32, 8, btnCol5);
                    SetTextColor(memDC, CLR_TEXT);
                    RECT btnTxtR5 = {224, currentY + 65, 319, currentY + 97};
                    DrawTextA(memDC, "Forget", -1, &btnTxtR5, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                } else {
                    if (networks[i].isSecure) {
                        TextOutA(memDC, 20, currentY + 60, "Enter network password:", 23);
                    } else {
                        TextOutA(memDC, 20, currentY + 60, "Open network. No password required.", 35);
                    }

                    COLORREF btnCol = (hoverButton == 1) ? CLR_ACCENT_HV : CLR_ACCENT;
                    DrawRoundRect(memDC, 225, currentY + 85, 95, 30, 8, btnCol);
                    
                    SetTextColor(memDC, RGB(255, 255, 255));
                    RECT btnTxtR = {225, currentY + 85, 320, currentY + 115};
                    DrawTextA(memDC, "Connect", -1, &btnTxtR, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                }
            }
        }
        currentY += itemH;
    }

    DrawSolidRect(memDC, 0, 0, WND_WIDTH, HEADER_HEIGHT, CLR_HEADER);
    DrawSolidRect(memDC, 0, HEADER_HEIGHT - 1, WND_WIDTH, 1, RGB(220, 220, 220));

    SetTextColor(memDC, CLR_TEXT);
    SelectObject(memDC, hFontLarge);
    TextOutA(memDC, 15, 16, "Available networks", 18);

    SetTextColor(memDC, (hoverButton == 3) ? CLR_ACCENT : CLR_TEXT_MUT);
    SelectObject(memDC, hFontNormal); 
    TextOutA(memDC, WND_WIDTH - 85, 20, "Refresh", 7);

    BitBlt(hdc, 0, 0, WND_WIDTH, WND_HEIGHT, memDC, 0, 0, SRCCOPY);
    
    DeleteObject(memBitmap);
    DeleteDC(memDC);
    EndPaint(hwnd, &ps);
}

// --- Window Procedure ---

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            hFontLarge = CreateFontA(24, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
            hFontNormal = CreateFontA(18, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
            hFontSmall = CreateFontA(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
            
            hPassEdit = CreateWindowExA(0, "EDIT", "", WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 
                                        0, 0, 0, 0, hwnd, NULL, GetModuleHandle(NULL), NULL);
            SendMessage(hPassEdit, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
            OldEditProc = (WNDPROC)SetWindowLongPtr(hPassEdit, GWLP_WNDPROC, (LONG_PTR)EditSubclassProc);
            
            WlanRegisterNotification(hWlan, WLAN_NOTIFICATION_SOURCE_ACM, TRUE, WlanNotificationCallback, hwnd, NULL, NULL);
            ScanNetworks();
            break;
        }

        case WM_ACTIVATE:
            if (LOWORD(wParam) == WA_INACTIVE && !g_bShowingDialog) {
                if (IsWindowVisible(hwnd)) {
                    ShowWindow(hwnd, SW_HIDE);
                    ShowWindow(hPassEdit, SW_HIDE);
                    g_dwLastHideTime = GetTickCount();
                }
            }
            break;

        case WM_USER_UPDATE_WIFI:
            UpdateTrayIcon();
            break;
        case WM_PAINT:
            PaintUI(hwnd);
            return 0;

        case WM_ERASEBKGND:
            return 1; 

        case WM_KEYDOWN: {
            if (wParam == VK_DOWN || wParam == VK_UP) {
                if (numNetworks == 0) break;
                
                int newIdx = selectedIndex;
                if (wParam == VK_DOWN) {
                    newIdx = (selectedIndex < numNetworks - 1) ? selectedIndex + 1 : selectedIndex;
                    if (selectedIndex == -1) newIdx = 0; 
                } else if (wParam == VK_UP) {
                    newIdx = (selectedIndex > 0) ? selectedIndex - 1 : 0;
                }
                
                if (newIdx != selectedIndex) {
                    selectedIndex = newIdx;
                    SetWindowTextA(hPassEdit, "");
                    
                    int yPos = HEADER_HEIGHT;
                    for (int i = 0; i < selectedIndex; i++) yPos += ITEM_NORMAL_H;
                    int targetH = networks[selectedIndex].isConnected ? ITEM_EXPAND_CONN_H : ITEM_EXPAND_H;
                    
                    if (yPos - scrollY < HEADER_HEIGHT) {
                        scrollY = yPos - HEADER_HEIGHT;
                    } else if (yPos + targetH - scrollY > WND_HEIGHT) {
                        scrollY = yPos + targetH - WND_HEIGHT;
                    }
                    
                    UpdateEditControlLayout();
                    
                    if (IsWindowVisible(hPassEdit)) SetFocus(hPassEdit);
                    else SetFocus(hwnd);
                    
                    InvalidateRect(hwnd, NULL, FALSE);
                }
            } else if (wParam == VK_RETURN) {
                if (selectedIndex != -1 && !networks[selectedIndex].isConnected) {
                    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_CONNECT_ENTER, 0), 0);
                }
            }
            break;
        }

        case WM_MOUSEWHEEL: {
            int zDelta = GET_WHEEL_DELTA_WPARAM(wParam);
            scrollY -= (zDelta / WHEEL_DELTA) * 30;
            if (scrollY < 0) scrollY = 0;
            
            int totalH = 0;
            for (int i=0; i<numNetworks; i++) {
                totalH += (i == selectedIndex) ? (networks[i].isConnected ? ITEM_EXPAND_CONN_H : ITEM_EXPAND_H) : ITEM_NORMAL_H;
            }
            int maxScroll = totalH - (WND_HEIGHT - HEADER_HEIGHT);
            if (maxScroll < 0) maxScroll = 0;
            if (scrollY > maxScroll) scrollY = maxScroll;
            
            UpdateEditControlLayout();
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        }

        case WM_MOUSEMOVE: {
            int mx = LOWORD(lParam);
            int my = HIWORD(lParam);
            
            int oldHover = hoverIndex;
            int oldBtn = hoverButton;
            hoverIndex = -1;
            hoverButton = 0;

            if (my < HEADER_HEIGHT) {
                if (mx > WND_WIDTH - 95) hoverButton = 3; 
            } 
            else {
                int currentY = HEADER_HEIGHT - scrollY;
                for (int i = 0; i < numNetworks; i++) {
                    int itemH = (i == selectedIndex) ? (networks[i].isConnected ? ITEM_EXPAND_CONN_H : ITEM_EXPAND_H) : ITEM_NORMAL_H;
                    if (my >= currentY && my < currentY + itemH) {
                        hoverIndex = i;
                        if (i == selectedIndex) {
                            if (networks[i].isConnected) {
                                if (my >= currentY + 65 && my <= currentY + 97) {
                                    if (mx >= 20 && mx <= 115) hoverButton = 1;       
                                    else if (mx >= 122 && mx <= 217) hoverButton = 4; 
                                    else if (mx >= 224 && mx <= 319) hoverButton = 5; 
                                }
                            } else {
                                if (mx >= 225 && mx <= 320 && my >= currentY + 85 && my <= currentY + 115) hoverButton = 1;
                            }
                        }
                        break;
                    }
                    currentY += itemH;
                }
            }

            if (oldHover != hoverIndex || oldBtn != hoverButton) {
                InvalidateRect(hwnd, NULL, FALSE);
            }
            break;
        }

        case WM_LBUTTONDOWN: {
            if (HIWORD(lParam) < HEADER_HEIGHT && hoverButton == 0) {
                ReleaseCapture();
                SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
                return 0;
            }

            if (hoverButton == 3) { 
                WlanScan(hWlan, &wlanGuid, NULL, NULL, NULL);
                Sleep(400); 
                ScanNetworks();
                selectedIndex = -1;
                scrollY = 0;
                UpdateEditControlLayout();
                SetFocus(hwnd);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            else if (hoverButton == 1 && selectedIndex != -1) { 
                if (networks[selectedIndex].isConnected) {
                    WlanDisconnect(hWlan, &wlanGuid, NULL);
                    Sleep(500); 
                    ScanNetworks();
                    selectedIndex = -1;
                    UpdateEditControlLayout();
                    SetFocus(hwnd);
                    InvalidateRect(hwnd, NULL, FALSE);
                } else {
                    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_CONNECT_ENTER, 0), 0);
                }
            }
            else if (hoverButton == 4 && selectedIndex != -1) { 
                char password[256] = {0};
                DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                LPWSTR profileXml = NULL;
                DWORD access = 0;
                wchar_t wSsid[256];
                MultiByteToWideChar(CP_UTF8, 0, networks[selectedIndex].ssid, -1, wSsid, 256);

                if (WlanGetProfile(hWlan, &wlanGuid, wSsid, NULL, &profileXml, &flags, &access) == ERROR_SUCCESS) {
                    wchar_t* keyStart = wcsstr(profileXml, L"<keyMaterial>");
                    if (keyStart) {
                        keyStart += 13;
                        wchar_t* keyEnd = wcsstr(keyStart, L"</keyMaterial>");
                        if (keyEnd) {
                            int len = keyEnd - keyStart;
                            if (len < 255) {
                                WideCharToMultiByte(CP_UTF8, 0, keyStart, len, password, 256, NULL, NULL);
                            }
                        }
                    }
                    WlanFreeMemory(profileXml);
                }

                char ipBuffer[256] = "None";
                GetAdapterIpAddresses(&wlanGuid, ipBuffer, sizeof(ipBuffer));

                char props[1024];
                sprintf(props, "Network Name (SSID):\t %s\nSignal Quality:\t\t %d%%\nSecurity:\t\t %s\nAuthentication:\t\t %s\nEncryption:\t\t %s\nIP Address(es):\t\t %s\nStatus:\t\t\t Connected", 
                    networks[selectedIndex].ssid, 
                    networks[selectedIndex].signal, 
                    networks[selectedIndex].isSecure ? "Secured" : "Open",
                    GetAuthString(networks[selectedIndex].authAlg),
                    GetCipherString(networks[selectedIndex].cipherAlg),
                    ipBuffer);
                
                g_bShowingDialog = TRUE;
                if (strlen(password) > 0) {
                    strcat(props, "\n\nWould you like to copy the Wi-Fi password to the clipboard?");
                    if (MessageBoxA(hwnd, props, "Network Properties", MB_YESNO | MB_ICONINFORMATION) == IDYES) {
                        if (OpenClipboard(hwnd)) {
                            EmptyClipboard();
                            HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(password) + 1);
                            if (hg) {
                                memcpy(GlobalLock(hg), password, strlen(password) + 1);
                                GlobalUnlock(hg);
                                SetClipboardData(CF_TEXT, hg);
                            }
                            CloseClipboard();
                        }
                    }
                } else {
                    MessageBoxA(hwnd, props, "Network Properties", MB_OK | MB_ICONINFORMATION);
                }
                g_bShowingDialog = FALSE;
            }
            else if (hoverButton == 5 && selectedIndex != -1) { 
                wchar_t wSsid[256];
                MultiByteToWideChar(CP_UTF8, 0, networks[selectedIndex].ssid, -1, wSsid, 256);
                
                g_bShowingDialog = TRUE;
                if (WlanDeleteProfile(hWlan, &wlanGuid, wSsid, NULL) == ERROR_SUCCESS) {
                    MessageBoxA(hwnd, "Network profile forgotten successfully.", "Forget Network", MB_OK | MB_ICONINFORMATION);
                } else {
                    MessageBoxA(hwnd, "Network is not saved or cannot be forgotten.", "Forget Network", MB_OK | MB_ICONWARNING);
                }
                g_bShowingDialog = FALSE;
                
                WlanDisconnect(hWlan, &wlanGuid, NULL);
                Sleep(500);
                ScanNetworks();
                selectedIndex = -1;
                UpdateEditControlLayout();
                SetFocus(hwnd);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            else if (hoverIndex != -1 && hoverIndex != selectedIndex) { 
                selectedIndex = hoverIndex;
                SetWindowTextA(hPassEdit, "");
                UpdateEditControlLayout();
                if (IsWindowVisible(hPassEdit)) SetFocus(hPassEdit);
                else SetFocus(hwnd);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            break;
        }

        case WM_NCHITTEST: {
            LRESULT hit = DefWindowProc(hwnd, uMsg, wParam, lParam);
            return (hit == HTCLIENT) ? HTCLIENT : hit; 
        }
        
        case WM_USER_SHOW_MANAGER: {
            PositionWindow(hwnd);
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            SetFocus(hwnd);
            WlanScan(hWlan, &wlanGuid, NULL, NULL, NULL);
            ScanNetworks();
            InvalidateRect(hwnd, NULL, FALSE);
            break;
        }

        case WM_USER_TRAY: {
            if (lParam == WM_LBUTTONUP) {
                if (IsWindowVisible(hwnd)) {
                    ShowWindow(hwnd, SW_HIDE);
                    ShowWindow(hPassEdit, SW_HIDE);
                    g_dwLastHideTime = GetTickCount();
                } else {
                    if (GetTickCount() - g_dwLastHideTime > 200) {
                        SendMessage(hwnd, WM_USER_SHOW_MANAGER, 0, 0);
                    }
                }
            } else if (lParam == WM_RBUTTONUP) {
                HMENU hMenu = CreatePopupMenu();
                AppendMenuA(hMenu, MF_STRING, ID_TRAY_EXIT, "Exit Wi-Fi Manager");
                POINT pt; GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_RIGHTALIGN, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
            }
            break;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == ID_TRAY_EXIT) {
                DestroyWindow(hwnd);
            } 
            else if (LOWORD(wParam) == ID_BTN_CONNECT_ENTER) {
                if (selectedIndex != -1 && !networks[selectedIndex].isConnected) {
                    char pass[65] = {0};
                    GetWindowTextA(hPassEdit, pass, 65);
                    ConnectNetwork(networks[selectedIndex].ssid, pass);
                    
                    g_bShowingDialog = TRUE;
                    MessageBoxA(hwnd, "Connection request sent.", "Connecting", MB_OK | MB_ICONINFORMATION);
                    g_bShowingDialog = FALSE;
                }
            }
            break;
        }

        case WM_DESTROY:
            WlanRegisterNotification(hWlan, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, NULL, NULL, NULL, NULL);
            Shell_NotifyIcon(NIM_DELETE, &nid);
            DeleteObject(hFontLarge);
            DeleteObject(hFontNormal);
            DeleteObject(hFontSmall);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// --- CLI + Main ---

int main(int argc, char *argv[]) {
    BOOL isGuiMode = (argc == 1);
    
    if (!isGuiMode) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }

    if (isGuiMode) {
        HANDLE hMutex = CreateMutexA(NULL, FALSE, "WinPE_Wifi_Tray_Mutex");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            HWND hExisting = FindWindowA("WinPEWifiWin11", NULL);
            if (hExisting) PostMessageA(hExisting, WM_USER_SHOW_MANAGER, 0, 0);
            return 0; 
        }
    }

    DWORD dwMaxClient = 2, dwCurVersion = 0;
    if (WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hWlan) != ERROR_SUCCESS) {
        if (isGuiMode) MessageBoxA(NULL, "Could not open WLAN. Ensure 'wlansvc' is running.", "Error", MB_ICONERROR);
        else printf("Error: WLAN Handle failed.\n");
        return 1;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    if (WlanEnumInterfaces(hWlan, NULL, &pIfList) != ERROR_SUCCESS || pIfList->dwNumberOfItems == 0) {
        if (isGuiMode) MessageBoxA(NULL, "No Wi-Fi adapters found.", "Error", MB_ICONERROR);
        else printf("Error: No Wi-Fi adapters found.\n");
        if (pIfList) WlanFreeMemory(pIfList);
        WlanCloseHandle(hWlan, NULL);
        return 1;
    }
    wlanGuid = pIfList->InterfaceInfo[0].InterfaceGuid;
    WlanFreeMemory(pIfList);

    if (!isGuiMode) {
        if (strcmp(argv[1], "connect") == 0 && argc >= 3) {
            ConnectNetwork(argv[2], (argc >= 4) ? argv[3] : NULL);
            printf("Connection request sent.\n");
        }
        WlanCloseHandle(hWlan, NULL);
        FreeConsole();
        return 0;
    }

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "WinPEWifiWin11";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassA(&wc);

    hMainWnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW, 
        "WinPEWifiWin11", "",
        WS_POPUP, 
        0, 0, WND_WIDTH, WND_HEIGHT,
        NULL, NULL, GetModuleHandle(NULL), NULL);

    HRGN hRgn = CreateRoundRectRgn(0, 0, WND_WIDTH, WND_HEIGHT, 16, 16);
    SetWindowRgn(hMainWnd, hRgn, TRUE);

    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = hMainWnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_USER_TRAY;
    nid.hIcon = CreateWaveTrayIcon(-1, FALSE);
    wcscpy(nid.szTip, L"Wi-Fi Manager");
    Shell_NotifyIcon(NIM_ADD, &nid);

    UpdateTrayIcon();
    SendMessage(hMainWnd, WM_USER_SHOW_MANAGER, 0, 0);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (hPassEdit == NULL || !IsDialogMessage(hMainWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    WlanCloseHandle(hWlan, NULL);
    return 0;
}