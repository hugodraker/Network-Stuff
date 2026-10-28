/* ============================================================================
 * Codeword Listener - Runs a command when a codeword is typed in 
 *
 * COMPILATION INSTRUCTIONS:
 *
 * With GCC (MinGW-w64):
 *   gcc -Os -s -mwindows wordis.c -o wordis.exe
 * 
 * 2026 HUGO
 * 
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#define _WIN32_WINNT 0x0501
#include <windows.h>
#include <stdio.h>
#define TIMER_COUNTDOWN 1
#define TIMER_MOUSE 2
#define TIMER_DEADMAN 3
// --- Globals & Definitions ---
typedef struct {
    char codeword[64];
    char message[256];
    char command[MAX_PATH];
    char commandParams[256];
} ActionDef;

// Global configuration variables
char codeword[64];
char message[256];
int fontSize;
COLORREF fontColor;
char command[MAX_PATH];
char commandParams[256];
int countdownTime;
int cancelKey;

// State variables
char inputBuffer[256] = {0};
HWND hMainWindow;
HHOOK hKeyboardHook;
BOOL isCountingDown = FALSE;
int currentCountdown = 0;
int mouseHoldTicks = 0;

ActionDef actions[256];
int actionCount = 0;
ActionDef* currentAction = NULL;

BOOL deadmanEnabled;
DWORD deadmanInterval;
char deadmanCommand[MAX_PATH];
char deadmanParams[256];
char deadmanResetCodeword[64];

BOOL IsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}

void CancelExecution(HWND hwnd) {
    KillTimer(hwnd, TIMER_COUNTDOWN);
    KillTimer(hwnd, TIMER_MOUSE);
    ShowWindow(hwnd, SW_HIDE);
    isCountingDown = FALSE;
    mouseHoldTicks = 0;
}

// --- Keyboard Hook ---
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *p = (KBDLLHOOKSTRUCT *)lParam;

        if (isCountingDown && p->vkCode == (DWORD)cancelKey) {
            PostMessage(hMainWindow, WM_APP + 2, 0, 0);
            return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
        }

        if (!isCountingDown) {
            char c = 0;
            if (p->vkCode >= 'A' && p->vkCode <= 'Z') c = (char)(p->vkCode + 32);
            else if (p->vkCode >= '0' && p->vkCode <= '9') c = (char)p->vkCode;
            else if (p->vkCode == VK_SPACE) c = ' ';

            if (c) {
                int len = lstrlenA(inputBuffer);
                if (len >= sizeof(inputBuffer) - 1) {
                    memmove(inputBuffer, inputBuffer + 1, len);
                    inputBuffer[len - 1] = c;
                } else {
                    inputBuffer[len] = c;
                    inputBuffer[len + 1] = '\0';
                }

                // Check deadman reset codeword
                if (deadmanEnabled && strstr(inputBuffer, deadmanResetCodeword) != NULL) {
                    inputBuffer[0] = '\0';
                    PostMessage(hMainWindow, WM_APP + 4, 0, 0); // Trigger timer reset silently
                    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
                }

                // Check against all loaded action codewords
                for (int i = 0; i < actionCount; i++) {
                    if (strstr(inputBuffer, actions[i].codeword) != NULL) {
                        inputBuffer[0] = '\0';
                        currentAction = &actions[i];
                        PostMessage(hMainWindow, WM_APP + 1, 0, 0);
                        break;
                    }
                }
            }
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

void DrawShadowText(HDC hdc, const char* text, RECT* rect, HFONT font, COLORREF color, UINT alignment) {
    HFONT hOldFont = (HFONT)SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    
    // Single solid shadow color (Black) instead of luminance calculation
    SetTextColor(hdc, RGB(0, 0, 0));
    
    // Single shadow offset
    RECT shadowRect = *rect; 
    OffsetRect(&shadowRect, 4, 4);
    
    // Draw shadow
    DrawTextA(hdc, text, -1, &shadowRect, alignment | DT_NOCLIP | DT_WORDBREAK);
    
    // Draw Main Text
    SetTextColor(hdc, color);
    DrawTextA(hdc, text, -1, rect, alignment | DT_NOCLIP | DT_WORDBREAK);
    
    SelectObject(hdc, hOldFont);
}
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_APP + 1:
            if (!isCountingDown && currentAction != NULL) {
                isCountingDown = TRUE;
                currentCountdown = countdownTime;
                mouseHoldTicks = 0;

                ShowWindow(hwnd, SW_SHOWNOACTIVATE);
                SetTimer(hwnd, TIMER_COUNTDOWN, 1000, NULL);
                SetTimer(hwnd, TIMER_MOUSE, 100, NULL);
                InvalidateRect(hwnd, NULL, TRUE);
            }
            return 0;

        case WM_APP + 2:
            CancelExecution(hwnd);
            return 0;

        case WM_APP + 4:
            if (deadmanEnabled) {
                SetTimer(hwnd, TIMER_DEADMAN, deadmanInterval, NULL);
            }
            return 0;

        case WM_TIMER:
            if (wParam == TIMER_DEADMAN) {
                KillTimer(hwnd, TIMER_DEADMAN);
                ShellExecuteA(NULL, "open", deadmanCommand, deadmanParams, NULL, SW_SHOWNORMAL);
            }
            else if (wParam == TIMER_COUNTDOWN) {
                currentCountdown--;
                if (currentCountdown <= 0) {
                    CancelExecution(hwnd); 
                    if (currentAction != NULL) {
                        ShellExecuteA(NULL, "open", currentAction->command, currentAction->commandParams, NULL, SW_SHOWNORMAL);
                    }
                } else {
                    InvalidateRect(hwnd, NULL, TRUE);
                }
            } 
            else if (wParam == TIMER_MOUSE) {
                if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                    mouseHoldTicks++;
                    if (mouseHoldTicks >= 50) CancelExecution(hwnd);
                } else {
                    mouseHoldTicks = 0;
                }
            }
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            RECT rect;
            GetClientRect(hwnd, &rect);
            FillRect(hdc, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));

            int centerY = rect.bottom / 2;
            
            // Adjusted bounding boxes to allow the text to flow downwards for word wrapping
            RECT msgRect = rect; msgRect.top = 50; msgRect.bottom = centerY;
            RECT timerRect = rect; timerRect.top = centerY; timerRect.bottom = rect.bottom;

            HFONT hMsgFont = CreateFontA(fontSize, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Arial");
            HFONT hTimerFont = CreateFontA(fontSize * 2, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Arial");
            
            if (currentAction != NULL) {
                // Replaced DT_SINGLELINE with DT_WORDBREAK
                DrawShadowText(hdc, currentAction->message, &msgRect, hMsgFont, fontColor, DT_CENTER | DT_WORDBREAK);
            }
            
            char timerStr[16];
            sprintf(timerStr, "%d", currentCountdown);
            DrawShadowText(hdc, timerStr, &timerRect, hTimerFont, fontColor, DT_CENTER | DT_WORDBREAK);

            DeleteObject(hMsgFont);
            DeleteObject(hTimerFont);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!IsAdmin()) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.lpVerb = "runas";
        sei.lpFile = exePath;
        sei.nShow = SW_NORMAL;
        if (ShellExecuteExA(&sei)) return 0;
        else return 1;
    }

    char iniPath[MAX_PATH];
    GetModuleFileNameA(NULL, iniPath, MAX_PATH);
    char *p = strrchr(iniPath, '\\');
    if (p) strcpy(p + 1, "wordis.ini");

    if (GetFileAttributesA(iniPath) == INVALID_FILE_ATTRIBUTES) {
        WritePrivateProfileStringA("Config", "FontSize", "144", iniPath);
        WritePrivateProfileStringA("Config", "Countdown", "10", iniPath);
        WritePrivateProfileStringA("Config", "CancelKey", "27", iniPath);
        WritePrivateProfileStringA("Config", "FontColor", "FF0000", iniPath);
        
        WritePrivateProfileStringA("Config", "DeadmanEnabled", "0", iniPath);
        WritePrivateProfileStringA("Config", "DeadmanInterval", "86400000", iniPath);
        
        // Added DeadmanResetCodeword to initialization
        WritePrivateProfileStringA("Config", "DeadmanResetCodeword", "alive", iniPath); 
        
        WritePrivateProfileStringA("Config", "DeadmanCommand", "shutdown.exe", iniPath);
        WritePrivateProfileStringA("Config", "DeadmanParams", "-s -f -t 0", iniPath);

        WritePrivateProfileStringA("Action_1", "Codeword", "launchpad", iniPath);
        WritePrivateProfileStringA("Action_1", "Message", "ACTION PENDING", iniPath);
        WritePrivateProfileStringA("Action_1", "Command", "notepad.exe", iniPath);
        WritePrivateProfileStringA("Action_1", "CommandParams", "C:\\temp\\classified.txt", iniPath);

        WritePrivateProfileStringA("Action_2", "Codeword", "abort", iniPath);
        WritePrivateProfileStringA("Action_2", "Message", "SYSTEM LOCK", iniPath);
        WritePrivateProfileStringA("Action_2", "Command", "rundll32.exe", iniPath);
        WritePrivateProfileStringA("Action_2", "CommandParams", "user32.dll,LockWorkStation", iniPath);
    }

    fontSize = GetPrivateProfileIntA("Config", "FontSize", 144, iniPath);
    countdownTime = GetPrivateProfileIntA("Config", "Countdown", 10, iniPath);
    cancelKey = GetPrivateProfileIntA("Config", "CancelKey", VK_ESCAPE, iniPath);

    deadmanEnabled = GetPrivateProfileIntA("Config", "DeadmanEnabled", 0, iniPath);
    deadmanInterval = GetPrivateProfileIntA("Config", "DeadmanInterval", 86400000, iniPath);
    GetPrivateProfileStringA("Config", "DeadmanResetCodeword", "alive", deadmanResetCodeword, sizeof(deadmanResetCodeword), iniPath);
    GetPrivateProfileStringA("Config", "DeadmanCommand", "shutdown.exe", deadmanCommand, sizeof(deadmanCommand), iniPath);
    GetPrivateProfileStringA("Config", "DeadmanParams", "-s -f -t 0", deadmanParams, sizeof(deadmanParams), iniPath);

    char colorStr[16];
    GetPrivateProfileStringA("Config", "FontColor", "FF0000", colorStr, sizeof(colorStr), iniPath);
    int r = 255, g = 0, b = 0;
    if (strlen(colorStr) == 6) {
        sscanf(colorStr, "%02x%02x%02x", &r, &g, &b);
    }
    fontColor = RGB(r, g, b);

    for (int i = 1; i <= 256; i++) {
        char section[32];
        sprintf(section, "Action_%d", i);
        char tempCodeword[64] = {0};
        
        GetPrivateProfileStringA(section, "Codeword", "", tempCodeword, sizeof(tempCodeword), iniPath);
        if (strlen(tempCodeword) > 0) {
            strcpy(actions[actionCount].codeword, tempCodeword);
            GetPrivateProfileStringA(section, "Message", "EXECUTING", actions[actionCount].message, sizeof(actions[actionCount].message), iniPath);
            GetPrivateProfileStringA(section, "Command", "cmd.exe", actions[actionCount].command, sizeof(actions[actionCount].command), iniPath);
            GetPrivateProfileStringA(section, "CommandParams", "", actions[actionCount].commandParams, sizeof(actions[actionCount].commandParams), iniPath);
            actionCount++;
        }
    }

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "OverlayWindowClass";
    RegisterClassA(&wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    hMainWindow = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        wc.lpszClassName, "", WS_POPUP,
        0, 0, screenW, screenH,
        NULL, NULL, hInstance, NULL
    );

    SetLayeredWindowAttributes(hMainWindow, RGB(0, 0, 0), 0, LWA_COLORKEY);
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, hInstance, 0);

    if (deadmanEnabled) {
        SetTimer(hMainWindow, TIMER_DEADMAN, deadmanInterval, NULL);
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(hKeyboardHook);
    
    return 0;
}
