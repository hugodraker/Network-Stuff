/*
 * ============================================================================
 * Touch-Friendly GCC C Compiler GUI
 * ============================================================================
 *
 * COMPILATION INSTRUCTIONS:
 * Using MinGW GCC on Windows:
 *   gcc gui_compiler.c -o gui_compiler.exe -mwindows -lcomdlg32
 *
 * Command Flags:
 *   -mwindows   : Prevents background console window creation.
 *   -lcomdlg32  : Links Windows Common Dialog library (Open File Dialog).
 *
 * ============================================================================
 * PUBLIC DOMAIN DEDICATION (Unlicense / CC0 style):
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * ============================================================================
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <commdlg.h>

#define ID_GCC_PATH 101
#define ID_FILE_COMBO 102
#define ID_BTN_BROWSE 103
#define ID_BTN_EDIT 104
#define ID_BTN_COMPILE 105
#define ID_BTN_COPY 106
#define ID_OUTPUT 107

// Global Variables
HWND hGccPath, hFileCombo, hBtnBrowse, hBtnEdit, hBtnCompile, hBtnCopy, hOutput;
HFONT hLargeFont;
char iniPath[MAX_PATH];

// Get the path to the INI file
void InitIniPath() {
    GetModuleFileName(NULL, iniPath, MAX_PATH);
    char *lastSlash = strrchr(iniPath, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    strcat(iniPath, "config.ini");
}

// Load settings from INI
void LoadSettings() {
    char buffer[MAX_PATH];
    GetPrivateProfileString("Settings", "GCCPath", "C:\\MinGW\\bin", buffer, MAX_PATH, iniPath);
    SetWindowText(hGccPath, buffer);

    GetPrivateProfileString("Settings", "LastFile", "", buffer, MAX_PATH, iniPath);
    if (strlen(buffer) > 0) {
        SendMessage(hFileCombo, CB_ADDSTRING, 0, (LPARAM)buffer);
        SendMessage(hFileCombo, CB_SETCURSEL, 0, 0);
    }
}

// Save settings to INI
void SaveSettings() {
    char buffer[MAX_PATH];
    GetWindowText(hGccPath, buffer, MAX_PATH);
    WritePrivateProfileString("Settings", "GCCPath", buffer, iniPath);

    GetWindowText(hFileCombo, buffer, MAX_PATH);
    WritePrivateProfileString("Settings", "LastFile", buffer, iniPath);
}

// Copy output text box contents to Windows Clipboard
void CopyOutputToClipboard(HWND hwndOwner) {
    int len = GetWindowTextLength(hOutput);
    if (len <= 0) return;

    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    if (!hMem) return;

    char *pMem = (char*)GlobalLock(hMem);
    if (pMem) {
        GetWindowText(hOutput, pMem, len + 1);
        GlobalUnlock(hMem);

        if (OpenClipboard(hwndOwner)) {
            EmptyClipboard();
            SetClipboardData(CF_TEXT, hMem);
            CloseClipboard();
        } else {
            GlobalFree(hMem);
        }
    }
}

// Scan the first 5 lines of the C file for a custom compile command
// Expected format: // CMD: gcc my_file.c -o my_file.exe -O3
int GetHeaderCommand(const char* filepath, char* outCmd, size_t outSize) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;

    char line[512];
    int found = 0;
    for (int i = 0; i < 5 && fgets(line, sizeof(line), f); i++) {
        char *cmdPtr = strstr(line, "// CMD:");
        if (cmdPtr) {
            cmdPtr += 7; // Skip "// CMD:"
            while (*cmdPtr == ' ') cmdPtr++; // trim leading space
            strncpy(outCmd, cmdPtr, outSize);
            outCmd[strcspn(outCmd, "\r\n")] = 0; // trim newline
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// Compile the selected file
void CompileFile() {
    char filepath[MAX_PATH];
    GetWindowText(hFileCombo, filepath, MAX_PATH);
    if (strlen(filepath) == 0) {
        SetWindowText(hOutput, "Error: No file selected.");
        return;
    }

    // 1. Get GCC Path from text box
    char gccPath[MAX_PATH];
    GetWindowText(hGccPath, gccPath, MAX_PATH);

    // 2. Scan for header command or construct default
    char compileCmd[512];
    if (!GetHeaderCommand(filepath, compileCmd, sizeof(compileCmd))) {
        char outExe[MAX_PATH];
        strcpy(outExe, filepath);
        char *dot = strrchr(outExe, '.');
        if (dot) *dot = '\0';
        strcat(outExe, ".exe");
        snprintf(compileCmd, sizeof(compileCmd), "gcc \"%s\" -o \"%s\"", filepath, outExe);
    }

    // 3. Prepend PATH directly in the cmd execution string
    // Format: set "PATH=<gccPath>;%PATH%" && <compileCmd> 2>&1
    char fullCmd[2048];
    snprintf(fullCmd, sizeof(fullCmd), "set \"PATH=%s;%%PATH%%\" && %s 2>&1", gccPath, compileCmd);

    SetWindowText(hOutput, "Compiling...\r\n");
    FILE *pipe = _popen(fullCmd, "r");
    if (!pipe) {
        SetWindowText(hOutput, "Error: Failed to launch cmd pipe.");
        return;
    }

    char buffer[1024];
    char outputLog[8192] = "";
    strcat(outputLog, "Command: ");
    strcat(outputLog, compileCmd);
    strcat(outputLog, "\r\n\r\n");

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        if (strlen(outputLog) + strlen(buffer) < sizeof(outputLog) - 1) {
            strcat(outputLog, buffer);
        }
    }
    
    int exitCode = _pclose(pipe);
    if (exitCode == 0) strcat(outputLog, "\r\n[Success] Compiled with 0 errors.");
    else strcat(outputLog, "\r\n[Failed] Compilation encountered errors.");
    
    SetWindowText(hOutput, outputLog);
}

// Window Procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Create a large font for 5" screens
            hLargeFont = CreateFont(28, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 
                                    OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, 
                                    DEFAULT_PITCH | FF_SWISS, "Segoe UI");

            hGccPath   = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_GCC_PATH, NULL, NULL);
            hFileCombo = CreateWindow("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, 0, 0, 0, 0, hwnd, (HMENU)ID_FILE_COMBO, NULL, NULL);
            hBtnBrowse = CreateWindow("BUTTON", "Browse...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);
            hBtnEdit   = CreateWindow("BUTTON", "Edit in Notepad", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)ID_BTN_EDIT, NULL, NULL);
            hBtnCompile= CreateWindow("BUTTON", "COMPILE", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)ID_BTN_COMPILE, NULL, NULL);
            hBtnCopy   = CreateWindow("BUTTON", "Copy Output", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)ID_BTN_COPY, NULL, NULL);
            hOutput    = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 0, 0, 0, 0, hwnd, (HMENU)ID_OUTPUT, NULL, NULL);

            SendMessage(hGccPath, WM_SETFONT, (WPARAM)hLargeFont, TRUE);
            SendMessage(hFileCombo, WM_SETFONT, (WPARAM)hLargeFont, TRUE);
            SendMessage(hBtnBrowse, WM_SETFONT, (WPARAM)hLargeFont, TRUE);
            SendMessage(hBtnEdit, WM_SETFONT, (WPARAM)hLargeFont, TRUE);
            SendMessage(hBtnCompile, WM_SETFONT, (WPARAM)hLargeFont, TRUE);
            SendMessage(hBtnCopy, WM_SETFONT, (WPARAM)hLargeFont, TRUE);
            SendMessage(hOutput, WM_SETFONT, (WPARAM)hLargeFont, TRUE);

            InitIniPath();
            LoadSettings();
            return 0;
        }

        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            int pad = 10;
            int rowH = 50; // Big touch targets

            // Row 1: GCC Path
            MoveWindow(hGccPath, pad, pad, width - (pad*2), rowH, TRUE);
            
            // Row 2: File Dropdown & Browse
            int btnW = 120;
            MoveWindow(hFileCombo, pad, pad*2 + rowH, width - (pad*3) - btnW, rowH, TRUE);
            MoveWindow(hBtnBrowse, width - pad - btnW, pad*2 + rowH, btnW, rowH, TRUE);

            // Row 3: Action Buttons (3 equal-width columns)
            int thirdW = (width - (pad*4)) / 3;
            MoveWindow(hBtnEdit,    pad,               pad*3 + rowH*2, thirdW, rowH*1.5, TRUE);
            MoveWindow(hBtnCompile, pad*2 + thirdW,     pad*3 + rowH*2, thirdW, rowH*1.5, TRUE);
            MoveWindow(hBtnCopy,    pad*3 + thirdW*2,   pad*3 + rowH*2, thirdW, rowH*1.5, TRUE);

            // Row 4: Output Log
            int outY = pad*4 + rowH*3.5;
            MoveWindow(hOutput, pad, outY, width - (pad*2), height - outY - pad, TRUE);
            return 0;
        }

        case WM_COMMAND: {
            if (LOWORD(wParam) == ID_BTN_BROWSE) {
                OPENFILENAME ofn;
                char szFile[MAX_PATH] = {0};
                ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = "C Source Files\0*.c\0All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFileTitle = NULL;
                ofn.nMaxFileTitle = 0;
                ofn.lpstrInitialDir = NULL;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                if (GetOpenFileName(&ofn) == TRUE) {
                    SendMessage(hFileCombo, CB_ADDSTRING, 0, (LPARAM)szFile);
                    SendMessage(hFileCombo, CB_SETCURSEL, SendMessage(hFileCombo, CB_GETCOUNT, 0, 0) - 1, 0);
                    SaveSettings();
                }
            }
            else if (LOWORD(wParam) == ID_BTN_EDIT) {
                char filepath[MAX_PATH];
                GetWindowText(hFileCombo, filepath, MAX_PATH);
                if (strlen(filepath) > 0) {
                    ShellExecute(NULL, "open", "notepad.exe", filepath, NULL, SW_SHOWNORMAL);
                }
            }
            else if (LOWORD(wParam) == ID_BTN_COMPILE) {
                SaveSettings();
                CompileFile();
            }
            else if (LOWORD(wParam) == ID_BTN_COPY) {
                CopyOutputToClipboard(hwnd);
            }
            return 0;
        }

        case WM_DESTROY: {
            SaveSettings();
            DeleteObject(hLargeFont);
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    const char CLASS_NAME[] = "GccGuiClass";
    WNDCLASS wc = {0};

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    HWND hwnd = CreateWindowEx(
        0, CLASS_NAME, "Touch GCC Compiler", 
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, 
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {0};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}