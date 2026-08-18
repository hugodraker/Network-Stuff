/*
 * ============================================================================
 * Touch-Friendly GCC C Compiler GUI
 * ============================================================================
 *
 * COMPILATION INSTRUCTIONS:
 * Using MinGW GCC on Windows:
 *   gcc gui_compiler.c -o gui_compiler.exe -mwindows -lcomdlg32
 *
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
    strcat(iniPath, "gui_compiler.ini"); // Changed from config.ini
}

// Load settings from INI
void LoadSettings() {
    char buffer[MAX_PATH];
    char keyName[32];
    
    // Load GCC Path
    GetPrivateProfileString("Settings", "GCCPath", "C:\\MinGW\\bin", buffer, MAX_PATH, iniPath);
    SetWindowText(hGccPath, buffer);

    // Load file history (up to 15 files)
    int count = GetPrivateProfileInt("Settings", "FileCount", 0, iniPath);
    for (int i = 0; i < count; i++) {
        snprintf(keyName, sizeof(keyName), "File%d", i);
        GetPrivateProfileString("Settings", keyName, "", buffer, MAX_PATH, iniPath);
        if (strlen(buffer) > 0) {
            SendMessage(hFileCombo, CB_ADDSTRING, 0, (LPARAM)buffer);
        }
    }

    // Restore the file that was actively selected last time
    GetPrivateProfileString("Settings", "LastSelected", "", buffer, MAX_PATH, iniPath);
    if (strlen(buffer) > 0) {
        SetWindowText(hFileCombo, buffer);
    } else if (count > 0) {
        SendMessage(hFileCombo, CB_SETCURSEL, 0, 0); // Default to first item if exist
    }
}

// Save settings to INI
void SaveSettings() {
    char buffer[MAX_PATH];
    char keyName[32];
    
    // Save GCC Path
    GetWindowText(hGccPath, buffer, MAX_PATH);
    WritePrivateProfileString("Settings", "GCCPath", buffer, iniPath);

    // Get current text in the combo box. If it's not in the list, add it.
    GetWindowText(hFileCombo, buffer, MAX_PATH);
    if (strlen(buffer) > 0) {
        LRESULT idx = SendMessage(hFileCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)buffer);
        if (idx == CB_ERR) {
            // Add typed string to dropdown history
            idx = SendMessage(hFileCombo, CB_ADDSTRING, 0, (LPARAM)buffer);
        }
        // Force the combobox to select this item to update the UI visually
        SendMessage(hFileCombo, CB_SETCURSEL, idx, 0);
    }

    // Save combo box history (limit to 15 to keep INI clean)
    int count = (int)SendMessage(hFileCombo, CB_GETCOUNT, 0, 0);
    int maxSave = (count > 15) ? 15 : count;
    
    snprintf(buffer, sizeof(buffer), "%d", maxSave);
    WritePrivateProfileString("Settings", "FileCount", buffer, iniPath);

    for (int i = 0; i < maxSave; i++) {
        SendMessage(hFileCombo, CB_GETLBTEXT, i, (LPARAM)buffer);
        snprintf(keyName, sizeof(keyName), "File%d", i);
        WritePrivateProfileString("Settings", keyName, buffer, iniPath);
    }
    
    // Save currently selected/typed text
    GetWindowText(hFileCombo, buffer, MAX_PATH);
    WritePrivateProfileString("Settings", "LastSelected", buffer, iniPath);
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

// Robust header command parser: scans first 30 lines directly for "gcc " or "g++ "
int GetHeaderCommand(const char* filepath, char* outCmd, size_t outSize) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;

    char line[1024];
    int found = 0;

    // Scan up to 30 lines to accommodate large license/header comments
    for (int i = 0; i < 30 && fgets(line, sizeof(line), f); i++) {
        // Look for gcc or g++
        char *cmdPtr = strstr(line, "gcc ");
        if (!cmdPtr) cmdPtr = strstr(line, "g++ ");
        
        // If found, and it looks like a real compile command
        if (cmdPtr && (strstr(cmdPtr, ".c") || strstr(cmdPtr, ".cpp") || strstr(cmdPtr, "-o "))) {
            
            strncpy(outCmd, cmdPtr, outSize - 1);
            outCmd[outSize - 1] = '\0';

            // Strip trailing newlines/carriage returns
            outCmd[strcspn(outCmd, "\r\n")] = 0;

            // Strip trailing block comment close "*/" if present
            char *commentEnd = strstr(outCmd, "*/");
            if (commentEnd) *commentEnd = '\0';

            // Trim trailing whitespace
            int len = (int)strlen(outCmd);
            while (len > 0 && (outCmd[len - 1] == ' ' || outCmd[len - 1] == '\t')) {
                outCmd[--len] = '\0';
            }

            if (len > 0) {
                found = 1;
                break;
            }
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

    // 2. Scan file header for custom compile command
    char compileCmd[1024];
    if (!GetHeaderCommand(filepath, compileCmd, sizeof(compileCmd))) {
        // Default command if no header directive is found
        char outExe[MAX_PATH];
        strcpy(outExe, filepath);
        char *dot = strrchr(outExe, '.');
        if (dot) *dot = '\0';
        strcat(outExe, ".exe");
        snprintf(compileCmd, sizeof(compileCmd), "gcc \"%s\" -o \"%s\"", filepath, outExe);
    }

    // 3. Prepend PATH in subshell execution
    char fullCmd[3072];
    snprintf(fullCmd, sizeof(fullCmd), "set \"PATH=%s;%%PATH%%\" && %s 2>&1", gccPath, compileCmd);

    SetWindowText(hOutput, "Compiling...\r\n");
    FILE *pipe = _popen(fullCmd, "r");
    if (!pipe) {
        SetWindowText(hOutput, "Error: Failed to launch command process.");
        return;
    }

    char buffer[1024];
    char outputLog[16384] = "";
    snprintf(outputLog, sizeof(outputLog), "Command: %s\r\n\r\n", compileCmd);

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
            int rowH = 50; 

            MoveWindow(hGccPath, pad, pad, width - (pad*2), rowH, TRUE);
            
            int btnW = 120;
            MoveWindow(hFileCombo, pad, pad*2 + rowH, width - (pad*3) - btnW, rowH, TRUE);
            MoveWindow(hBtnBrowse, width - pad - btnW, pad*2 + rowH, btnW, rowH, TRUE);

            int thirdW = (width - (pad*4)) / 3;
            MoveWindow(hBtnEdit,    pad,               pad*3 + rowH*2, thirdW, rowH*1.5, TRUE);
            MoveWindow(hBtnCompile, pad*2 + thirdW,     pad*3 + rowH*2, thirdW, rowH*1.5, TRUE);
            MoveWindow(hBtnCopy,    pad*3 + thirdW*2,   pad*3 + rowH*2, thirdW, rowH*1.5, TRUE);

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
                ofn.lpstrFilter = "C Source Files\0*.c;*.cpp\0All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                if (GetOpenFileName(&ofn) == TRUE) {
                    LRESULT idx = SendMessage(hFileCombo, CB_FINDSTRINGEXACT, -1, (LPARAM)szFile);
                    if (idx == CB_ERR) { 
                        idx = SendMessage(hFileCombo, CB_ADDSTRING, 0, (LPARAM)szFile);
                    }
                    SendMessage(hFileCombo, CB_SETCURSEL, idx, 0);
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
                SaveSettings(); // Captures typed path, adds to dropdown, selects it, saves INI
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