/*
 * Start Menu Shortcut Creator
 *
 * This work is released into the PUBLIC DOMAIN.
 * You may use, modify, copy, or distribute this software without any restrictions.
 *
 * GCC Compilation Instructions:
 * gcc -Os -s -mwindows -o shortcutc.exe shortcutc.c -lole32 -lshell32 -lcomctl32 -lcomdlg32 -luuid
 */

#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <commctrl.h>
#include <commdlg.h>
#include <tchar.h>
#include <stdio.h>

#define ID_EDIT_TARGET   101
#define ID_BTN_BROWSE    102
#define ID_EDIT_NAME     103
#define ID_COMBO_FOLDER  104
#define ID_BTN_CREATE    105

// Recursively create directory paths if they do not exist
static void CreateDirectoryRecursive(const TCHAR *path) {
    TCHAR temp[MAX_PATH];
    TCHAR *p = NULL;
    size_t len;

    _sntprintf(temp, sizeof(temp) / sizeof(TCHAR), _T("%s"), path);
    len = _tcslen(temp);
    if (len == 0) return;

    if (temp[len - 1] == _T('\\') || temp[len - 1] == _T('/')) {
        temp[len - 1] = _T('\0');
    }

    for (p = temp + 1; *p; p++) {
        if (*p == _T('\\') || *p == _T('/')) {
            *p = _T('\0');
            CreateDirectory(temp, NULL);
            *p = _T('\\');
        }
    }
    CreateDirectory(temp, NULL);
}

// Check if file ends with .exe (case-insensitive)
static BOOL IsExeFile(const TCHAR *path) {
    const TCHAR *ext = _tcsrchr(path, _T('.'));
    return (ext && _tcsicmp(ext, _T(".exe")) == 0);
}

// Create shortcut using Win32 IShellLink COM interface
static BOOL CreateStartMenuShortcut(const TCHAR *targetPath, const TCHAR *subFolder, const TCHAR *shortcutName) {
    TCHAR programsPath[MAX_PATH];
    TCHAR targetFolder[MAX_PATH];
    TCHAR shortcutPath[MAX_PATH];
    TCHAR iconPath[MAX_PATH];
    int iconIndex = 0;

    if (FAILED(SHGetFolderPath(NULL, CSIDL_PROGRAMS, NULL, SHGFP_TYPE_CURRENT, programsPath))) {
        return FALSE;
    }

    // Build subfolder path under Programs
    if (subFolder && _tcslen(subFolder) > 0) {
        _sntprintf(targetFolder, MAX_PATH, _T("%s\\%s"), programsPath, subFolder);
    } else {
        _tcscpy(targetFolder, programsPath);
    }

    // Ensure folder structure exists
    CreateDirectoryRecursive(targetFolder);

    _sntprintf(shortcutPath, MAX_PATH, _T("%s\\%s.lnk"), targetFolder, shortcutName);

    // Determine icon: Target itself if EXE, generic system icon otherwise
    if (IsExeFile(targetPath)) {
        _tcscpy(iconPath, targetPath);
        iconIndex = 0;
    } else {
        GetSystemDirectory(iconPath, MAX_PATH);
        _tcscat(iconPath, _T("\\shell32.dll"));
        iconIndex = 0; // Default generic file/document icon
    }

    // Initialize COM and create shortcut
    HRESULT hr;
    IShellLink* psl = NULL;

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLink, (void**)&psl);
    if (SUCCEEDED(hr)) {
        IPersistFile* ppf = NULL;

        psl->lpVtbl->SetPath(psl, targetPath);

        // Set working directory to source file folder
        TCHAR workDir[MAX_PATH];
        _tcscpy(workDir, targetPath);
        TCHAR *lastSlash = _tcsrchr(workDir, _T('\\'));
        if (lastSlash) *lastSlash = _T('\0');
        psl->lpVtbl->SetWorkingDirectory(psl, workDir);

        psl->lpVtbl->SetIconLocation(psl, iconPath, iconIndex);

        hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void**)&ppf);
        if (SUCCEEDED(hr)) {
            WCHAR wsz[MAX_PATH];
#ifdef UNICODE
            _tcscpy(wsz, shortcutPath);
#else
            MultiByteToWideChar(CP_ACP, 0, shortcutPath, -1, wsz, MAX_PATH);
#endif
            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
            ppf->lpVtbl->Release(ppf);
        }
        psl->lpVtbl->Release(psl);
    }

    return SUCCEEDED(hr);
}

// Populate dropdown with existing folders in Start Menu Programs
static void PopulateFolderCombo(HWND hCombo) {
    TCHAR programsPath[MAX_PATH];
    if (FAILED(SHGetFolderPath(NULL, CSIDL_PROGRAMS, NULL, SHGFP_TYPE_CURRENT, programsPath))) {
        return;
    }

    // Top-level Programs folder
    SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)_T("(Root / Programs)"));

    TCHAR searchPath[MAX_PATH];
    _sntprintf(searchPath, MAX_PATH, _T("%s\\*"), programsPath);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                _tcscmp(fd.cFileName, _T(".")) != 0 &&
                _tcscmp(fd.cFileName, _T("..")) != 0) {
                SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)fd.cFileName);
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }

    SendMessage(hCombo, CB_SETCURSEL, 0, 0);
}

// Extract file name without extension for initial shortcut name
static void SetDefaultShortcutName(HWND hwnd, const TCHAR *filePath) {
    TCHAR name[MAX_PATH];
    const TCHAR *fileName = _tcsrchr(filePath, _T('\\'));
    fileName = (fileName) ? fileName + 1 : filePath;

    _tcscpy(name, fileName);
    TCHAR *ext = _tcsrchr(name, _T('.'));
    if (ext) *ext = _T('\0');

    SetDlgItemText(hwnd, ID_EDIT_NAME, name);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            // Labels and Inputs
            HWND hLbl1 = CreateWindow(_T("STATIC"), _T("Target File:"), WS_CHILD | WS_VISIBLE, 15, 18, 90, 20, hwnd, NULL, NULL, NULL);
            HWND hEditTarget = CreateWindowEx(WS_EX_CLIENTEDGE, _T("EDIT"), _T(""), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 15, 270, 23, hwnd, (HMENU)ID_EDIT_TARGET, NULL, NULL);
            HWND hBtnBrowse = CreateWindow(_T("BUTTON"), _T("Browse..."), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 390, 14, 80, 25, hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);

            HWND hLbl2 = CreateWindow(_T("STATIC"), _T("Shortcut Name:"), WS_CHILD | WS_VISIBLE, 15, 53, 90, 20, hwnd, NULL, NULL, NULL);
            HWND hEditName = CreateWindowEx(WS_EX_CLIENTEDGE, _T("EDIT"), _T(""), WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 110, 50, 360, 23, hwnd, (HMENU)ID_EDIT_NAME, NULL, NULL);

            HWND hLbl3 = CreateWindow(_T("STATIC"), _T("Folder:"), WS_CHILD | WS_VISIBLE, 15, 88, 90, 20, hwnd, NULL, NULL, NULL);
            // CBS_DROPDOWN allows selecting an existing item or typing a new custom folder
            HWND hComboFolder = CreateWindow(_T("COMBOBOX"), _T(""), WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, 110, 85, 360, 180, hwnd, (HMENU)ID_COMBO_FOLDER, NULL, NULL);

            HWND hBtnCreate = CreateWindow(_T("BUTTON"), _T("Create Shortcut"), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 175, 130, 140, 32, hwnd, (HMENU)ID_BTN_CREATE, NULL, NULL);

            // Set system UI font for clean modern look
            SendMessage(hLbl1, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hEditTarget, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hBtnBrowse, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hLbl2, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hEditName, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hLbl3, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hComboFolder, WM_SETFONT, (WPARAM)hFont, TRUE);
            SendMessage(hBtnCreate, WM_SETFONT, (WPARAM)hFont, TRUE);

            PopulateFolderCombo(hComboFolder);
            break;
        }

        case WM_COMMAND: {
            WORD id = LOWORD(wParam);
            if (id == ID_BTN_BROWSE) {
                OPENFILENAME ofn = {0};
                TCHAR szFile[MAX_PATH] = _T("");

                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile) / sizeof(TCHAR);
                ofn.lpstrFilter = _T("All Files (*.*)\0*.*\0Executables (*.exe)\0*.exe\0");
                ofn.nFilterIndex = 1;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

                if (GetOpenFileName(&ofn)) {
                    SetDlgItemText(hwnd, ID_EDIT_TARGET, szFile);
                    SetDefaultShortcutName(hwnd, szFile);
                }
            } 
            else if (id == ID_BTN_CREATE) {
                TCHAR szTarget[MAX_PATH] = _T("");
                TCHAR szName[MAX_PATH] = _T("");
                TCHAR szFolder[MAX_PATH] = _T("");

                GetDlgItemText(hwnd, ID_EDIT_TARGET, szTarget, MAX_PATH);
                GetDlgItemText(hwnd, ID_EDIT_NAME, szName, MAX_PATH);
                GetDlgItemText(hwnd, ID_COMBO_FOLDER, szFolder, MAX_PATH);

                if (_tcslen(szTarget) == 0) {
                    MessageBox(hwnd, _T("Please select or enter a target file."), _T("Error"), MB_ICONERROR);
                    break;
                }
                if (_tcslen(szName) == 0) {
                    MessageBox(hwnd, _T("Please enter a shortcut name."), _T("Error"), MB_ICONERROR);
                    break;
                }

                // If root placeholder selected, leave folder empty
                if (_tcscmp(szFolder, _T("(Root / Programs)")) == 0) {
                    szFolder[0] = _T('\0');
                }

                if (CreateStartMenuShortcut(szTarget, szFolder, szName)) {
                    MessageBox(hwnd, _T("Start Menu shortcut created successfully!"), _T("Success"), MB_ICONINFORMATION);
                } else {
                    MessageBox(hwnd, _T("Failed to create shortcut."), _T("Error"), MB_ICONERROR);
                }
            }
            break;
        }

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    CoInitialize(NULL);

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = _T("ShortcutCreatorClass");
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    HWND hwnd = CreateWindow(_T("ShortcutCreatorClass"), _T("Create Start Menu Shortcut"),
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             CW_USEDEFAULT, CW_USEDEFAULT, 500, 215,
                             NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // If file path passed as command line argument, pre-fill GUI inputs
    if (__argc > 1) {
        TCHAR szTarget[MAX_PATH];
#ifdef UNICODE
        MultiByteToWideChar(CP_ACP, 0, __argv[1], -1, szTarget, MAX_PATH);
#else
        _tcscpy(szTarget, __argv[1]);
#endif
        SetDlgItemText(hwnd, ID_EDIT_TARGET, szTarget);
        SetDefaultShortcutName(hwnd, szTarget);
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}