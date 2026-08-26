/*
 * Compile instructions (GCC / MinGW):
 * gcc -Os -s -mwindows -o ProcManager.exe ProcManager.c -lcomctl32 -lcomdlg32
 *
 * Release to Public domain
 */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IDB_BROWSE       101
#define IDB_PASTEREPLACE 102
#define IDB_PASTE        103
#define IDB_UPDATE       104
#define IDB_SAVE         105
#define IDC_MRUCOMBO     106
#define IDL_LEFT         201
#define IDL_RIGHT        202
#define IDS_STATUS       301

typedef struct Chunk {
    int isProc;
    char name[256];
    char* text;
    struct Chunk* next;
} Chunk;

HWND hMainWindow;
HWND hComboMru;
HWND hBtnBrowse, hBtnPasteRep, hBtnPaste, hBtnUpdate, hBtnSave;
HWND hListLeft, hListRight;
HWND hStatus;

Chunk* g_LeftChunks = NULL;
Chunk* g_RightChunks = NULL;
char szCurrentFile[MAX_PATH] = {0};
char szIniFile[MAX_PATH] = {0};

char mruList[20][MAX_PATH];
int mruCount = 0;

char* my_strdup(const char* s) {
    char* d = (char*)malloc(strlen(s) + 1);
    if (d) strcpy(d, s);
    return d;
}

void SetStatus(const char* msg) {
    SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)msg);
}

void FreeChunks(Chunk** head) {
    Chunk* curr = *head;
    while (curr) {
        Chunk* next = curr->next;
        if (curr->text) free(curr->text);
        free(curr);
        curr = next;
    }
    *head = NULL;
}

void AddChunk(Chunk** head, Chunk** tail, int isProc, const char* name, const char* text) {
    if (!text || strlen(text) == 0) return;
    Chunk* c = (Chunk*)malloc(sizeof(Chunk));
    c->isProc = isProc;
    strncpy(c->name, name, 255);
    c->name[255] = '\0';
    c->text = my_strdup(text);
    c->next = NULL;
    if (*tail) {
        (*tail)->next = c;
        *tail = c;
    } else {
        *head = *tail = c;
    }
}

void ExtractMasmName(const char* line, char* procName) {
    const char* p = strstr(line, " PROC");
    if (!p) return;
    p--;
    while (p >= line && (*p == ' ' || *p == '\t')) p--;
    const char* end = p;
    while (p >= line && (*p != ' ' && *p != '\t')) p--;
    p++;
    int len = end - p + 1;
    if (len > 0 && len < 255) {
        strncpy(procName, p, len);
        procName[len] = '\0';
    }
}

int IsLikeCFunction(const char* line, char* procName) {
    if (strstr(line, "if ") || strstr(line, "if(") || strstr(line, "for ") || strstr(line, "for(") ||
        strstr(line, "while ") || strstr(line, "while(") || strstr(line, "switch ") ||
        line[0] == '#' || strstr(line, "//") == line) {
        
        if (strstr(line, "=>") && strchr(line, '=')) {
            const char* pEq = strchr(line, '=');
            const char* p = pEq - 1;
            while (p >= line && (*p == ' ' || *p == '\t')) p--;
            const char* endW = p;
            while (p >= line && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_')) p--;
            p++;
            int len = endW - p + 1;
            if (len > 0 && len < 255) {
                strncpy(procName, p, len);
                procName[len] = '\0';
                return 1;
            }
        }
        if (strstr(line, "=>") == NULL) return 0;
    }

    if (strstr(line, "function ")) {
        const char* pf = strstr(line, "function ") + 9;
        while (*pf == ' ' || *pf == '\t') pf++;
        const char* endW = pf;
        while ((*endW >= 'a' && *endW <= 'z') || (*endW >= 'A' && *endW <= 'Z') || (*endW >= '0' && *endW <= '9') || *endW == '_') endW++;
        int len = endW - pf;
        if (len > 0 && len < 255) {
            strncpy(procName, pf, len);
            procName[len] = '\0';
            return 1;
        }
    }

    const char* end = line + strlen(line) - 1;
    while (end > line && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) end--;
    if (*end == ';') return 0;

    char* pOpen = strchr(line, '(');
    char* pClose = strchr(line, ')');
    if (pOpen && pClose && pOpen < pClose) {
        const char* p = pOpen - 1;
        while (p >= line && (*p == ' ' || *p == '\t')) p--;
        const char* endWord = p;
        while (p >= line && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_')) p--;
        p++;
        int len = endWord - p + 1;
        if (len > 0 && len < 255) {
            strncpy(procName, p, len);
            procName[len] = '\0';
            if (strcmp(procName, "return") == 0 || strcmp(procName, "sizeof") == 0 || strcmp(procName, "if") == 0) return 0;
            return 1;
        }
    }
    return 0;
}

void UpdateBraces(const char* line, int* count, int* seen) {
    while (*line) {
        if (*line == '{') {
            (*count)++;
            *seen = 1;
        } else if (*line == '}') {
            (*count)--;
        }
        line++;
    }
}

Chunk* ParseTextToChunks(const char* text) {
    Chunk* head = NULL;
    Chunk* tail = NULL;
    int maxBuf = strlen(text) + 2;
    char* buf = (char*)malloc(maxBuf);
    buf[0] = '\0';
    int bufLen = 0;

    int state = 0; 
    char procName[256] = {0};
    const char* p = text;
    char line[2048];
    int lineLen = 0;
    int braceCount = 0;
    int seenBrace = 0;

    while (*p) {
        lineLen = 0;
        while (*p && *p != '\n' && lineLen < 2047) {
            line[lineLen++] = *p++;
        }
        if (*p == '\n') line[lineLen++] = *p++;
        line[lineLen] = '\0';

        if (state == 0) {
            if (strstr(line, " PROC ") || (lineLen > 5 && strstr(line, " PROC\r") == line + lineLen - 6) || (lineLen > 4 && strstr(line, " PROC\n") == line + lineLen - 6)) {
                if (bufLen > 0) {
                    AddChunk(&head, &tail, 0, "", buf);
                    buf[0] = '\0'; bufLen = 0;
                }
                state = 1;
                ExtractMasmName(line, procName);
                strcat(buf, line); bufLen += lineLen;
            } else {
                if (IsLikeCFunction(line, procName)) {
                    if (bufLen > 0) {
                        AddChunk(&head, &tail, 0, "", buf);
                        buf[0] = '\0'; bufLen = 0;
                    }
                    state = 2;
                    braceCount = 0;
                    seenBrace = 0;
                    strcat(buf, line); bufLen += lineLen;
                    UpdateBraces(line, &braceCount, &seenBrace);
                    if (seenBrace && braceCount == 0) {
                        AddChunk(&head, &tail, 1, procName, buf);
                        buf[0] = '\0'; bufLen = 0;
                        state = 0;
                    }
                } else {
                    strcat(buf, line); bufLen += lineLen;
                }
            }
        }
        else if (state == 1) { 
            strcat(buf, line); bufLen += lineLen;
            if (strstr(line, " ENDP")) {
                AddChunk(&head, &tail, 1, procName, buf);
                buf[0] = '\0'; bufLen = 0;
                state = 0;
            }
        }
        else if (state == 2) { 
            strcat(buf, line); bufLen += lineLen;
            UpdateBraces(line, &braceCount, &seenBrace);
            if (seenBrace && braceCount <= 0) {
                AddChunk(&head, &tail, 1, procName, buf);
                buf[0] = '\0'; bufLen = 0;
                state = 0;
            }
        }
    }
    if (bufLen > 0) {
        AddChunk(&head, &tail, (state > 0), procName, buf);
    }
    free(buf);
    return head;
}

void PopulateList(HWND hList, Chunk* head) {
    SendMessage(hList, LB_RESETCONTENT, 0, 0);
    Chunk* c = head;
    while (c) {
        if (c->isProc) {
            SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)c->name);
        }
        c = c->next;
    }
}

char* ReadClipboardText() {
    if (!OpenClipboard(hMainWindow)) return NULL;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return NULL; }
    char* pszText = (char*)GlobalLock(hData);
    if (!pszText) { CloseClipboard(); return NULL; }
    char* copy = my_strdup(pszText);
    GlobalUnlock(hData);
    CloseClipboard();
    return copy;
}

char* ReadFileText(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* buf = (char*)malloc(size + 1);
    fread(buf, 1, size, f);
    buf[size] = '\0';
    fclose(f);
    return buf;
}

void SaveMRU() {
    for (int i = 0; i < 20; i++) {
        char key[32];
        sprintf(key, "File%d", i + 1);
        if (i < mruCount) {
            WritePrivateProfileString("MRU", key, mruList[i], szIniFile);
        } else {
            WritePrivateProfileString("MRU", key, NULL, szIniFile);
        }
    }
}

void LoadMRU() {
    mruCount = 0;
    for (int i = 0; i < 20; i++) {
        char key[32];
        sprintf(key, "File%d", i + 1);
        char val[MAX_PATH];
        GetPrivateProfileString("MRU", key, "", val, MAX_PATH, szIniFile);
        if (val[0] != '\0') {
            strcpy(mruList[mruCount++], val);
        }
    }
}

void PopulateMRUCombo() {
    SendMessage(hComboMru, CB_RESETCONTENT, 0, 0);
    for (int i = 0; i < mruCount; i++) {
        SendMessage(hComboMru, CB_ADDSTRING, 0, (LPARAM)mruList[i]);
    }
    if (mruCount > 0) {
        SendMessage(hComboMru, CB_SETCURSEL, 0, 0);
    } else {
        SetWindowText(hComboMru, "");
    }
}

void AddMRU(const char* newPath) {
    if (!newPath || !*newPath) return;
    int foundIdx = -1;
    for (int i = 0; i < mruCount; i++) {
        if (_stricmp(mruList[i], newPath) == 0) { foundIdx = i; break; }
    }
    if (foundIdx != -1) {
        char temp[MAX_PATH];
        strcpy(temp, mruList[foundIdx]);
        for (int i = foundIdx; i > 0; i--) {
            strcpy(mruList[i], mruList[i - 1]);
        }
        strcpy(mruList[0], temp);
    } else {
        if (mruCount < 20) mruCount++;
        for (int i = mruCount - 1; i > 0; i--) {
            strcpy(mruList[i], mruList[i - 1]);
        }
        strcpy(mruList[0], newPath);
    }
    SaveMRU();
    PopulateMRUCombo();
}

void LoadFile(const char* path) {
    if (!path || !path[0]) return;

    char fullPath[MAX_PATH];
    if (!GetFullPathName(path, MAX_PATH, fullPath, NULL)) {
        strcpy(fullPath, path);
    }

    char* text = ReadFileText(fullPath);
    if (text) {
        strcpy(szCurrentFile, fullPath);
        FreeChunks(&g_LeftChunks);
        g_LeftChunks = ParseTextToChunks(text);
        PopulateList(hListLeft, g_LeftChunks);
        free(text);
        
        char msg[512];
        sprintf(msg, "Loaded: %s", szCurrentFile);
        SetStatus(msg);
        
        AddMRU(szCurrentFile);
    } else {
        char msg[512];
        sprintf(msg, "Failed to read file: %s", fullPath);
        SetStatus(msg);
    }
}

// --- NEW STATE RELOAD FUNCTIONS ---

void ReloadLeftList() {
    if (szCurrentFile[0] != '\0') {
        char* text = ReadFileText(szCurrentFile);
        if (text) {
            FreeChunks(&g_LeftChunks);
            g_LeftChunks = ParseTextToChunks(text);
            PopulateList(hListLeft, g_LeftChunks);
            free(text);
        }
    }
}

void ReloadRightList() {
    char* cb = ReadClipboardText();
    FreeChunks(&g_RightChunks);
    if (cb) {
        g_RightChunks = ParseTextToChunks(cb);
        free(cb);
    }
    PopulateList(hListRight, g_RightChunks);
}

// ----------------------------------

void OnBrowse() {
    ReloadRightList(); // Keep clipboard fresh
    OPENFILENAME ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWindow;
    ofn.lpstrFilter = "Source Files\0*.c;*.cpp;*.js;*.java;*.asm\0All Files\0*.*\0";
    ofn.lpstrFile = szCurrentFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileName(&ofn)) {
        LoadFile(szCurrentFile);
    }
}

void UpdateProcInLeft(Chunk* sourceChunk) {
    Chunk* l = g_LeftChunks;
    // Step 1: See if the procedure already exists
    while (l) {
        if (l->isProc && strcmp(l->name, sourceChunk->name) == 0) break;
        l = l->next;
    }

    if (l) {
        // Exists: Just update the text
        free(l->text);
        l->text = my_strdup(sourceChunk->text);
    } else {
        // Doesn't exist: Prepare the new chunk
        Chunk* nc = (Chunk*)malloc(sizeof(Chunk));
        nc->isProc = 1;
        strcpy(nc->name, sourceChunk->name);
        nc->text = my_strdup(sourceChunk->text);
        nc->next = NULL;

        // Step 2: Find insertion point (above main, WinMain, etc.)
        Chunk* curr = g_LeftChunks;
        Chunk* prev = NULL;
        int inserted = 0;

        while (curr) {
            if (curr->isProc && (
                strcmp(curr->name, "main") == 0 ||
                strcmp(curr->name, "WinMain") == 0 ||
                strcmp(curr->name, "wmain") == 0 ||
                strcmp(curr->name, "wWinMain") == 0
            )) {
                // Insert nc right before the entry point (curr)
                nc->next = curr;
                if (prev) {
                    prev->next = nc;
                } else {
                    g_LeftChunks = nc; // It was the very first chunk
                }
                inserted = 1;
                break;
            }
            prev = curr;
            curr = curr->next;
        }

        // Step 3: If no entry point was found at all, just append it to the end
        if (!inserted) {
            if (prev) {
                prev->next = nc;
            } else {
                g_LeftChunks = nc; // List was entirely empty
            }
        }
    }
}

void OnPasteAndReplace() {
    ReloadLeftList();
    ReloadRightList();

    if (!g_RightChunks) { SetStatus("Clipboard is empty or inaccessible."); return; }
    
    int replacedCount = 0;
    Chunk* tc = g_RightChunks;
    while (tc) {
        if (tc->isProc) {
            UpdateProcInLeft(tc);
            replacedCount++;
        }
        tc = tc->next;
    }
    
    PopulateList(hListLeft, g_LeftChunks);
    char msg[128];
    sprintf(msg, "Pasted and replaced/added %d procedures in the left list.", replacedCount);
    SetStatus(msg);
}

void OnPaste() {
    ReloadLeftList();
    ReloadRightList();
    SetStatus("Reloaded file and clipboard. Clipboard procedures in right list.");
}

void OnUpdate() {
    int count = SendMessage(hListRight, LB_GETSELCOUNT, 0, 0);
    if (count <= 0) {
        SetStatus("No procedures selected in the right list.");
        return;
    }

    // Must gather selections BEFORE reloading the right list, as reloading clears selection
    int* indices = (int*)malloc(count * sizeof(int));
    SendMessage(hListRight, LB_GETSELITEMS, count, (LPARAM)indices);

    char** selectedNames = (char**)malloc(count * sizeof(char*));
    for (int i = 0; i < count; i++) {
        selectedNames[i] = (char*)malloc(256);
        SendMessage(hListRight, LB_GETTEXT, indices[i], (LPARAM)selectedNames[i]);
    }
    free(indices);

    // Keep the current right chunks temporarily so we can copy from them
    Chunk* oldRightChunks = g_RightChunks;
    g_RightChunks = NULL;

    // Reload the file from disk (resets g_LeftChunks)
    ReloadLeftList();
    
    // Apply the previously selected chunks
    for (int i = 0; i < count; i++) {
        Chunk* r = oldRightChunks;
        while (r) {
            if (r->isProc && strcmp(r->name, selectedNames[i]) == 0) break;
            r = r->next;
        }
        if (r) UpdateProcInLeft(r);
        free(selectedNames[i]);
    }
    free(selectedNames);

    // Cleanup old right chunks and reload fresh clipboard
    FreeChunks(&oldRightChunks);
    ReloadRightList();

    PopulateList(hListLeft, g_LeftChunks);
    char msg[128];
    sprintf(msg, "Updated/added %d selected procedures to the left list.", count);
    SetStatus(msg);
}

void OnSave() {
    // We only reload the right list here. Reloading the left list BEFORE saving 
    // would overwrite any memory changes!
    ReloadRightList();

    if (szCurrentFile[0] == '\0') {
        OPENFILENAME ofn;
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hMainWindow;
        ofn.lpstrFilter = "All Files\0*.*\0";
        ofn.lpstrFile = szCurrentFile;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT;
        if (!GetSaveFileName(&ofn)) {
            SetStatus("Save cancelled.");
            return;
        }
    }
    FILE* f = fopen(szCurrentFile, "wb");
    if (f) {
        Chunk* c = g_LeftChunks;
        while (c) {
            fwrite(c->text, 1, strlen(c->text), f);
            c = c->next;
        }
        fclose(f);
        
        // NOW that we've successfully saved, reload the left list to confirm parity
        ReloadLeftList();

        char msg[512];
        sprintf(msg, "Saved changes to: %s", szCurrentFile);
        SetStatus(msg);
    } else {
        SetStatus("Failed to save file.");
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_BAR_CLASSES;
            InitCommonControlsEx(&icex);

            hComboMru    = CreateWindow("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | WS_VSCROLL, 0, 4, 250, 300, hwnd, (HMENU)IDC_MRUCOMBO, NULL, NULL);
            hBtnBrowse   = CreateWindow("BUTTON", "Browse", WS_CHILD | WS_VISIBLE, 250, 0, 70, 30, hwnd, (HMENU)IDB_BROWSE, NULL, NULL);
            hBtnPasteRep = CreateWindow("BUTTON", "Paste & Replace", WS_CHILD | WS_VISIBLE, 320, 0, 120, 30, hwnd, (HMENU)IDB_PASTEREPLACE, NULL, NULL);
            hBtnPaste    = CreateWindow("BUTTON", "Paste", WS_CHILD | WS_VISIBLE, 440, 0, 60, 30, hwnd, (HMENU)IDB_PASTE, NULL, NULL);
            hBtnUpdate   = CreateWindow("BUTTON", "Update", WS_CHILD | WS_VISIBLE, 500, 0, 60, 30, hwnd, (HMENU)IDB_UPDATE, NULL, NULL);
            hBtnSave     = CreateWindow("BUTTON", "Save", WS_CHILD | WS_VISIBLE, 560, 0, 60, 30, hwnd, (HMENU)IDB_SAVE, NULL, NULL);

            hListLeft  = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOTIFY, 0, 0, 0, 0, hwnd, (HMENU)IDL_LEFT, NULL, NULL);
            hListRight = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_EXTENDEDSEL, 0, 0, 0, 0, hwnd, (HMENU)IDL_RIGHT, NULL, NULL);
            
            hStatus = CreateWindowEx(0, STATUSCLASSNAME, NULL, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)IDS_STATUS, NULL, NULL);
            SetStatus("Ready. Release to Public domain.");
            
            LoadMRU();
            PopulateMRUCombo();
        } break;

        case WM_SIZE: {
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            SendMessage(hStatus, WM_SIZE, 0, 0);
            RECT rectStatus;
            GetWindowRect(hStatus, &rectStatus);
            int statusHeight = rectStatus.bottom - rectStatus.top;

            int listY = 32;
            int listH = height - listY - statusHeight;
            int halfW = width / 2;

            MoveWindow(hListLeft, 0, listY, halfW, listH, TRUE);
            MoveWindow(hListRight, halfW, listY, width - halfW, listH, TRUE);
        } break;

        case WM_COMMAND: {
            if (LOWORD(wParam) == IDC_MRUCOMBO && HIWORD(wParam) == CBN_SELENDOK) {
                int idx = SendMessage(hComboMru, CB_GETCURSEL, 0, 0);
                if (idx != CB_ERR) {
                    char buf[MAX_PATH];
                    SendMessage(hComboMru, CB_GETLBTEXT, idx, (LPARAM)buf);
                    LoadFile(buf);
                }
            }
            else if (LOWORD(wParam) == IDB_BROWSE) OnBrowse();
            else if (LOWORD(wParam) == IDB_PASTEREPLACE) OnPasteAndReplace();
            else if (LOWORD(wParam) == IDB_PASTE) OnPaste();
            else if (LOWORD(wParam) == IDB_UPDATE) OnUpdate();
            else if (LOWORD(wParam) == IDB_SAVE) OnSave();
        } break;

        case WM_DESTROY:
            FreeChunks(&g_LeftChunks);
            FreeChunks(&g_RightChunks);
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    GetModuleFileName(NULL, szIniFile, MAX_PATH);
    char* pExt = strrchr(szIniFile, '.');
    if (pExt) strcpy(pExt, ".ini");
    else strcat(szIniFile, ".ini");

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "ProcManagerClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!RegisterClass(&wc)) return 0;

    hMainWindow = CreateWindow("ProcManagerClass", "Procedure Manager", WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, NULL, NULL, hInstance, NULL);

    char* cmd = lpCmdLine;
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    if (*cmd == '"') {
        cmd++;
        char* p = cmd + strlen(cmd) - 1;
        while (p > cmd && (*p == ' ' || *p == '\t')) p--;
        if (*p == '"') *p = '\0';
    }
    
    if (strlen(cmd) > 0) {
        LoadFile(cmd);
    } else if (mruCount > 0) {
        LoadFile(mruList[0]);
    }

    // Auto-load clipboard contents on startup
    ReloadRightList();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN) {
            HWND hFocus = GetFocus();
            if (hFocus == hComboMru || GetParent(hFocus) == hComboMru) {
                char buf[MAX_PATH];
                GetWindowText(hComboMru, buf, MAX_PATH);
                LoadFile(buf);
                continue; 
            }
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}