/* ============================================================================
 * C & Java Procedure Function Replacer - Replaces Functions with updated ones
 *
 * Compile instructions (GCC / MinGW):
 * gcc -Os -s -mwindows -o ProcManager.exe ProcManager.c -lcomctl32 -lcomdlg32 -lshell32
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shellapi.h>
#include <ctype.h>
#define IDB_BROWSE       101
#define IDB_PASTEREPLACE 102
#define IDB_PASTE        103
#define IDB_UPDATE       104
#define IDB_SAVE         105
#define IDC_MRUCOMBO     106
#define IDB_EDIT         107
#define IDB_COMPILE      108
#define IDB_COPYLEFT     109
#define IDB_DELETELEFT   110
#define IDB_ADDPROTO     111
#define IDL_LEFT         201
#define IDL_RIGHT        202
#define IDS_STATUS       301
#define TIMER_FILTER_LEFT  1001
#define TIMER_FILTER_RIGHT 1002
typedef enum {
    T_OTHER = 0,
    T_PROC = 1,
    T_PROTO = 2,
    T_VAR = 3,
    T_STRUCT = 4,
    T_DEFINE = 5
} ChunkType;

typedef struct Chunk {
    int isProc;      
    ChunkType type;  
    int isAdded;     
    int lineNum;
    char name[256];
    char* text;
    struct Chunk* next;
} Chunk;

typedef struct {
    Chunk* head;
    Chunk* tail;
} ProcGroup;

void SetStatus(const char* msg);
void PopulateList(HWND hList, Chunk* head);
void EnsureCRLF(Chunk* c);
void MoveLeftChunks(int* selIndices, int selCount, int dropIndex);
int MoveAddedAbove(const char* targetName);

LRESULT CALLBACK LeftListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK RightListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

HWND hMainWindow;
HWND hComboMru;
HWND hBtnBrowse, hBtnPasteRep, hBtnPaste, hBtnUpdate, hBtnSave, hBtnEdit, hBtnCompile, hBtnCopyLeft, hBtnDeleteLeft, hBtnAddProto;
HWND hListLeft, hListRight;
HWND hStatus;

WNDPROC OldListProc;
WNDPROC OldRightListProc;

Chunk* g_LeftChunks = NULL;
Chunk* g_RightChunks = NULL;
char szCurrentFile[MAX_PATH] = {0};
char szIniFile[MAX_PATH] = {0};

char g_FilterLeft[256] = {0};
char g_FilterRight[256] = {0};

char mruList[20][MAX_PATH];
int mruCount = 0;

// Case-insensitive substring search
const char* str_istr(const char* haystack, const char* needle) {
    if (!*needle) return haystack;
    for (; *haystack; ++haystack) {
        if (toupper((unsigned char)*haystack) == toupper((unsigned char)*needle)) {
            const char *h = haystack, *n = needle;
            while (*h && *n && toupper((unsigned char)*h) == toupper((unsigned char)*n)) {
                ++h; ++n;
            }
            if (!*n) return haystack;
        }
    }
    return NULL;
}

void EnsureCRLF(Chunk* c) {
    if (!c || !c->text) return;
    int len = strlen(c->text);
    if (len == 0) return;
    
    if (c->text[len - 1] != '\n') {
        char* newText = (char*)malloc(len + 3); 
        strcpy(newText, c->text);
        strcat(newText, "\r\n");
        free(c->text);
        c->text = newText;
    }
}

const char* GetRealName(const char* displayName) {
    static char buffer[256];
    strncpy(buffer, displayName, 255);
    buffer[255] = '\0';
    
    char* tab = strchr(buffer, '\t');
    if (tab) *tab = '\0';
    
    char* p = buffer;
    if (*p == '+') p++;
    if (strncmp(p, "[DEF] ", 6) == 0 || strncmp(p, "[STR] ", 6) == 0 ||
        strncmp(p, "[VAR] ", 6) == 0 || strncmp(p, "[PRO] ", 6) == 0) {
        p += 6;
    }
    return p;
}

void CleanBlock(const char* in, char* out) {
    int i = 0, j = 0;
    int inSingle = 0, inMulti = 0, inStr = 0, inChar = 0;
    while(in[i]) {
        if(!inStr && !inChar && !inSingle && !inMulti) {
            if(in[i] == '/' && in[i+1] == '/') { inSingle = 1; i+=2; continue; }
            if(in[i] == '/' && in[i+1] == '*') { inMulti = 1; i+=2; continue; }
            if(in[i] == '"') { inStr = 1; out[j++] = in[i++]; continue; }
            if(in[i] == '\'') { inChar = 1; out[j++] = in[i++]; continue; }
            out[j++] = in[i++];
        } else if(inSingle) {
            if(in[i] == '\n') { inSingle = 0; out[j++] = '\n'; }
            i++;
        } else if(inMulti) {
            if(in[i] == '*' && in[i+1] == '/') { inMulti = 0; i+=2; }
            else i++;
        } else if(inStr) {
            if(in[i] == '\\' && in[i+1]) { i += 2; }
            else if(in[i] == '"') { inStr = 0; out[j++] = in[i++]; }
            else { i++; }
        } else if(inChar) {
            if(in[i] == '\\' && in[i+1]) { i += 2; }
            else if(in[i] == '\'') { inChar = 0; out[j++] = in[i++]; }
            else { i++; }
        }
    }
    out[j] = '\0';
}
char* my_strdup(const char* s) {
    char* d = (char*)malloc(strlen(s) + 1);
    if (d) strcpy(d, s);
    return d;
}

char* safe_strdup_newline(const char* s) {
    int len = strlen(s);
    int needsNewline = (len > 0 && s[len-1] != '\n');
    char* d = (char*)malloc(len + (needsNewline ? 3 : 1));
    if (d) {
        strcpy(d, s);
        if (needsNewline) strcat(d, "\r\n");
    }
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

void ClassifyChunk(const char* buf, ChunkType* outType, char* outName, int* isProc) {
    *outType = T_OTHER;
    outName[0] = '\0';
    *isProc = 0;

    int len = strlen(buf);
    char* clean = (char*)malloc(len + 1);
    CleanBlock(buf, clean);

    char* p = clean;
    while(*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;

    char* pOpen = strchr(p, '(');
    char* pBrace = strchr(p, '{');
    char* pSemi = strchr(p, ';');
    char* pEq = strchr(p, '=');
    
    // Updated isStructStart for Java class/interface support
    int isStructStart = (strncmp(p, "typedef struct", 14) == 0 || strncmp(p, "struct ", 7) == 0 ||
                         strncmp(p, "enum ", 5) == 0 || strncmp(p, "union ", 6) == 0 ||
                         strncmp(p, "typedef enum", 12) == 0 || strncmp(p, "typedef union", 13) == 0 ||
                         strncmp(p, "class ", 6) == 0 || strstr(p, " class ") != NULL || strstr(p, "\nclass ") != NULL ||
                         strncmp(p, "interface ", 10) == 0 || strstr(p, " interface ") != NULL || strstr(p, "\ninterface ") != NULL ||
                         strncmp(p, "@interface ", 11) == 0);

    if(strncmp(p, "#define", 7) == 0) {
        *outType = T_DEFINE;
        *isProc = 1;
        char* n = p + 7;
        while(*n == ' ' || *n == '\t') n++;
        int i=0;
        while(n[i] && (isalnum((unsigned char)n[i]) || n[i] == '_') && i<254) { outName[i] = n[i]; i++; }
        outName[i]='\0';
    } else if(isStructStart && (!pOpen || (pBrace && pBrace < pOpen))) {
        *outType = T_STRUCT;
        *isProc = 1;
        char* search = strstr(p, "struct ");
        if(!search) search = strstr(p, "enum ");
        if(!search) search = strstr(p, "union ");
        if(!search) search = strstr(p, "class ");
        if(!search) search = strstr(p, "interface ");
        if(!search) search = strstr(p, "@interface ");
        if(search) {
            while (*search && *search != ' ' && *search != '\t' && *search != '\n' && *search != '\r') search++;
            while(*search == ' ' || *search == '\t' || *search == '\r' || *search == '\n') search++;
            int i=0;
            while(search[i] && (isalnum((unsigned char)search[i]) || search[i] == '_') && i<254) { outName[i] = search[i]; i++; }
            outName[i]='\0';
        }
        if(outName[0] == '\0' && pBrace) {
            char* lastBrace = strrchr(p, '}');
            if(lastBrace) {
                char* after = lastBrace + 1;
                while(*after == ' ' || *after == '\t' || *after == '\r' || *after == '\n') after++;
                int i=0;
                while(after[i] && (isalnum((unsigned char)after[i]) || after[i] == '_') && i<254) { outName[i] = after[i]; i++; }
                outName[i]='\0';
            }
        }
        if(outName[0] == '\0') strcpy(outName, "unnamed_struct");
    } else if(pBrace && pOpen && pOpen < pBrace) {
        *outType = T_PROC;
        *isProc = 1;
        char* n = pOpen - 1;
        while(n > p && (*n == ' ' || *n == '\t' || *n == '\n' || *n == '\r')) n--;
        char* end = n;
        while(n >= p && (isalnum((unsigned char)*n) || *n == '_')) n--;
        n++;
        int slen = end - n + 1;
        if(slen>0 && slen<255) { strncpy(outName, n, slen); outName[slen]='\0'; }
    } else if(pSemi && pOpen && pOpen < pSemi && !pBrace) {
        *outType = T_PROTO;
        *isProc = 1;
        char* n = pOpen - 1;
        while(n > p && (*n == ' ' || *n == '\t' || *n == '\n' || *n == '\r')) n--;
        char* end = n;
        while(n >= p && (isalnum((unsigned char)*n) || *n == '_')) n--;
        n++;
        int slen = end - n + 1;
        if(slen>0 && slen<255) { strncpy(outName, n, slen); outName[slen]='\0'; }
    } else if(pSemi && (!pBrace || (pEq && pEq < pBrace))) {
        if(strncmp(p, "return ", 7) != 0 && strncmp(p, "goto ", 5) != 0 && strncmp(p, "break;", 6) != 0 && strncmp(p, "continue;", 9) != 0) {
            *outType = T_VAR;
            *isProc = 1;
            char* semi = pSemi;
            char* n = semi - 1;
            char* eq = pEq;
            if (eq && eq < semi) n = eq - 1;

            while(n > p && (*n == ' ' || *n == '\t' || *n == '\n' || *n == '\r')) n--;
            
            // Skip backwards over potential Java array brackets
            while (n > p && *n == ']') {
                while (n > p && *n != '[') n--;
                if (n > p) n--;
                while(n > p && (*n == ' ' || *n == '\t' || *n == '\n' || *n == '\r')) n--;
            }

            char* end = n;
            while(n >= p && (isalnum((unsigned char)*n) || *n == '_')) n--;
            n++;
            int slen = end - n + 1;
            if(slen>0 && slen<255) { strncpy(outName, n, slen); outName[slen]='\0'; }
        }
    }
    free(clean);
}
void ExtractAndAddChunk(Chunk** head, Chunk** tail, const char* fullText, int start, int end) {
    if(start >= end) return;
    while(start < end && (fullText[start] == ' ' || fullText[start] == '\t' || fullText[start] == '\r' || fullText[start] == '\n')) start++;
    if(start >= end) return;

    int lineNum = 1;
    for(int i = 0; i < start; i++) {
        if (fullText[i] == '\r' && fullText[i+1] == '\n') {
            lineNum++;
            i++; 
        } else if (fullText[i] == '\n') {
            lineNum++;
        }
    }

    int len = end - start;
    char* buf = (char*)malloc(len + 1);
    strncpy(buf, fullText + start, len);
    buf[len] = '\0';

    ChunkType type;
    char name[256];
    int isProc;
    ClassifyChunk(buf, &type, name, &isProc);

    Chunk* c = (Chunk*)malloc(sizeof(Chunk));
    c->isProc = isProc;
    c->type = type;
    c->isAdded = 0;
    c->lineNum = lineNum;
    strncpy(c->name, name, 255);
    c->name[255] = '\0';
    c->text = buf;
    c->next = NULL;

    if(*tail) { (*tail)->next = c; *tail = c; }
    else { *head = *tail = c; }
}

Chunk* ParseTextToChunks(const char* text) {
    Chunk* head = NULL;
    Chunk* tail = NULL;

    int len = strlen(text);
    int i = 0, blockStart = 0, braceLevel = 0;
    int inSingle = 0, inMulti = 0, inStr = 0, inChar = 0;
    int inPreproc = 0;
    int sawParenBeforeBrace = 0;
    int baseBraceLevel = 0;
    int isJava = 0;
    
    if (szCurrentFile[0]) {
        size_t fLen = strlen(szCurrentFile);
        if (fLen > 5 && _stricmp(szCurrentFile + fLen - 5, ".java") == 0) isJava = 1;
    }

    while(i < len) {
        if(!inStr && !inChar && !inSingle && !inMulti) {
            if(text[i] == '/' && text[i+1] == '/') { inSingle = 1; i+=2; continue; }
            if(text[i] == '/' && text[i+1] == '*') { inMulti = 1; i+=2; continue; }
            if(text[i] == '"') { inStr = 1; i++; continue; }
            if(text[i] == '\'') { inChar = 1; i++; continue; }

            if(text[i] == '#' && braceLevel == 0 && !inPreproc) {
                int isStart = 1;
                for(int k = i-1; k >= blockStart; k--) {
                    if(text[k] == '\n') break;
                    if(text[k] != ' ' && text[k] != '\t') { isStart = 0; break; }
                }
                if(isStart) inPreproc = 1;
            }

            if(inPreproc) {
                if(text[i] == '\n') {
                    if(i > 0 && text[i-1] != '\\' && (i < 2 || text[i-2] != '\\' || text[i-1] != '\r')) {
                        inPreproc = 0;
                        int endIdx = i + 1;
                        ExtractAndAddChunk(&head, &tail, text, blockStart, endIdx);
                        blockStart = endIdx;
                        sawParenBeforeBrace = 0;
                    }
                }
            } else {
                if(text[i] == '(' && braceLevel == baseBraceLevel) {
                    sawParenBeforeBrace = 1;
                } else if(text[i] == '{') {
                    if (braceLevel == 0) {
                        int isWrapper = 0;
                        char* block = (char*)malloc(i - blockStart + 1);
                        strncpy(block, text + blockStart, i - blockStart);
                        block[i - blockStart] = '\0';
                        if (strstr(block, "class ") || strstr(block, "interface ") || strstr(block, "@interface ") || (isJava && strstr(block, "enum "))) {
                            isWrapper = 1;
                        }
                        free(block);

                        if (isWrapper) {
                            braceLevel++;
                            int endIdx = i + 1;
                            ExtractAndAddChunk(&head, &tail, text, blockStart, endIdx);
                            blockStart = endIdx;
                            baseBraceLevel = 1;
                            sawParenBeforeBrace = 0;
                            i = endIdx - 1;
                            i++; 
                            continue;
                        }
                    }
                    braceLevel++;
                } else if(text[i] == '}') {
                    braceLevel--;
                    if(braceLevel == baseBraceLevel) {
                        int endIdx = i + 1;
                        if(!sawParenBeforeBrace && baseBraceLevel == 0) {
                            while(endIdx < len && text[endIdx] != ';') endIdx++;
                            if(endIdx < len && text[endIdx] == ';') endIdx++;
                        } else {
                            while(endIdx < len && (text[endIdx] == ' ' || text[endIdx] == '\t' || text[endIdx] == '\r' || text[endIdx] == '\n')) endIdx++;
                            if(endIdx < len && text[endIdx] == ';') endIdx++;
                        }
                        while(endIdx < len && (text[endIdx] == '\r' || text[endIdx] == '\n')) endIdx++;

                        ExtractAndAddChunk(&head, &tail, text, blockStart, endIdx);
                        blockStart = endIdx;
                        sawParenBeforeBrace = 0;
                        i = endIdx - 1;
                    } else if (braceLevel == 0 && baseBraceLevel == 1) {
                        // Just closed the class wrapper block itself
                        int endIdx = i + 1;
                        while(endIdx < len && (text[endIdx] == '\r' || text[endIdx] == '\n')) endIdx++;
                        ExtractAndAddChunk(&head, &tail, text, blockStart, endIdx);
                        blockStart = endIdx;
                        baseBraceLevel = 0;
                        sawParenBeforeBrace = 0;
                        i = endIdx - 1;
                    }
                } else if(text[i] == ';' && braceLevel == baseBraceLevel) {
                    int endIdx = i + 1;
                    while(endIdx < len && (text[endIdx] == '\r' || text[endIdx] == '\n' || text[endIdx] == ' ' || text[endIdx] == '\t')) endIdx++;
                    ExtractAndAddChunk(&head, &tail, text, blockStart, endIdx);
                    blockStart = endIdx;
                    sawParenBeforeBrace = 0;
                    i = endIdx - 1;
                }
            }
        } else if(inSingle) {
            if(text[i] == '\n') inSingle = 0;
        } else if(inMulti) {
            if(text[i] == '*' && text[i+1] == '/') { inMulti = 0; i++; }
        } else if(inStr) {
            if(text[i] == '\\' && text[i+1]) i++;
            else if(text[i] == '"') inStr = 0;
        } else if(inChar) {
            if(text[i] == '\\' && text[i+1]) i++;
            else if(text[i] == '\'') inChar = 0;
        }
        i++;
    }
    if(blockStart < len) ExtractAndAddChunk(&head, &tail, text, blockStart, len);
    return head;
}

void PopulateList(HWND hList, Chunk* head) {
    const char* filter = (hList == hListLeft) ? g_FilterLeft : g_FilterRight;
    
    SendMessage(hList, WM_SETREDRAW, FALSE, 0);
    SendMessage(hList, LB_RESETCONTENT, 0, 0);
    
    Chunk* c = head;
    while (c) {
        if (c->isProc) {
            if (filter && filter[0] != '\0') {
                if (!str_istr(c->name, filter)) {
                    c = c->next;
                    continue;
                }
            }

            char display[256] = {0};
            char prefix[16] = {0};

            if (c->type == T_DEFINE) strcpy(prefix, "[DEF] ");
            else if (c->type == T_STRUCT) strcpy(prefix, "[STR] ");
            else if (c->type == T_VAR) strcpy(prefix, "[VAR] ");
            else if (c->type == T_PROTO) strcpy(prefix, "[PRO] ");

            char namePart[256] = {0};
            if (c->isAdded) {
                sprintf(namePart, "+%s%.200s", prefix, c->name);
            } else {
                sprintf(namePart, "%s%.200s", prefix, c->name);
            }
            
            if (hList == hListLeft && c->lineNum > 0) {
                sprintf(display, "%s\t%d", namePart, c->lineNum);
            } else {
                strcpy(display, namePart);
            }
            SendMessage(hList, LB_ADDSTRING, 0, (LPARAM)display);
        }
        c = c->next;
    }
    
    SendMessage(hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hList, NULL, TRUE);
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
        HWND hComboEdit = FindWindowEx(hComboMru, NULL, "Edit", NULL);
        if (hComboEdit) {
            int len = GetWindowTextLength(hComboEdit);
            PostMessage(hComboEdit, EM_SETSEL, len, len);
        }
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

    char dirPath[MAX_PATH];
    strcpy(dirPath, fullPath);
    char* lastSlash = strrchr(dirPath, '\\');
    char* fwdSlash = strrchr(dirPath, '/');
    if (fwdSlash > lastSlash) lastSlash = fwdSlash;
    if (lastSlash) {
        *lastSlash = '\0';
        SetCurrentDirectory(dirPath);
    }

    char* text = ReadFileText(fullPath);
    if (text) {
        g_FilterLeft[0] = '\0'; 
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

void OnBrowse() {
    ReloadRightList(); 
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

int UpdateProcInLeft(Chunk* sourceChunk) {
    Chunk* l = g_LeftChunks;
    while (l) {
        if (l->isProc && l->type == sourceChunk->type && strcmp(l->name, sourceChunk->name) == 0) break;
        l = l->next;
    }

    if (l) {
        if (strcmp(l->text, sourceChunk->text) == 0) return 0; 
        free(l->text);
        l->text = safe_strdup_newline(sourceChunk->text);
        return 1;
    } else {
        Chunk* nc = (Chunk*)malloc(sizeof(Chunk));
        nc->isProc = sourceChunk->isProc;
        nc->type = sourceChunk->type;
        nc->isAdded = 1; 
        nc->lineNum = 0;
        strcpy(nc->name, sourceChunk->name);
        nc->text = safe_strdup_newline(sourceChunk->text);
        nc->next = NULL;
        EnsureCRLF(nc);

        if (nc->type == T_PROC) {
            char cNew = nc->name[0];
            if (cNew >= 'A' && cNew <= 'Z') cNew += 32;

            Chunk* curr = g_LeftChunks;
            Chunk* prev = NULL;
            int inserted = 0;

            while(curr && curr->type != T_PROC) { prev = curr; curr = curr->next; }
            Chunk* groupStart = curr;
            Chunk* groupPrev = prev;

            while (curr) {
                if (curr->type == T_PROC) {
                    char cCurr = curr->name[0];
                    if (cCurr >= 'A' && cCurr <= 'Z') cCurr += 32;

                    if (cCurr >= cNew) {
                        nc->next = groupStart;
                        if (groupPrev) groupPrev->next = nc;
                        else g_LeftChunks = nc; 
                        inserted = 1; break;
                    }
                    groupPrev = curr;
                    groupStart = curr->next;
                }
                prev = curr;
                curr = curr->next;
            }

            if (!inserted) {
                Chunk* tail = g_LeftChunks;
                Chunk* pPrev = NULL;
                if (tail) { 
                    while(tail->next) { pPrev = tail; tail = tail->next; }
                    
                    int isJustBrace = 0;
                    char* t = tail->text;
                    if (t) {
                        while (*t && (*t == ' ' || *t == '\t' || *t == '\r' || *t == '\n')) t++;
                        if (*t == '}' && *(t+1) == '\0') isJustBrace = 1;
                        else if (*t == '}' && (*(t+1) == '\r' || *(t+1) == '\n')) isJustBrace = 1;
                    }
                    
                    if (isJustBrace && pPrev) {
                        nc->next = tail;
                        pPrev->next = nc;
                    } else {
                        tail->next = nc; 
                    }
                } 
                else g_LeftChunks = nc;
            }
        } else {
            Chunk* curr = g_LeftChunks;
            Chunk* lastOfKind = NULL;
            while (curr) {
                if (curr->type == nc->type) lastOfKind = curr;
                curr = curr->next;
            }

            if (lastOfKind) {
                nc->next = lastOfKind->next;
                lastOfKind->next = nc;
            } else {
                Chunk* p = g_LeftChunks;
                Chunk* prev = NULL;
                while(p && p->type != T_PROC) { prev = p; p = p->next; }
                if(prev) { nc->next = prev->next; prev->next = nc; }
                else { nc->next = g_LeftChunks; g_LeftChunks = nc; }
            }
        }
        return 2;
    }
}

void OnPasteAndReplace() {
    ReloadLeftList();
    ReloadRightList();

    if (!g_RightChunks) { SetStatus("Clipboard is empty or inaccessible."); return; }
    
    int addedCount = 0, updatedCount = 0;
    char addedNames[1024] = {0};
    char updatedNames[1024] = {0};

    Chunk* tc = g_RightChunks;
    while (tc) {
        if (tc->isProc) {
            int res = UpdateProcInLeft(tc);
            if (res == 1) {
                updatedCount++;
                if (strlen(updatedNames) < 800) { strcat(updatedNames, tc->name); strcat(updatedNames, " "); }
            } else if (res == 2) {
                addedCount++;
                if (strlen(addedNames) < 800) { strcat(addedNames, tc->name); strcat(addedNames, " "); }
            }
        }
        tc = tc->next;
    }
    
    PopulateList(hListLeft, g_LeftChunks);
    
    if (addedCount == 0 && updatedCount == 0) {
        SetStatus("No changes (content identical to current source).");
    } else {
        char msg[1024];
        sprintf(msg, "Changed! Added %d [%s] | Updated %d [%s]", addedCount, addedNames, updatedCount, updatedNames);
        SetStatus(msg);
    }
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

    int* indices = (int*)malloc(count * sizeof(int));
    SendMessage(hListRight, LB_GETSELITEMS, count, (LPARAM)indices);

    char** selectedNames = (char**)malloc(count * sizeof(char*));
    for (int i = 0; i < count; i++) {
        selectedNames[i] = (char*)malloc(256);
        SendMessage(hListRight, LB_GETTEXT, indices[i], (LPARAM)selectedNames[i]);
    }
    free(indices);

    ReloadLeftList();
    ReloadRightList();
    
    int addedCount = 0, updatedCount = 0;
    char addedNames[1024] = {0};
    char updatedNames[1024] = {0};

    for (int i = 0; i < count; i++) {
        const char* realName = GetRealName(selectedNames[i]);
        Chunk* r = g_RightChunks;
        while (r) {
            if (r->isProc && strcmp(r->name, realName) == 0) break;
            r = r->next;
        }
        if (r) {
            int res = UpdateProcInLeft(r);
            if (res == 1) {
                updatedCount++;
                if (strlen(updatedNames) < 800) { strcat(updatedNames, r->name); strcat(updatedNames, " "); }
            } else if (res == 2) {
                addedCount++;
                if (strlen(addedNames) < 800) { strcat(addedNames, r->name); strcat(addedNames, " "); }
            }
        }
        free(selectedNames[i]);
    }
    free(selectedNames);

    PopulateList(hListLeft, g_LeftChunks);
    
    if (addedCount == 0 && updatedCount == 0) {
        SetStatus("No changes (selected content identical to current source).");
    } else {
        char msg[1024];
        sprintf(msg, "Changed! Added %d [%s] | Updated %d [%s]", addedCount, addedNames, updatedCount, updatedNames);
        SetStatus(msg);
    }
}

void OnSave() {
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
        
        int addedCount = 0;
        char* addedNames[1024];
        c = g_LeftChunks;
        while(c) {
            if (c->isProc && c->isAdded && addedCount < 1024) {
                addedNames[addedCount++] = my_strdup(c->name);
            }
            c = c->next;
        }

        ReloadLeftList();

        c = g_LeftChunks;
        while(c) {
            if (c->isProc) {
                for (int i = 0; i < addedCount; i++) {
                    if (strcmp(c->name, addedNames[i]) == 0) {
                        c->isAdded = 1;
                        break;
                    }
                }
            }
            c = c->next;
        }
        
        for (int i = 0; i < addedCount; i++) free(addedNames[i]);
        PopulateList(hListLeft, g_LeftChunks); 

        char msg[512];
        sprintf(msg, "Saved changes to: %s", szCurrentFile);
        SetStatus(msg);
    } else {
        SetStatus("Failed to save file.");
    }
}

void OnEdit() {
    if (szCurrentFile[0] == '\0') {
        SetStatus("No file loaded to edit.");
        return;
    }
    ShellExecute(hMainWindow, "open", "notepad.exe", szCurrentFile, NULL, SW_SHOW);
    SetStatus("Opened current file in Notepad.");
}

void OnCompile() {
    if (szCurrentFile[0] == '\0') {
        SetStatus("No file loaded to compile.");
        return;
    }
    
    FILE* f = fopen(szCurrentFile, "rt");
    if (!f) {
        SetStatus("Failed to read file for compile command scan.");
        return;
    }

    char line[1024];
    char cmd[1024] = {0};
    int linesRead = 0;
    
    while (fgets(line, sizeof(line), f) && linesRead < 40) {
        char* p = strstr(line, "gcc ");
        if (!p) p = strstr(line, "wcl ");
        if (!p) p = strstr(line, "wcl386 ");
        
        if (p) {
            char* endComm = strstr(p, "*/");
            if (endComm) *endComm = '\0';
            
            char* nl = strpbrk(p, "\r\n");
            if (nl) *nl = '\0';
            
            strcpy(cmd, p);
            break;
        }
        linesRead++;
    }
    fclose(f);

    if (cmd[0] != '\0') {
        char msg[1024];
        sprintf(msg, "Compiling: %s", cmd);
        SetStatus(msg);
        
        char sysCmd[1024];
        sprintf(sysCmd, "cmd.exe /c \"%s || pause\"", cmd);
        system(sysCmd);
        
        SetStatus("Compilation command finished.");
    } else {
        SetStatus("Error: Could not find gcc, wcl, or wcl386 string in the first 40 lines.");
    }
}

void OnCopyLeft() {
    int count = SendMessage(hListLeft, LB_GETSELCOUNT, 0, 0);
    if (count <= 0) {
        SetStatus("No procedures selected in the left list.");
        return;
    }

    int* indices = (int*)malloc(count * sizeof(int));
    SendMessage(hListLeft, LB_GETSELITEMS, count, (LPARAM)indices);

    int totalLen = 0;
    char** selectedNames = (char**)malloc(count * sizeof(char*));
    
    for (int i = 0; i < count; i++) {
        selectedNames[i] = (char*)malloc(256);
        SendMessage(hListLeft, LB_GETTEXT, indices[i], (LPARAM)selectedNames[i]);
        
        const char* matchName = GetRealName(selectedNames[i]);
        
        Chunk* l = g_LeftChunks;
        while (l) {
            if (l->isProc && strcmp(l->name, matchName) == 0) {
                totalLen += strlen(l->text) + 4; 
                break;
            }
            l = l->next;
        }
    }

    if (totalLen > 0) {
        char* clipBuf = (char*)malloc(totalLen + 1);
        clipBuf[0] = '\0';

        for (int i = 0; i < count; i++) {
            const char* matchName = GetRealName(selectedNames[i]);
            
            Chunk* l = g_LeftChunks;
            while (l) {
                if (l->isProc && strcmp(l->name, matchName) == 0) {
                    strcat(clipBuf, l->text);
                    if (i < count - 1) {
                        strcat(clipBuf, "\r\n\r\n");
                    }
                    break;
                }
                l = l->next;
            }
            free(selectedNames[i]);
        }
        
        if (OpenClipboard(hMainWindow)) {
            EmptyClipboard();
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(clipBuf) + 1);
            if (hMem) {
                memcpy(GlobalLock(hMem), clipBuf, strlen(clipBuf) + 1);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
                
                char msg[256];
                sprintf(msg, "Copied %d procedures to clipboard.", count);
                SetStatus(msg);
            }
            CloseClipboard();
        }
        free(clipBuf);
    }
    
    free(selectedNames);
    free(indices);
}

void OnDeleteLeft() {
    int count = SendMessage(hListLeft, LB_GETSELCOUNT, 0, 0);
    if (count <= 0) {
        SetStatus("No procedures selected to delete.");
        return;
    }

    int* indices = (int*)malloc(count * sizeof(int));
    SendMessage(hListLeft, LB_GETSELITEMS, count, (LPARAM)indices);

    char** selectedNames = (char**)malloc(count * sizeof(char*));
    for (int i = 0; i < count; i++) {
        selectedNames[i] = (char*)malloc(256);
        SendMessage(hListLeft, LB_GETTEXT, indices[i], (LPARAM)selectedNames[i]);
    }
    free(indices);

    int deletedCount = 0;
    for (int i = 0; i < count; i++) {
        const char* matchName = GetRealName(selectedNames[i]);

        Chunk* curr = g_LeftChunks;
        Chunk* prev = NULL;

        while (curr) {
            if (curr->isProc && strcmp(curr->name, matchName) == 0) {
                if (prev) {
                    prev->next = curr->next;
                } else {
                    g_LeftChunks = curr->next;
                }
                
                Chunk* toDelete = curr;
                curr = curr->next;
                free(toDelete->text);
                free(toDelete);
                deletedCount++;
                break; 
            } else {
                prev = curr;
                curr = curr->next;
            }
        }
        free(selectedNames[i]);
    }
    free(selectedNames);

    PopulateList(hListLeft, g_LeftChunks);

    char msg[256];
    sprintf(msg, "Deleted %d procedures.", deletedCount);
    SetStatus(msg);
}

char* CreatePrototypeFromFunc(const char* funcText) {
    int len = strlen(funcText);
    char* proto = (char*)malloc(len + 3);
    int i = 0, j = 0;
    int inSingle = 0, inMulti = 0, inStr = 0, inChar = 0;
    
    while (i < len) {
        if (!inStr && !inChar && !inSingle && !inMulti) {
            if (funcText[i] == '/' && funcText[i+1] == '/') { inSingle = 1; proto[j++] = funcText[i++]; continue; }
            if (funcText[i] == '/' && funcText[i+1] == '*') { inMulti = 1; proto[j++] = funcText[i++]; continue; }
            if (funcText[i] == '"') { inStr = 1; proto[j++] = funcText[i++]; continue; }
            if (funcText[i] == '\'') { inChar = 1; proto[j++] = funcText[i++]; continue; }
            
            if (funcText[i] == '{') {
                break;
            }
            proto[j++] = funcText[i++];
        } else if (inSingle) {
            if (funcText[i] == '\n') inSingle = 0;
            proto[j++] = funcText[i++];
        } else if (inMulti) {
            if (funcText[i] == '*' && funcText[i+1] == '/') { inMulti = 0; proto[j++] = funcText[i++]; }
            proto[j++] = funcText[i++];
        } else if (inStr) {
            if (funcText[i] == '\\' && funcText[i+1]) { proto[j++] = funcText[i++]; proto[j++] = funcText[i++]; }
            else if (funcText[i] == '"') { inStr = 0; proto[j++] = funcText[i++]; }
            else proto[j++] = funcText[i++];
        } else if (inChar) {
            if (funcText[i] == '\\' && funcText[i+1]) { proto[j++] = funcText[i++]; proto[j++] = funcText[i++]; }
            else if (funcText[i] == '\'') { inChar = 0; proto[j++] = funcText[i++]; }
            else proto[j++] = funcText[i++];
        }
    }
    
    while (j > 0 && (proto[j-1] == ' ' || proto[j-1] == '\t' || proto[j-1] == '\r' || proto[j-1] == '\n')) j--;
    
    proto[j++] = ';';
    proto[j++] = '\r';
    proto[j++] = '\n';
    proto[j] = '\0';
    
    return proto;
}

void OnAddProto() {
    int count = SendMessage(hListLeft, LB_GETSELCOUNT, 0, 0);
    if (count <= 0) {
        SetStatus("No procedures selected to create prototypes for.");
        return;
    }

    int* indices = (int*)malloc(count * sizeof(int));
    SendMessage(hListLeft, LB_GETSELITEMS, count, (LPARAM)indices);

    char** selectedNames = (char**)malloc(count * sizeof(char*));
    for (int i = 0; i < count; i++) {
        selectedNames[i] = (char*)malloc(256);
        SendMessage(hListLeft, LB_GETTEXT, indices[i], (LPARAM)selectedNames[i]);
    }
    free(indices);

    int addedCount = 0;
    
    for (int i = 0; i < count; i++) {
        const char* matchName = GetRealName(selectedNames[i]);
        
        Chunk* l = g_LeftChunks;
        Chunk* targetProc = NULL;
        while (l) {
            if (l->isProc && l->type == T_PROC && strcmp(l->name, matchName) == 0) {
                targetProc = l;
                break;
            }
            l = l->next;
        }
        
        if (targetProc) {
            Chunk* pCheck = g_LeftChunks;
            int exists = 0;
            while(pCheck) {
                if (pCheck->type == T_PROTO && strcmp(pCheck->name, matchName) == 0) {
                    exists = 1; break;
                }
                pCheck = pCheck->next;
            }
            
            if (!exists) {
                Chunk* nc = (Chunk*)malloc(sizeof(Chunk));
                nc->isProc = 1;
                nc->type = T_PROTO;
                nc->isAdded = 1;
                nc->lineNum = 0;
                strcpy(nc->name, targetProc->name);
                nc->text = CreatePrototypeFromFunc(targetProc->text);
                nc->next = NULL;
                
                Chunk* curr = g_LeftChunks;
                Chunk* lastProto = NULL;
                while (curr) {
                    if (curr->type == T_PROTO) lastProto = curr;
                    curr = curr->next;
                }
                
                if (lastProto) {
                    nc->next = lastProto->next;
                    lastProto->next = nc;
                } else {
                    curr = g_LeftChunks;
                    Chunk* prev = NULL;
                    while (curr && curr->type != T_PROC) { prev = curr; curr = curr->next; }
                    if (prev) { nc->next = prev->next; prev->next = nc; }
                    else { nc->next = g_LeftChunks; g_LeftChunks = nc; }
                }
                addedCount++;
            }
        }
        free(selectedNames[i]);
    }
    free(selectedNames);

    if (addedCount > 0) {
        PopulateList(hListLeft, g_LeftChunks);
        char msg[256];
        sprintf(msg, "Added %d prototypes (new items prefixed with +).", addedCount);
        SetStatus(msg);
    } else {
        SetStatus("No prototypes added (they may already exist, or non-functions were selected).");
    }
}

void MoveLeftChunks(int* selIndices, int selCount, int dropIndex) {
    if (selCount <= 0 || !selIndices) return;

    int pCount = 0;
    Chunk* curr = g_LeftChunks;
    while (curr) {
        if (curr->isProc) pCount++;
        curr = curr->next;
    }

    if (pCount == 0 || selCount > pCount) return;
    if (dropIndex > pCount) dropIndex = pCount;
    if (dropIndex < 0) dropIndex = 0;

    ProcGroup* groups = (ProcGroup*)malloc(sizeof(ProcGroup) * pCount);
    
    Chunk* headerHead = NULL;
    Chunk* headerTail = NULL;
    curr = g_LeftChunks;

    if (curr && !curr->isProc) {
        headerHead = curr;
        while (curr && !curr->isProc) {
            headerTail = curr;
            curr = curr->next;
        }
    }

    int idx = 0;
    while (curr && idx < pCount) {
        groups[idx].head = curr;
        Chunk* tail = curr;
        curr = curr->next;
        
        while (curr && !curr->isProc) {
            tail = curr;
            curr = curr->next;
        }
        groups[idx].tail = tail;
        idx++;
    }

    ProcGroup* movingGroups = (ProcGroup*)malloc(sizeof(ProcGroup) * selCount);
    int* isMoving = (int*)calloc(pCount, sizeof(int));
    
    for (int i = 0; i < selCount; i++) {
        isMoving[selIndices[i]] = 1;
        movingGroups[i] = groups[selIndices[i]];
    }

    ProcGroup* newGroups = (ProcGroup*)malloc(sizeof(ProcGroup) * pCount);
    int nIdx = 0;
    
    for (int i = 0; i <= pCount; i++) {
        if (i == dropIndex) {
            for (int j = 0; j < selCount; j++) {
                newGroups[nIdx++] = movingGroups[j];
            }
        }
        if (i < pCount && !isMoving[i]) {
            newGroups[nIdx++] = groups[i];
        }
    }

    g_LeftChunks = headerHead ? headerHead : newGroups[0].head;
    
    if (headerTail) {
        EnsureCRLF(headerTail);
        headerTail->next = newGroups[0].head;
    }

    for (int i = 0; i < pCount; i++) {
        EnsureCRLF(newGroups[i].tail); 
        if (i < pCount - 1) {
            newGroups[i].tail->next = newGroups[i + 1].head;
        } else {
            newGroups[i].tail->next = NULL;
        }
    }

    free(groups);
    free(movingGroups);
    free(isMoving);
    free(newGroups);
}

int MoveAddedAbove(const char* targetName) {
    int pCount = 0;
    Chunk* curr = g_LeftChunks;
    while (curr) {
        if (curr->isProc) pCount++;
        curr = curr->next;
    }

    if (pCount <= 1 || !targetName) return -1;
    
    int targetIdx = -1;
    curr = g_LeftChunks;
    int idx = 0;
    while(curr) {
        if (curr->isProc) {
            if (strcmp(curr->name, targetName) == 0) { targetIdx = idx; break; }
            idx++;
        }
        curr = curr->next;
    }
    if (targetIdx == -1) return -1;

    ProcGroup* groups = (ProcGroup*)malloc(sizeof(ProcGroup) * pCount);
    
    Chunk* headerHead = NULL;
    Chunk* headerTail = NULL;
    curr = g_LeftChunks;

    if (curr && !curr->isProc) {
        headerHead = curr;
        while (curr && !curr->isProc) {
            headerTail = curr;
            curr = curr->next;
        }
    }

    idx = 0;
    while (curr && idx < pCount) {
        groups[idx].head = curr;
        Chunk* tail = curr;
        curr = curr->next;
        
        while (curr && !curr->isProc) {
            tail = curr;
            curr = curr->next;
        }
        groups[idx].tail = tail;
        idx++;
    }

    ProcGroup targetGroup = groups[targetIdx];
    
    ProcGroup* addedGroups = (ProcGroup*)malloc(sizeof(ProcGroup) * pCount);
    int addedCount = 0;
    ProcGroup* otherGroups = (ProcGroup*)malloc(sizeof(ProcGroup) * pCount);
    int otherCount = 0;
    
    for (int i = 0; i < pCount; i++) {
        if (groups[i].head->isAdded && i != targetIdx) {
            addedGroups[addedCount++] = groups[i];
        } else {
            otherGroups[otherCount++] = groups[i];
        }
    }
    
    ProcGroup* newGroups = (ProcGroup*)malloc(sizeof(ProcGroup) * pCount);
    int newIdx = 0;
    
    for (int i = 0; i < otherCount; i++) {
        if (otherGroups[i].head == targetGroup.head) {
            for (int j = 0; j < addedCount; j++) {
                newGroups[newIdx++] = addedGroups[j];
            }
        }
        newGroups[newIdx++] = otherGroups[i];
    }
    
    int finalTargetIdx = -1;
    for (int i = 0; i < pCount; i++) {
        if (newGroups[i].head == targetGroup.head) finalTargetIdx = i;
    }

    g_LeftChunks = headerHead ? headerHead : newGroups[0].head;
    if (headerTail) {
        EnsureCRLF(headerTail);
        headerTail->next = newGroups[0].head;
    }

    for (int i = 0; i < pCount; i++) {
        EnsureCRLF(newGroups[i].tail); 
        if (i < pCount - 1) {
            newGroups[i].tail->next = newGroups[i + 1].head;
        } else {
            newGroups[i].tail->next = NULL;
        }
    }

    free(groups);
    free(addedGroups);
    free(otherGroups);
    free(newGroups);
    
    return finalTargetIdx;
}

BOOL HandleFilterInput(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, char* filterBuf, UINT_PTR timerId) {
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        if (filterBuf[0] != '\0') {
            filterBuf[0] = '\0';
            KillTimer(hwnd, timerId);
            PopulateList(hwnd, hwnd == hListLeft ? g_LeftChunks : g_RightChunks);
            SetStatus("Filter cleared.");
        }
        return TRUE;
    }
    if (msg == WM_CHAR) {
        char c = (char)wParam;
        int len = strlen(filterBuf);
        if (c == '\b') {
            if (len > 0) filterBuf[len - 1] = '\0';
            else return TRUE; 
        } else if (c >= 32 && c <= 126 && len < 255) {
            filterBuf[len] = c;
            filterBuf[len + 1] = '\0';
        } else {
            return FALSE; 
        }
        
        KillTimer(hwnd, timerId);
        SetTimer(hwnd, timerId, 500, NULL);
        
        char statusMsg[300];
        sprintf(statusMsg, "Filtering: '%s' (Waiting 0.5s...)", filterBuf);
        SetStatus(statusMsg);
        return TRUE;
    }
    if (msg == WM_TIMER && wParam == timerId) {
        KillTimer(hwnd, timerId);
        PopulateList(hwnd, hwnd == hListLeft ? g_LeftChunks : g_RightChunks);
        char statusMsg[300];
        if (filterBuf[0] != '\0') {
            sprintf(statusMsg, "Filtered: '%s' (Press ESC to clear)", filterBuf);
        } else {
            strcpy(statusMsg, "Filter cleared.");
        }
        SetStatus(statusMsg);
        return TRUE;
    }
    return FALSE;
}

LRESULT CALLBACK LeftListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static POINT ptDown;
    static BOOL bDragging = FALSE;
    static BOOL bOurCapture = FALSE;

    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        if (bOurCapture) {
            ReleaseCapture();
            bOurCapture = FALSE;
            bDragging = FALSE;
        }
        if (HandleFilterInput(hwnd, msg, wParam, lParam, g_FilterLeft, TIMER_FILTER_LEFT)) return 0;
    }
    if (msg == WM_CHAR) {
        if (HandleFilterInput(hwnd, msg, wParam, lParam, g_FilterLeft, TIMER_FILTER_LEFT)) return 0;
    }
    if (msg == WM_TIMER && wParam == TIMER_FILTER_LEFT) {
        if (HandleFilterInput(hwnd, msg, wParam, lParam, g_FilterLeft, TIMER_FILTER_LEFT)) return 0;
    }

    switch (msg) {
        case WM_KEYDOWN: {
            if (wParam == VK_RETURN) {
                int count = SendMessage(hwnd, LB_GETSELCOUNT, 0, 0);
                if (count == 1) {
                    int targetIdx = -1;
                    SendMessage(hwnd, LB_GETSELITEMS, 1, (LPARAM)&targetIdx);
                    if (targetIdx != -1) {
                        char targetName[256];
                        SendMessage(hwnd, LB_GETTEXT, targetIdx, (LPARAM)targetName);
                        const char* realTarget = GetRealName(targetName);
                        
                        MoveAddedAbove(realTarget);
                        PopulateList(hwnd, g_LeftChunks);
                        
                        int newSel = SendMessage(hwnd, LB_FINDSTRINGEXACT, -1, (LPARAM)targetName);
                        SendMessage(hwnd, LB_SETSEL, FALSE, -1);
                        if (newSel != LB_ERR) SendMessage(hwnd, LB_SETSEL, TRUE, newSel);
                        
                        SetStatus("Moved all added (+) items above selected.");
                    }
                } else {
                    SetStatus("Please select exactly one item to move added items above.");
                }
                return 0; 
            }
            break;
        }
        case WM_LBUTTONDOWN: {
            SetFocus(hwnd); 
            
            int idx = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, lParam);
            if (!HIWORD(idx)) {
                int clickIdx = LOWORD(idx);
                ptDown.x = (short)LOWORD(lParam);
                ptDown.y = (short)HIWORD(lParam);
                bDragging = FALSE;
                
                if ((wParam & MK_SHIFT) || (wParam & MK_CONTROL)) {
                    bOurCapture = FALSE;
                } else {
                    if (SendMessage(hwnd, LB_GETSEL, clickIdx, 0) == 0) {
                        SendMessage(hwnd, LB_SETSEL, FALSE, -1);
                        SendMessage(hwnd, LB_SETSEL, TRUE, clickIdx);
                    }
                    
                    bOurCapture = TRUE;
                    SetCapture(hwnd);
                    return 0; 
                }
            }
            break; 
        }
        case WM_MOUSEMOVE: {
            if (bOurCapture && (wParam & MK_LBUTTON)) {
                int x = (short)LOWORD(lParam);
                int y = (short)HIWORD(lParam);
                if (!bDragging) {
                    if (abs(x - ptDown.x) > GetSystemMetrics(SM_CXDRAG) ||
                        abs(y - ptDown.y) > GetSystemMetrics(SM_CYDRAG)) {
                        bDragging = TRUE;
                    }
                }
                if (bDragging) {
                    SetCursor(LoadCursor(NULL, IDC_HAND));
                    return 0; 
                }
            }
            break;
        }
        case WM_LBUTTONUP: {
            if (bOurCapture) {
                ReleaseCapture();
                bOurCapture = FALSE;
                
                if (bDragging) {
                    bDragging = FALSE;
                    int x = (short)LOWORD(lParam);
                    int y = (short)HIWORD(lParam);
                    
                    int idx = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, MAKELPARAM(x, y));
                    int dropIndex = LOWORD(idx);
                    
                    if (HIWORD(idx)) {
                        if (y < 0) dropIndex = 0; 
                        else dropIndex = SendMessage(hwnd, LB_GETCOUNT, 0, 0); 
                    }
                    
                    int selCount = SendMessage(hwnd, LB_GETSELCOUNT, 0, 0);
                    if (selCount > 0) {
                        int* lbIndices = (int*)malloc(selCount * sizeof(int));
                        SendMessage(hwnd, LB_GETSELITEMS, selCount, (LPARAM)lbIndices);
                        
                        int* globalIndices = (int*)malloc(selCount * sizeof(int));
                        int globalDropIndex = -1;

                        int gIdx = 0;
                        int lIdx = 0;
                        int lastVisibleGIdx = -1;

                        Chunk* c = g_LeftChunks;
                        while (c) {
                            if (c->isProc) {
                                int match = 1;
                                if (g_FilterLeft[0] != '\0' && !str_istr(c->name, g_FilterLeft)) {
                                    match = 0;
                                }
                                if (match) {
                                    for (int k = 0; k < selCount; k++) {
                                        if (lbIndices[k] == lIdx) globalIndices[k] = gIdx;
                                    }
                                    if (lIdx == dropIndex) {
                                        globalDropIndex = gIdx;
                                    }
                                    lastVisibleGIdx = gIdx;
                                    lIdx++;
                                }
                                gIdx++;
                            }
                            c = c->next;
                        }

                        if (dropIndex == lIdx) {
                            globalDropIndex = lastVisibleGIdx + 1;
                        }
                        if (globalDropIndex == -1) {
                            globalDropIndex = gIdx;
                        }

                        MoveLeftChunks(globalIndices, selCount, globalDropIndex);
                        PopulateList(hwnd, g_LeftChunks);
                        
                        int itemsBeforeDrop = 0;
                        for (int i = 0; i < dropIndex; i++) {
                            int isMoving = 0;
                            for (int j = 0; j < selCount; j++) {
                                if (lbIndices[j] == i) isMoving = 1;
                            }
                            if (!isMoving) itemsBeforeDrop++;
                        }
                        
                        SendMessage(hwnd, LB_SETSEL, FALSE, -1);
                        for (int i = 0; i < selCount; i++) {
                            SendMessage(hwnd, LB_SETSEL, TRUE, itemsBeforeDrop + i);
                        }
                        
                        free(globalIndices);
                        free(lbIndices);
                        SetStatus("Order changed (will apply on save).");
                    }
                } else {
                    int idx = SendMessage(hwnd, LB_ITEMFROMPOINT, 0, MAKELPARAM(ptDown.x, ptDown.y));
                    if (!HIWORD(idx)) {
                        SendMessage(hwnd, LB_SETSEL, FALSE, -1);
                        SendMessage(hwnd, LB_SETSEL, TRUE, LOWORD(idx));
                    }
                }
                return 0; 
            }
            bDragging = FALSE;
            break;
        }
    }
    return CallWindowProc(OldListProc, hwnd, msg, wParam, lParam);
}
LRESULT CALLBACK RightListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_ESCAPE) {
        if (HandleFilterInput(hwnd, msg, wParam, lParam, g_FilterRight, TIMER_FILTER_RIGHT)) return 0;
    }
    if (msg == WM_CHAR) {
        if (HandleFilterInput(hwnd, msg, wParam, lParam, g_FilterRight, TIMER_FILTER_RIGHT)) return 0;
    }
    if (msg == WM_TIMER && wParam == TIMER_FILTER_RIGHT) {
        if (HandleFilterInput(hwnd, msg, wParam, lParam, g_FilterRight, TIMER_FILTER_RIGHT)) return 0;
    }
    return CallWindowProc(OldRightListProc, hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch(msg) {
        case WM_CREATE: {
            INITCOMMONCONTROLSEX icex;
            icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
            icex.dwICC = ICC_BAR_CLASSES;
            InitCommonControlsEx(&icex);

            hComboMru      = CreateWindow("COMBOBOX", "", WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_AUTOHSCROLL | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_VSCROLL, 0, 4, 220, 300, hwnd, (HMENU)IDC_MRUCOMBO, NULL, NULL);
            HWND hComboEdit = FindWindowEx(hComboMru, NULL, "Edit", NULL);
            if (hComboEdit) {
                SetWindowLong(hComboEdit, GWL_STYLE, GetWindowLong(hComboEdit, GWL_STYLE) | ES_RIGHT | ES_AUTOHSCROLL);
            }

            hBtnBrowse     = CreateWindow("BUTTON", "Browse", WS_CHILD | WS_VISIBLE, 0, 0, 60, 30, hwnd, (HMENU)IDB_BROWSE, NULL, NULL);
            hBtnPasteRep   = CreateWindow("BUTTON", "Paste & Rep", WS_CHILD | WS_VISIBLE, 0, 0, 90, 30, hwnd, (HMENU)IDB_PASTEREPLACE, NULL, NULL);
            hBtnPaste      = CreateWindow("BUTTON", "Paste", WS_CHILD | WS_VISIBLE, 0, 0, 50, 30, hwnd, (HMENU)IDB_PASTE, NULL, NULL);
            hBtnUpdate     = CreateWindow("BUTTON", "Update", WS_CHILD | WS_VISIBLE, 0, 0, 60, 30, hwnd, (HMENU)IDB_UPDATE, NULL, NULL);
            hBtnSave       = CreateWindow("BUTTON", "Save", WS_CHILD | WS_VISIBLE, 0, 0, 50, 30, hwnd, (HMENU)IDB_SAVE, NULL, NULL);
            hBtnEdit       = CreateWindow("BUTTON", "Edit", WS_CHILD | WS_VISIBLE, 0, 0, 50, 30, hwnd, (HMENU)IDB_EDIT, NULL, NULL);
            hBtnAddProto   = CreateWindow("BUTTON", "+Proto", WS_CHILD | WS_VISIBLE, 0, 0, 60, 30, hwnd, (HMENU)IDB_ADDPROTO, NULL, NULL);
            hBtnCompile    = CreateWindow("BUTTON", "Compile", WS_CHILD | WS_VISIBLE, 0, 0, 70, 30, hwnd, (HMENU)IDB_COMPILE, NULL, NULL);
            hBtnCopyLeft   = CreateWindow("BUTTON", "Copy (L)", WS_CHILD | WS_VISIBLE, 0, 0, 70, 30, hwnd, (HMENU)IDB_COPYLEFT, NULL, NULL);
            hBtnDeleteLeft = CreateWindow("BUTTON", "Delete", WS_CHILD | WS_VISIBLE, 0, 0, 60, 30, hwnd, (HMENU)IDB_DELETELEFT, NULL, NULL);

            hListLeft  = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_EXTENDEDSEL | LBS_USETABSTOPS, 0, 0, 0, 0, hwnd, (HMENU)IDL_LEFT, NULL, NULL);
            hListRight = CreateWindowEx(WS_EX_CLIENTEDGE, "LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_EXTENDEDSEL | LBS_USETABSTOPS, 0, 0, 0, 0, hwnd, (HMENU)IDL_RIGHT, NULL, NULL);
            
            int tabStops[1] = { 160 };
            SendMessage(hListLeft, LB_SETTABSTOPS, 1, (LPARAM)tabStops);
            SendMessage(hListRight, LB_SETTABSTOPS, 1, (LPARAM)tabStops);

            OldListProc = (WNDPROC)SetWindowLongPtr(hListLeft, GWLP_WNDPROC, (LONG_PTR)LeftListWndProc);
            OldRightListProc = (WNDPROC)SetWindowLongPtr(hListRight, GWLP_WNDPROC, (LONG_PTR)RightListWndProc);

            hStatus = CreateWindowEx(0, STATUSCLASSNAME, NULL, WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, hwnd, (HMENU)IDS_STATUS, NULL, NULL);
            SetStatus("Ready. Release to Public domain.");
            
            LoadMRU();
            PopulateMRUCombo();

            DragAcceptFiles(hwnd, TRUE);
        } break;

        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT lpdis = (LPDRAWITEMSTRUCT)lParam;
            if (lpdis->CtlID == IDC_MRUCOMBO && lpdis->itemID != (UINT)-1) {
                char buf[MAX_PATH];
                SendMessage(lpdis->hwndItem, CB_GETLBTEXT, lpdis->itemID, (LPARAM)buf);
                COLORREF bgColor = GetSysColor((lpdis->itemState & ODS_SELECTED) ? COLOR_HIGHLIGHT : COLOR_WINDOW);
                COLORREF txColor = GetSysColor((lpdis->itemState & ODS_SELECTED) ? COLOR_HIGHLIGHTTEXT : COLOR_WINDOWTEXT);
                HBRUSH hBr = CreateSolidBrush(bgColor);
                FillRect(lpdis->hDC, &lpdis->rcItem, hBr);
                DeleteObject(hBr);
                SetBkMode(lpdis->hDC, TRANSPARENT);
                SetTextColor(lpdis->hDC, txColor);
                RECT rc = lpdis->rcItem;
                rc.left += 2;
                rc.right -= 4;
                DrawText(lpdis->hDC, buf, -1, &rc, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                if (lpdis->itemState & ODS_FOCUS) {
                    DrawFocusRect(lpdis->hDC, &lpdis->rcItem);
                }
                return TRUE;
            }
        } break;

        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            char droppedFile[MAX_PATH];
            
            if (DragQueryFile(hDrop, 0, droppedFile, MAX_PATH)) {
                LoadFile(droppedFile);
            }
            
            DragFinish(hDrop);
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

            int rightX = width - 4;
            rightX -= 70; MoveWindow(hBtnCompile, rightX, 0, 70, 30, TRUE);
            rightX -= 60; MoveWindow(hBtnAddProto, rightX, 0, 60, 30, TRUE);
            rightX -= 50; MoveWindow(hBtnEdit, rightX, 0, 50, 30, TRUE);
            rightX -= 50; MoveWindow(hBtnSave, rightX, 0, 50, 30, TRUE);
            rightX -= 60; MoveWindow(hBtnUpdate, rightX, 0, 60, 30, TRUE);
            rightX -= 50; MoveWindow(hBtnPaste, rightX, 0, 50, 30, TRUE);
            rightX -= 90; MoveWindow(hBtnPasteRep, rightX, 0, 90, 30, TRUE);
            rightX -= 60; MoveWindow(hBtnBrowse, rightX, 0, 60, 30, TRUE);
            rightX -= 60; MoveWindow(hBtnDeleteLeft, rightX, 0, 60, 30, TRUE);
            rightX -= 70; MoveWindow(hBtnCopyLeft, rightX, 0, 70, 30, TRUE);

            int comboWidth = rightX - 8;
            if (comboWidth < 100) comboWidth = 100;
            MoveWindow(hComboMru, 4, 4, comboWidth, 300, TRUE);
            HWND hComboEdit = FindWindowEx(hComboMru, NULL, "Edit", NULL);
            if (hComboEdit) {
                int len = GetWindowTextLength(hComboEdit);
                PostMessage(hComboEdit, EM_SETSEL, len, len);
            }

            MoveWindow(hListLeft, 0, listY, halfW, listH, TRUE);
            MoveWindow(hListRight, halfW, listY, width - halfW, listH, TRUE);
        } break;

        case WM_COMMAND: {
            if (LOWORD(wParam) == IDC_MRUCOMBO) {
                if (HIWORD(wParam) == CBN_SELENDOK) {
                    int idx = SendMessage(hComboMru, CB_GETCURSEL, 0, 0);
                    if (idx != CB_ERR) {
                        char buf[MAX_PATH];
                        SendMessage(hComboMru, CB_GETLBTEXT, idx, (LPARAM)buf);
                        LoadFile(buf);
                    }
                } else if (HIWORD(wParam) == CBN_CLOSEUP || HIWORD(wParam) == CBN_SELCHANGE) {
                    HWND hComboEdit = FindWindowEx(hComboMru, NULL, "Edit", NULL);
                    if (hComboEdit) {
                        int len = GetWindowTextLength(hComboEdit);
                        PostMessage(hComboEdit, EM_SETSEL, len, len);
                    }
                }
            }
            else if (LOWORD(wParam) == IDB_BROWSE) OnBrowse();
            else if (LOWORD(wParam) == IDB_PASTEREPLACE) OnPasteAndReplace();
            else if (LOWORD(wParam) == IDB_PASTE) OnPaste();
            else if (LOWORD(wParam) == IDB_UPDATE) OnUpdate();
            else if (LOWORD(wParam) == IDB_SAVE) OnSave();
            else if (LOWORD(wParam) == IDB_EDIT) OnEdit();
            else if (LOWORD(wParam) == IDB_ADDPROTO) OnAddProto();
            else if (LOWORD(wParam) == IDB_COMPILE) OnCompile();
            else if (LOWORD(wParam) == IDB_COPYLEFT) OnCopyLeft();
            else if (LOWORD(wParam) == IDB_DELETELEFT) OnDeleteLeft();
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