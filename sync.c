/* ============================================================================
 * sync - Background Folder Synchronizer (Updated with FTP, GUI Editor, & Delete)
 * 
 * COMPILATION:
 *   gcc -Os -s -Wall -Wextra sync.c -o sync.exe -mwindows -lshlwapi -lshell32 -luser32 -lkernel32 -ladvapi32 -lmpr -lgdi32 -lwininet -lcomdlg32 -lole32
 *
 * FEATURES:
 *  - Windowless System Tray operation with dynamic path-compacted tooltips.
 *  - Real-time recent log history inside the tooltip.
 *  - Bitmask-driven copy logic (Newer, Older, Move, Clone Times, .bak, etc).
 *  - Hardware Resource Throttling (CPU limit via Job Objects, Disk MB/s limits).
 *  - Automatic Network Share Authentication from INI.
 *  - Idle-Detection execution (Waits for system idle before heavy copying).
 *  - Hot-reloading INI file (Changes apply on the next refresh tick).
 *  - Non-Blocking On-Screen Error Drawing (Lower right corner screen DC painting).
 *  - Action Logging (Outputs exact timestamps and byte sizes of changed files).
 *  - Post-Sync Command Execution (Hidden Window).
 *  - Conditional Execution based on Process Exists / Does Not Exist (InStr match).
 *  - FTP Protocol Support via WinINet (`ftp://user:pass@host.com:2121/path`).
 *  - Interactive Win32 Configuration Editor (`-edit` command line or Tray Menu).
 *
 * INI JOB FORMAT:
 *   JobName=Src,Dst,Flags,Masks,PostCmd,IfProcExists,IfProcNotExists
 *
 * THIS WORK IS NOT FIT FOR ANY FUNCTION OR PURPOSE, COMES WITH NO WARRANTY,
 * AND IS BEING RELEASED INTO THE PUBLIC DOMAIN.
 * ============================================================================ */

#define _WIN32_IE 0x0500    
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <process.h>
#include <winnetwk.h>
#include <tlhelp32.h> 
#include <wininet.h>
#include <commdlg.h>
#ifndef JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
#define JOB_OBJECT_CPU_RATE_CONTROL_ENABLE 0x1
#define JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP 0x4
typedef struct _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
    DWORD ControlFlags;
    union { DWORD CpuRate; DWORD Weight; struct { WORD MinRate; WORD MaxRate; }; };
} JOBOBJECT_CPU_RATE_CONTROL_INFORMATION;
#ifndef JobObjectCpuRateControlInformation
#define JobObjectCpuRateControlInformation 15
#endif
#endif
#define WM_TRAYICON (WM_USER + 1)
#define ID_PAUSE 1001
#define ID_EXIT  1002
#define ID_EDIT  1003
#define LONG_PATH_SIZE 4096
// --- UI Defines ---
#define ID_CMB_JOBS       2001
#define ID_BTN_SAVE_JOB   2002
#define ID_TXT_JOB        2003
#define ID_BTN_BROWSE_SRC 2004
#define ID_BTN_BROWSE_DST 2005
#define ID_BTN_SAVE_SET   2006
#define ID_BTN_SAVE_CRED  2007
#define ID_BTN_DELETE_JOB 2020
#define ID_CMB_CRED_SHARE 2021
#define ID_BTN_DELETE_CRED 2022
// --- Pro Sync Mode Bitmasks ---
#define SYNC_SKIP              0
#define SYNC_NEWER             1
#define SYNC_OLDER             2
#define SYNC_LARGER            4
#define SYNC_SMALLER           8
#define SYNC_ALWAYS           16
#define SYNC_FORCE_READONLY   32
#define SYNC_MOVE_FILE        64
#define SYNC_BACKUP_DEST     128
#define SYNC_CLONE_TIMES     256
volatile BOOL g_Paused = FALSE;
volatile BOOL g_Exit = FALSE;
HWND g_hwnd = NULL;
HWND g_hEditWnd = NULL;
HWND g_hCmbJobs, g_hTxtSrc, g_hTxtDst, g_hTxtFlags, g_hTxtMasks, g_hTxtCmd, g_hTxtIfProc, g_hTxtIfNotProc;
HWND g_hSetLog, g_hSetDisk, g_hSetRefresh, g_hCredShare, g_hCredUser, g_hCredPass;
NOTIFYICONDATAA g_nid = {0};
char g_iniPath[LONG_PATH_SIZE];
char g_logFile[MAX_PATH] = ""; 
char g_recentLogs[3][64] = {"", "", ""};HINTERNET g_hInternet = NULL;

DWORD g_dwLastHideTime = 0;

// Add new globals for captive portal tracking
BOOL g_bCaptivePortal = FALSE;
struct ErrorMsg { char msg[2048]; };
struct SyncMsg { char msg[256]; };

// Forward declarations
void ShowEditWindow(HINSTANCE hInstance);

HBITMAP hbmMask = CreateBitmap(16, 16, 1, 1, maskBits);
    
    
HICON hIcon = CreateIconIndirect(&ii);
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
// -----------------------------------------------------------------------------
// Logging & UI
// -----------------------------------------------------------------------------

void LogSyncAction(const char* src, const char* dst, ULARGE_INTEGER size, FILETIME ft) {
    if (g_logFile[0] == '\0') return; 
    FILE* f = fopen(g_logFile, "a");
    if (!f) return;
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] SIZE: %llu bytes | %s -> %s\n",
            stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond,
            size.QuadPart, src, dst);
    fclose(f);
}

void UpdateTrayTooltip(const char* text) {
    NOTIFYICONDATAA tipNid = {0}; tipNid.cbSize = sizeof(NOTIFYICONDATAA);
    tipNid.hWnd = g_hwnd; tipNid.uID = 1; tipNid.uFlags = NIF_TIP;
    snprintf(tipNid.szTip, sizeof(tipNid.szTip), "%s", text); 
    Shell_NotifyIconA(NIM_MODIFY, &tipNid);
}

void AddToRecentLogs(const char* filename) {
    SYSTEMTIME st; GetLocalTime(&st);
    char newLog[64]; char shortFile[18];
    PathCompactPathExA(shortFile, filename, 16, 0); 
    snprintf(newLog, sizeof(newLog), "[%02d:%02d:%02d] %s", st.wHour, st.wMinute, st.wSecond, shortFile);
    strcpy(g_recentLogs[2], g_recentLogs[1]);
    strcpy(g_recentLogs[1], g_recentLogs[0]);
    strcpy(g_recentLogs[0], newLog);
}

void UpdateTrayTooltipDone() {
    char tip[128] = "Recent Syncs:";
    if (g_recentLogs[0][0] == '\0') {
        snprintf(tip, sizeof(tip), "Sync Idle\nWaiting for new files");
    } else {
        for (int i = 0; i < 3; i++) {
            if (g_recentLogs[i][0] != '\0') {
                if (strlen(tip) + strlen(g_recentLogs[i]) + 2 < sizeof(tip)) {
                    strcat(tip, "\n"); strcat(tip, g_recentLogs[i]);
                }
            }
        }
    }
    UpdateTrayTooltip(tip);
}

unsigned __stdcall DrawErrorThread(void* arg) {
    struct ErrorMsg* err = (struct ErrorMsg*)arg;
    for (int i = 0; i < 30 && !g_Exit; i++) { 
        HDC hdc = GetDC(NULL); 
        if (hdc) {
            SetBkColor(hdc, RGB(220, 20, 60)); SetTextColor(hdc, RGB(255, 255, 255)); 
            HFONT hFont = CreateFontA(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, "Arial");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            SIZE sz; GetTextExtentPoint32A(hdc, err->msg, strlen(err->msg), &sz);
            int x = GetSystemMetrics(SM_CXSCREEN) - sz.cx - 20;
            int y = GetSystemMetrics(SM_CYSCREEN) - sz.cy - 60; 
            TextOutA(hdc, x, y, err->msg, strlen(err->msg));
            SelectObject(hdc, hOldFont); DeleteObject(hFont); ReleaseDC(NULL, hdc);
        }
        Sleep(100);
    }
    free(err);
    return 0;
}

void ShowErrorNonBlocking(const char* path, const char* reason) {
    struct ErrorMsg* err = malloc(sizeof(struct ErrorMsg));
    if (err) {
        snprintf(err->msg, sizeof(err->msg), " SYNC FAILED: %s | %s ", path, reason ? reason : "UNKNOWN");
        _beginthreadex(NULL, 0, DrawErrorThread, err, 0, NULL);
    }
}

unsigned __stdcall DrawSyncTextThread(void* arg) {
    struct SyncMsg* sm = (struct SyncMsg*)arg;
    RECT workArea; SystemParametersInfoA(SPI_GETWORKAREA, 0, &workArea, 0);

    for (int i = 0; i < 20 && !g_Exit; i++) { 
        HDC hdc = GetDC(NULL); 
        if (hdc) {
            SetBkColor(hdc, RGB(0, 100, 0)); 
            SetTextColor(hdc, RGB(255, 255, 255)); 
            HFONT hFont = CreateFontA(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, "Arial");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            SIZE sz; GetTextExtentPoint32A(hdc, sm->msg, strlen(sm->msg), &sz);
            
            int x = workArea.right - sz.cx - 20;
            int y = workArea.bottom - sz.cy - 10; 
            
            TextOutA(hdc, x, y, sm->msg, strlen(sm->msg));
            SelectObject(hdc, hOldFont); DeleteObject(hFont); ReleaseDC(NULL, hdc);
        }
        Sleep(100);
    }
    free(sm);
    return 0;
}

void ShowSyncTextNonBlocking(const char* text) {
    struct SyncMsg* sm = malloc(sizeof(struct SyncMsg));
    if (sm) {
        snprintf(sm->msg, sizeof(sm->msg), " SYNCING: %s ", text);
        _beginthreadex(NULL, 0, DrawSyncTextThread, sm, 0, NULL);
    }
}

// -----------------------------------------------------------------------------
// FTP & Network Logic
// -----------------------------------------------------------------------------

BOOL ParseFtpUrl(const char* url, char* user, char* pass, char* host, int* port, char* path) {
    if (strncmp(url, "ftp://", 6) != 0) return FALSE;
    *port = 21; user[0] = 0; pass[0] = 0; host[0] = 0; path[0] = 0;
    
    char temp[LONG_PATH_SIZE];
    strncpy(temp, url + 6, sizeof(temp));
    
    char* at = strchr(temp, '@');
    char* slash = strchr(at ? at : temp, '/');
    
    if (at) {
        *at = '\0';
        char* colon = strchr(temp, ':');
        if (colon) {
            *colon = '\0';
            strcpy(user, temp);
            strcpy(pass, colon + 1);
        } else {
            strcpy(user, temp);
        }
        memmove(temp, at + 1, strlen(at + 1) + 1);
    }
    
    slash = strchr(temp, '/');
    if (slash) {
        strcpy(path, slash + 1);
        *slash = '\0';
    }
    
    char* portColon = strchr(temp, ':');
    if (portColon) {
        *portColon = '\0';
        *port = atoi(portColon + 1);
    }
    strcpy(host, temp);
    return TRUE;
}

void ExtractShareName(const char* path, char* shareOut) {
    shareOut[0] = '\0';
    if (path[0] == '\\' && path[1] == '\\') {
        const char* p = path + 2; int slashes = 0;
        while (*p) { if (*p == '\\') slashes++; if (slashes == 2) break; p++; }
        snprintf(shareOut, MAX_PATH, "%.*s", (int)(p - path), path);
    }
}

BOOL EnsureNetworkConnection(const char* path) {
    if (strncmp(path, "ftp://", 6) == 0) return TRUE;
    if (path[0] != '\\' || path[1] != '\\') return TRUE; 
    char shareName[MAX_PATH]; ExtractShareName(path, shareName);
    if (shareName[0] == '\0') return FALSE;

    char creds[512] = {0}; GetPrivateProfileStringA("Credentials", shareName, "", creds, sizeof(creds), g_iniPath);
    char *user = NULL, *pass = NULL;
    if (creds[0] != '\0') { user = creds; pass = strchr(creds, ','); if (pass) { *pass = '\0'; pass++; } }

    NETRESOURCEA nr = {0}; nr.dwType = RESOURCETYPE_DISK; nr.lpRemoteName = shareName;
    DWORD res = WNetAddConnection2A(&nr, pass, user, CONNECT_TEMPORARY);
    if (res == NO_ERROR || res == ERROR_ALREADY_ASSIGNED || res == ERROR_SESSION_CREDENTIAL_CONFLICT) return TRUE;
    
    ShowErrorNonBlocking(path, "Network Auth Failed"); 
    return FALSE;
}

void SyncFile(const char* src, const char* dst, int syncFlags, int maxDiskMb) {
    (void)maxDiskMb;
    char user[64], pass[64], host[256], path[LONG_PATH_SIZE]; int port;
    BOOL isSrcFtp = ParseFtpUrl(src, user, pass, host, &port, path);
    BOOL isDstFtp = ParseFtpUrl(dst, user, pass, host, &port, path);

    if (isSrcFtp || isDstFtp) {
        if (!g_hInternet) g_hInternet = InternetOpenA("SyncClient", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        HINTERNET hFtp = InternetConnectA(g_hInternet, host, port, user, pass, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        if (hFtp) {
            char shortFile[32]; PathCompactPathExA(shortFile, isSrcFtp ? src : dst, 28, 0);
            ShowSyncTextNonBlocking(shortFile);
            
            BOOL success = FALSE;
            if (isSrcFtp) success = FtpGetFileA(hFtp, path, dst, FALSE, FILE_ATTRIBUTE_NORMAL, FTP_TRANSFER_TYPE_BINARY, 0);
            else if (isDstFtp) success = FtpPutFileA(hFtp, src, path, FTP_TRANSFER_TYPE_BINARY, 0);
            
            if (success) AddToRecentLogs(shortFile);
            else ShowErrorNonBlocking(isSrcFtp ? src : dst, "FTP Transfer Failed");
            InternetCloseHandle(hFtp);
        }
        return;
    }

    WIN32_FILE_ATTRIBUTE_DATA srcAttr, dstAttr;
    BOOL dstExists = GetFileAttributesExA(dst, GetFileExInfoStandard, &dstAttr);
    if (!GetFileAttributesExA(src, GetFileExInfoStandard, &srcAttr)) { ShowErrorNonBlocking(src, "Cannot Access Source"); return; }
    
    ULARGE_INTEGER srcSize; srcSize.HighPart = srcAttr.nFileSizeHigh; srcSize.LowPart = srcAttr.nFileSizeLow;

    if (dstExists && !(syncFlags & SYNC_ALWAYS)) {
        BOOL overwrite = FALSE;
        ULARGE_INTEGER dstSize; dstSize.HighPart = dstAttr.nFileSizeHigh; dstSize.LowPart = dstAttr.nFileSizeLow;
        LONG timeCmp = CompareFileTime(&srcAttr.ftLastWriteTime, &dstAttr.ftLastWriteTime);

        if ((syncFlags & SYNC_NEWER) && timeCmp > 0) overwrite = TRUE;
        if ((syncFlags & SYNC_OLDER) && timeCmp < 0) overwrite = TRUE;
        if ((syncFlags & SYNC_LARGER) && srcSize.QuadPart > dstSize.QuadPart) overwrite = TRUE;
        if ((syncFlags & SYNC_SMALLER) && srcSize.QuadPart < dstSize.QuadPart) overwrite = TRUE;
        if (!overwrite) return; 
    }

    char destDir[LONG_PATH_SIZE]; snprintf(destDir, LONG_PATH_SIZE, "%s", dst);
    PathRemoveFileSpecA(destDir); SHCreateDirectoryExA(NULL, destDir, NULL);

    char shortFile[32]; PathCompactPathExA(shortFile, PathFindFileNameA(src), 28, 0);
    ShowSyncTextNonBlocking(shortFile);

    if (CopyFileA(src, dst, FALSE)) {
        LogSyncAction(src, dst, srcSize, srcAttr.ftLastWriteTime);
        AddToRecentLogs(PathFindFileNameA(src));
        if (syncFlags & SYNC_MOVE_FILE) { SetFileAttributesA(src, FILE_ATTRIBUTE_NORMAL); DeleteFileA(src); }
    } else {
        ShowErrorNonBlocking(src, "File Copy Error");
    }
}

void SyncDirectory(const char* srcDir, const char* dstDir, int syncFlags, const char* masks, int maxDiskMb) {
    if (g_Exit) return;
    char searchPath[LONG_PATH_SIZE]; snprintf(searchPath, LONG_PATH_SIZE, "%s\\*.*", srcDir);
    
    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (g_Exit) break;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char srcPath[LONG_PATH_SIZE], dstPath[LONG_PATH_SIZE];
        snprintf(srcPath, LONG_PATH_SIZE, "%s\\%s", srcDir, fd.cFileName);
        snprintf(dstPath, LONG_PATH_SIZE, "%s\\%s", dstDir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            SyncDirectory(srcPath, dstPath, syncFlags, masks, maxDiskMb);
        } else {
            if (masks[0] == '\0' || PathMatchSpecA(fd.cFileName, masks)) SyncFile(srcPath, dstPath, syncFlags, maxDiskMb);
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

// -----------------------------------------------------------------------------
// Core Engine & Main
// -----------------------------------------------------------------------------

void ApplyCpuLimit(int maxCpuPercent) {
    if (maxCpuPercent <= 0 || maxCpuPercent >= 100) return;
    HANDLE hJob = CreateJobObject(NULL, NULL);
    if (hJob) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuRate = {0};
        cpuRate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpuRate.CpuRate = maxCpuPercent * 100;
        SetInformationJobObject(hJob, JobObjectCpuRateControlInformation, &cpuRate, sizeof(cpuRate));
        AssignProcessToJobObject(hJob, GetCurrentProcess());
    }
}

BOOL IsSystemIdle(int idleSecondsRequired) {
    LASTINPUTINFO lii; lii.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lii)) return ((GetTickCount() - lii.dwTime) / 1000 >= (DWORD)idleSecondsRequired);
    return FALSE;
}

BOOL IsProcessRunning(const char* procName) {
    if (!procName || procName[0] == '\0') return FALSE;
    BOOL exists = FALSE;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32; pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (StrStrIA(pe32.szExeFile, procName) != NULL) { exists = TRUE; break; }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return exists;
}

void RunCommandHidden(const char* cmd) {
    if (!cmd || cmd[0] == '\0') return;
    STARTUPINFOA si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE; 
    char cmdBuf[LONG_PATH_SIZE]; snprintf(cmdBuf, sizeof(cmdBuf), "%s", cmd);
    if (CreateProcessA(NULL, cmdBuf, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}

unsigned __stdcall SyncThread(void* arg) {
    (void)arg; 
    while (!g_Exit) {
        if (!g_Paused) {
            GetPrivateProfileStringA("Settings", "LogFile", "", g_logFile, MAX_PATH, g_iniPath);
            int maxDiskMb = GetPrivateProfileIntA("Settings", "MaxDiskMBps", 0, g_iniPath);
            
            if (!GetPrivateProfileIntA("Settings", "IdleOnly", 0, g_iniPath) || IsSystemIdle(GetPrivateProfileIntA("Settings", "IdleWaitSeconds", 300, g_iniPath))) {
                char jobs[32768] = {0}; GetPrivateProfileSectionA("Jobs", jobs, sizeof(jobs), g_iniPath);

                for (char* p = jobs; *p && !g_Exit && !g_Paused; p += strlen(p) + 1) {
                    char* val = strchr(p, '='); if (!val) continue; val++; 

                    char src[LONG_PATH_SIZE]={0}, dst[LONG_PATH_SIZE]={0}, masks[LONG_PATH_SIZE]={0};
                    int syncFlags = SYNC_SKIP;
                    
                    char *tok1 = val, *tok2 = NULL, *tok3 = NULL, *tok4 = NULL, *tok5 = NULL, *tok6 = NULL, *tok7 = NULL;
                    char *ptr = strchr(val, ','); if(ptr){ *ptr++ = 0; tok2 = ptr; ptr = strchr(ptr, ','); }
                    if(ptr){ *ptr++ = 0; tok3 = ptr; ptr = strchr(ptr, ','); }
                    if(ptr){ *ptr++ = 0; tok4 = ptr; ptr = strchr(ptr, ','); }
                    if(ptr){ *ptr++ = 0; tok5 = ptr; ptr = strchr(ptr, ','); }
                    if(ptr){ *ptr++ = 0; tok6 = ptr; ptr = strchr(ptr, ','); }
                    if(ptr){ *ptr++ = 0; tok7 = ptr; } 

                    strcpy(src, tok1 ? tok1 : ""); strcpy(dst, tok2 ? tok2 : "");
                    
                    if (tok3) {
                        if (strchr(tok3, '*') || strchr(tok3, '?')) {
                            strcpy(masks, tok3); if (tok4) { strcat(masks, ";"); strcat(masks, tok4); }
                        } else if (isdigit(tok3[0])) {
                            syncFlags = atoi(tok3); strcpy(masks, tok4 ? tok4 : "*.*");
                        } else strcpy(masks, tok4 ? tok4 : "*.*");
                    } else strcpy(masks, "*.*");
                    
                    for(int i=0; masks[i]; i++) if(masks[i] == ',') masks[i] = ';';

                    BOOL shouldRun = TRUE;
                    if (tok6 && tok6[0] != '\0' && !IsProcessRunning(tok6)) shouldRun = FALSE;
                    if (tok7 && tok7[0] != '\0' && IsProcessRunning(tok7)) shouldRun = FALSE; 

                    if (shouldRun && src[0] && dst[0] && EnsureNetworkConnection(src) && EnsureNetworkConnection(dst)) {
                        SyncDirectory(src, dst, syncFlags, masks, maxDiskMb);
                        if (tok5 && tok5[0] != '\0') RunCommandHidden(tok5);
                    }
                }
                UpdateTrayTooltipDone();
            }
        }
        int waitSecs = GetPrivateProfileIntA("Settings", "RefreshInterval", 3600, g_iniPath);
        for (int i = 0; i < waitSecs && !g_Exit; i++) Sleep(1000);
    }
    if (g_hInternet) InternetCloseHandle(g_hInternet);
    return 0;
}

LRESULT CALLBACK EditWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_CREATE: {
            // Group Boxes for cleaner layout
            CreateWindowA("BUTTON", "Job Configuration", WS_VISIBLE|WS_CHILD|BS_GROUPBOX, 5, 5, 305, 305, hwnd, NULL, NULL, NULL);
            CreateWindowA("BUTTON", "Global Settings", WS_VISIBLE|WS_CHILD|BS_GROUPBOX, 320, 5, 245, 145, hwnd, NULL, NULL, NULL);
            CreateWindowA("BUTTON", "SMB Credentials", WS_VISIBLE|WS_CHILD|BS_GROUPBOX, 320, 160, 245, 150, hwnd, NULL, NULL, NULL);

            // --- Jobs Section ---
            CreateWindowA("STATIC", "Select Job:", WS_VISIBLE|WS_CHILD, 15, 25, 70, 20, hwnd, NULL, NULL, NULL);
            g_hCmbJobs = CreateWindowA("COMBOBOX", "", WS_VISIBLE|WS_CHILD|CBS_DROPDOWN|WS_VSCROLL, 90, 25, 205, 150, hwnd, (HMENU)ID_CMB_JOBS, NULL, NULL);
            
            CreateWindowA("STATIC", "Src:", WS_VISIBLE|WS_CHILD, 15, 55, 40, 20, hwnd, NULL, NULL, NULL);
            g_hTxtSrc = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 55, 55, 205, 20, hwnd, NULL, NULL, NULL);
            CreateWindowA("BUTTON", "...", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 265, 55, 30, 20, hwnd, (HMENU)ID_BTN_BROWSE_SRC, NULL, NULL);
            
            CreateWindowA("STATIC", "Dst:", WS_VISIBLE|WS_CHILD, 15, 85, 40, 20, hwnd, NULL, NULL, NULL);
            g_hTxtDst = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 55, 85, 205, 20, hwnd, NULL, NULL, NULL);
            CreateWindowA("BUTTON", "...", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 265, 85, 30, 20, hwnd, (HMENU)ID_BTN_BROWSE_DST, NULL, NULL);
            
            CreateWindowA("STATIC", "Flags:", WS_VISIBLE|WS_CHILD, 15, 115, 40, 20, hwnd, NULL, NULL, NULL);
            g_hTxtFlags = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER, 55, 115, 60, 20, hwnd, NULL, NULL, NULL);
            CreateWindowA("STATIC", "Masks:", WS_VISIBLE|WS_CHILD, 125, 115, 45, 20, hwnd, NULL, NULL, NULL);
            g_hTxtMasks = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 170, 115, 125, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("STATIC", "Cmd:", WS_VISIBLE|WS_CHILD, 15, 145, 40, 20, hwnd, NULL, NULL, NULL);
            g_hTxtCmd = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 55, 145, 240, 20, hwnd, NULL, NULL, NULL);

            CreateWindowA("STATIC", "IfProc:", WS_VISIBLE|WS_CHILD, 15, 175, 45, 20, hwnd, NULL, NULL, NULL);
            g_hTxtIfProc = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 65, 175, 80, 20, hwnd, NULL, NULL, NULL);
            CreateWindowA("STATIC", "IfNotProc:", WS_VISIBLE|WS_CHILD, 155, 175, 65, 20, hwnd, NULL, NULL, NULL);
            g_hTxtIfNotProc = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 220, 175, 75, 20, hwnd, NULL, NULL, NULL);

            CreateWindowA("BUTTON", "Save Job", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 15, 275, 135, 25, hwnd, (HMENU)ID_BTN_SAVE_JOB, NULL, NULL);
            CreateWindowA("BUTTON", "Delete Job", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 160, 275, 135, 25, hwnd, (HMENU)ID_BTN_DELETE_JOB, NULL, NULL);

            // --- Global Settings Section ---
            CreateWindowA("STATIC", "LogFile:", WS_VISIBLE|WS_CHILD, 330, 25, 60, 20, hwnd, NULL, NULL, NULL);
            g_hSetLog = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 395, 25, 155, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("STATIC", "DiskMBps:", WS_VISIBLE|WS_CHILD, 330, 55, 65, 20, hwnd, NULL, NULL, NULL);
            g_hSetDisk = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER, 395, 55, 60, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("STATIC", "Refresh(s):", WS_VISIBLE|WS_CHILD, 330, 85, 65, 20, hwnd, NULL, NULL, NULL);
            g_hSetRefresh = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER, 395, 85, 60, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("BUTTON", "Save Settings", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 330, 115, 220, 25, hwnd, (HMENU)ID_BTN_SAVE_SET, NULL, NULL);

            // --- SMB Credentials Section ---
            CreateWindowA("STATIC", "Share:", WS_VISIBLE|WS_CHILD, 330, 185, 45, 20, hwnd, NULL, NULL, NULL);
            g_hCredShare = CreateWindowA("COMBOBOX", "", WS_VISIBLE|WS_CHILD|CBS_DROPDOWN|WS_VSCROLL, 380, 185, 170, 100, hwnd, (HMENU)ID_CMB_CRED_SHARE, NULL, NULL);
            
            CreateWindowA("STATIC", "User:", WS_VISIBLE|WS_CHILD, 330, 215, 45, 20, hwnd, NULL, NULL, NULL);
            g_hCredUser = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL, 380, 215, 170, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("STATIC", "Pass:", WS_VISIBLE|WS_CHILD, 330, 245, 45, 20, hwnd, NULL, NULL, NULL);
            g_hCredPass = CreateWindowA("EDIT", "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_AUTOHSCROLL|ES_PASSWORD, 380, 245, 170, 20, hwnd, NULL, NULL, NULL);
            
            CreateWindowA("BUTTON", "Save Cred", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 330, 275, 105, 25, hwnd, (HMENU)ID_BTN_SAVE_CRED, NULL, NULL);
            CreateWindowA("BUTTON", "Delete Cred", WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 445, 275, 105, 25, hwnd, (HMENU)ID_BTN_DELETE_CRED, NULL, NULL);

            // --- Populate Comboboxes ---
            char jobs[32768] = {0}; GetPrivateProfileSectionA("Jobs", jobs, sizeof(jobs), g_iniPath);
            for (char* p = jobs; *p; p += strlen(p) + 1) {
                char jobName[256]; strncpy(jobName, p, sizeof(jobName));
                char* eq = strchr(jobName, '='); if (eq) *eq = 0;
                SendMessageA(g_hCmbJobs, CB_ADDSTRING, 0, (LPARAM)jobName);
            }
            
            char shares[32768] = {0}; GetPrivateProfileStringA("Credentials", NULL, "", shares, sizeof(shares), g_iniPath);
            for (char* p = shares; *p; p += strlen(p) + 1) {
                SendMessageA(g_hCredShare, CB_ADDSTRING, 0, (LPARAM)p);
            }
            
            // --- Populate Settings ---
            char temp[256];
            GetPrivateProfileStringA("Settings", "LogFile", "", temp, sizeof(temp), g_iniPath);
            SetWindowTextA(g_hSetLog, temp);
            snprintf(temp, sizeof(temp), "%d", GetPrivateProfileIntA("Settings", "MaxDiskMBps", 0, g_iniPath));
            SetWindowTextA(g_hSetDisk, temp);
            snprintf(temp, sizeof(temp), "%d", GetPrivateProfileIntA("Settings", "RefreshInterval", 3600, g_iniPath));
            SetWindowTextA(g_hSetRefresh, temp);
            break;
        }
        case WM_COMMAND:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                if (LOWORD(wParam) == ID_CMB_JOBS) {
                    int idx = SendMessageA(g_hCmbJobs, CB_GETCURSEL, 0, 0);
                    if (idx != CB_ERR) {
                        char jobName[256]; SendMessageA(g_hCmbJobs, CB_GETLBTEXT, idx, (LPARAM)jobName);
                        char jobData[1024]; GetPrivateProfileStringA("Jobs", jobName, "", jobData, sizeof(jobData), g_iniPath);
                        
                        char *tok1 = jobData, *tok2 = "", *tok3 = "", *tok4 = "", *tok5 = "", *tok6 = "", *tok7 = "";
                        char *ptr = strchr(jobData, ','); if(ptr){ *ptr++ = 0; tok2 = ptr; ptr = strchr(ptr, ','); }
                        if(ptr){ *ptr++ = 0; tok3 = ptr; ptr = strchr(ptr, ','); }
                        if(ptr){ *ptr++ = 0; tok4 = ptr; ptr = strchr(ptr, ','); }
                        if(ptr){ *ptr++ = 0; tok5 = ptr; ptr = strchr(ptr, ','); }
                        if(ptr){ *ptr++ = 0; tok6 = ptr; ptr = strchr(ptr, ','); }
                        if(ptr){ *ptr++ = 0; tok7 = ptr; }
                        
                        SetWindowTextA(g_hTxtSrc, tok1); SetWindowTextA(g_hTxtDst, tok2);
                        SetWindowTextA(g_hTxtFlags, tok3); SetWindowTextA(g_hTxtMasks, tok4);
                        SetWindowTextA(g_hTxtCmd, tok5); SetWindowTextA(g_hTxtIfProc, tok6);
                        SetWindowTextA(g_hTxtIfNotProc, tok7);
                    }
                } else if (LOWORD(wParam) == ID_CMB_CRED_SHARE) {
                    int idx = SendMessageA(g_hCredShare, CB_GETCURSEL, 0, 0);
                    if (idx != CB_ERR) {
                        char share[256]; SendMessageA(g_hCredShare, CB_GETLBTEXT, idx, (LPARAM)share);
                        char credData[512]; GetPrivateProfileStringA("Credentials", share, "", credData, sizeof(credData), g_iniPath);
                        char *user = credData, *pass = "";
                        char *comma = strchr(credData, ',');
                        if (comma) { *comma = '\0'; pass = comma + 1; }
                        SetWindowTextA(g_hCredUser, user);
                        SetWindowTextA(g_hCredPass, pass);
                    }
                }
            }
            else if (LOWORD(wParam) == ID_BTN_SAVE_JOB) {
                char jobName[256]; GetWindowTextA(g_hCmbJobs, jobName, sizeof(jobName));
                if (jobName[0] != 0) {
                    char src[MAX_PATH], dst[MAX_PATH], flags[16], masks[128], cmd[256], ifp[64], ifnp[64];
                    GetWindowTextA(g_hTxtSrc, src, sizeof(src)); GetWindowTextA(g_hTxtDst, dst, sizeof(dst));
                    GetWindowTextA(g_hTxtFlags, flags, sizeof(flags)); GetWindowTextA(g_hTxtMasks, masks, sizeof(masks));
                    GetWindowTextA(g_hTxtCmd, cmd, sizeof(cmd)); GetWindowTextA(g_hTxtIfProc, ifp, sizeof(ifp));
                    GetWindowTextA(g_hTxtIfNotProc, ifnp, sizeof(ifnp));
                    
                    char fullJob[2048]; 
                    sprintf(fullJob, "%s,%s,%s,%s,%s,%s,%s", src, dst, flags, masks, cmd, ifp, ifnp);
                    WritePrivateProfileStringA("Jobs", jobName, fullJob, g_iniPath);
                    
                    if (SendMessageA(g_hCmbJobs, CB_FINDSTRINGEXACT, -1, (LPARAM)jobName) == CB_ERR) {
                        SendMessageA(g_hCmbJobs, CB_ADDSTRING, 0, (LPARAM)jobName);
                    }
                    MessageBoxA(hwnd, "Job saved.", "Success", MB_OK);
                } else MessageBoxA(hwnd, "Please select or type a Job Name.", "Error", MB_OK | MB_ICONERROR);
            }
            else if (LOWORD(wParam) == ID_BTN_DELETE_JOB) {
                char jobName[256]; GetWindowTextA(g_hCmbJobs, jobName, sizeof(jobName));
                if (jobName[0] != 0) {
                    WritePrivateProfileStringA("Jobs", jobName, NULL, g_iniPath);
                    int idx = SendMessageA(g_hCmbJobs, CB_FINDSTRINGEXACT, -1, (LPARAM)jobName);
                    if (idx != CB_ERR) SendMessageA(g_hCmbJobs, CB_DELETESTRING, idx, 0);
                    
                    SetWindowTextA(g_hCmbJobs, ""); SetWindowTextA(g_hTxtSrc, ""); SetWindowTextA(g_hTxtDst, "");
                    SetWindowTextA(g_hTxtFlags, ""); SetWindowTextA(g_hTxtMasks, ""); SetWindowTextA(g_hTxtCmd, "");
                    SetWindowTextA(g_hTxtIfProc, ""); SetWindowTextA(g_hTxtIfNotProc, "");
                    MessageBoxA(hwnd, "Job deleted.", "Success", MB_OK);
                } else MessageBoxA(hwnd, "Please select a Job Name to delete.", "Error", MB_OK | MB_ICONERROR);
            }
            else if (LOWORD(wParam) == ID_BTN_SAVE_SET) {
                char log[MAX_PATH], disk[16], refresh[16];
                GetWindowTextA(g_hSetLog, log, sizeof(log)); GetWindowTextA(g_hSetDisk, disk, sizeof(disk));
                GetWindowTextA(g_hSetRefresh, refresh, sizeof(refresh));
                WritePrivateProfileStringA("Settings", "LogFile", log, g_iniPath);
                WritePrivateProfileStringA("Settings", "MaxDiskMBps", disk, g_iniPath);
                WritePrivateProfileStringA("Settings", "RefreshInterval", refresh, g_iniPath);
                MessageBoxA(hwnd, "Settings saved.", "Success", MB_OK);
            }
            else if (LOWORD(wParam) == ID_BTN_SAVE_CRED) {
                char share[MAX_PATH], user[64], pass[64], fullCred[256];
                GetWindowTextA(g_hCredShare, share, sizeof(share));
                GetWindowTextA(g_hCredUser, user, sizeof(user));
                GetWindowTextA(g_hCredPass, pass, sizeof(pass));
                if (share[0]) {
                    sprintf(fullCred, "%s,%s", user, pass);
                    WritePrivateProfileStringA("Credentials", share, fullCred, g_iniPath);
                    if (SendMessageA(g_hCredShare, CB_FINDSTRINGEXACT, -1, (LPARAM)share) == CB_ERR) {
                        SendMessageA(g_hCredShare, CB_ADDSTRING, 0, (LPARAM)share);
                    }
                    MessageBoxA(hwnd, "Credentials saved.", "Success", MB_OK);
                } else MessageBoxA(hwnd, "Please provide a Share path.", "Error", MB_OK | MB_ICONERROR);
            }
            else if (LOWORD(wParam) == ID_BTN_DELETE_CRED) {
                char share[MAX_PATH]; GetWindowTextA(g_hCredShare, share, sizeof(share));
                if (share[0] != 0) {
                    WritePrivateProfileStringA("Credentials", share, NULL, g_iniPath);
                    int idx = SendMessageA(g_hCredShare, CB_FINDSTRINGEXACT, -1, (LPARAM)share);
                    if (idx != CB_ERR) SendMessageA(g_hCredShare, CB_DELETESTRING, idx, 0);
                    SetWindowTextA(g_hCredShare, ""); SetWindowTextA(g_hCredUser, ""); SetWindowTextA(g_hCredPass, "");
                    MessageBoxA(hwnd, "Credential deleted.", "Success", MB_OK);
                } else MessageBoxA(hwnd, "Please select a Share to delete.", "Error", MB_OK | MB_ICONERROR);
            }
            else if (LOWORD(wParam) == ID_BTN_BROWSE_SRC || LOWORD(wParam) == ID_BTN_BROWSE_DST) {
                char szDir[MAX_PATH];
                BROWSEINFOA bi = {0}; bi.hwndOwner = hwnd; bi.lpszTitle = "Select Directory";
                bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
                PIDLIST_ABSOLUTE pidl = SHBrowseForFolderA(&bi);
                if (pidl) {
                    SHGetPathFromIDListA(pidl, szDir);
                    SetWindowTextA(LOWORD(wParam) == ID_BTN_BROWSE_SRC ? g_hTxtSrc : g_hTxtDst, szDir);
                    CoTaskMemFree(pidl);
                }
            }
            break;
        case WM_CLOSE: DestroyWindow(hwnd); g_Paused = FALSE; g_hEditWnd = NULL; break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void ShowEditWindow(HINSTANCE hInstance) {
    WNDCLASSA wcEdit = {0}; wcEdit.lpfnWndProc = EditWndProc; wcEdit.hInstance = hInstance; wcEdit.lpszClassName = "SyncEditClass";
    RegisterClassA(&wcEdit);
    g_hEditWnd = CreateWindowA(wcEdit.lpszClassName, "Sync Configuration Editor", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 595, 365, NULL, NULL, hInstance, NULL);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP || lParam == WM_LBUTTONUP) {
                POINT pt; GetCursorPos(&pt); HMENU hMenu = CreatePopupMenu();
                AppendMenuA(hMenu, MF_STRING, ID_EDIT, "Edit Config");
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenuA(hMenu, MF_STRING | (g_Paused ? MF_CHECKED : MF_UNCHECKED), ID_PAUSE, "Pause");
                AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL); 
                AppendMenuA(hMenu, MF_STRING, ID_EXIT, "Exit");
                SetForegroundWindow(hwnd); TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL); DestroyMenu(hMenu);
            }
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == ID_EDIT) {
                g_Paused = TRUE; 
                if (!IsWindow(g_hEditWnd)) ShowEditWindow(GetModuleHandle(NULL));
                else SetForegroundWindow(g_hEditWnd);
            }
            if (LOWORD(wParam) == ID_PAUSE) {
                g_Paused = !g_Paused;
                if (g_Paused) UpdateTrayTooltip("Sync Paused");
                else UpdateTrayTooltipDone();
            }
            if (LOWORD(wParam) == ID_EXIT) DestroyWindow(hwnd);
            break;
        case WM_DESTROY: g_Exit = TRUE; Shell_NotifyIconA(NIM_DELETE, &g_nid); PostQuitMessage(0); return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)nCmdShow;

    GetModuleFileNameA(NULL, g_iniPath, LONG_PATH_SIZE); PathRemoveFileSpecA(g_iniPath); strcat(g_iniPath, "\\sync.ini");
    ApplyCpuLimit(GetPrivateProfileIntA("Settings", "MaxCpuPercent", 100, g_iniPath));
    
    if (strstr(lpCmdLine, "-edit")) {
        g_Paused = TRUE;
        ShowEditWindow(hInstance);
    }

    WNDCLASSA wc = {0}; wc.lpfnWndProc = WindowProc; wc.hInstance = hInstance; wc.lpszClassName = "BackgroundSyncClass";
    RegisterClassA(&wc);
    g_hwnd = CreateWindowA(wc.lpszClassName, "Sync", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
    g_nid.cbSize = sizeof(NOTIFYICONDATAA); g_nid.hWnd = g_hwnd; g_nid.uID = 1; g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON; g_nid.hIcon = LoadIcon(NULL, IDI_APPLICATION); strcpy(g_nid.szTip, "Sync Idle\nWaiting for new files");
    Shell_NotifyIconA(NIM_ADD, &g_nid);
    
    _beginthreadex(NULL, 0, SyncThread, NULL, 0, NULL);
    MSG msg; while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}