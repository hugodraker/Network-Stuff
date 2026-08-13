/*
 * ============================================================================
 * 
 *  SMB2 Server Implementation - PUBLIC DOMAIN
 *  
 *  LICENSE: This code is released into the PUBLIC DOMAIN worldwide.
 *           Where public domain dedication is not legally recognized,
 *           you may treat this as MIT/0/BSD-0 equivalent.
 *  
 *  DISCLAIMER: This software is provided "AS IS", WITHOUT ANY WARRANTY,
 *              EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES
 *              OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
 *              NON-INFRINGEMENT. THIS CODE IS NOT FIT FOR ANY PURPOSE.
 *              DO NOT USE IN PRODUCTION ENVIRONMENTS. NO AUTHENTICATION,
 *              ENCRYPTION, OR SECURITY MECHANISMS ARE IMPLEMENTED.
 *  
 *  COMPILATION INSTRUCTIONS (MinGW-w64 on Windows):
 *      gcc -o smb2server.exe smb2server.c -lwsock32 -lws2_32
 *      
 *  COMPILATION INSTRUCTIONS (Cross-compile from Linux):
 *      x86_64-w64-mingw32-gcc -static -o smb2server.exe smb2server.c -lwsock32 -lws2_32
 *      
 *  COMPILATION INSTRUCTIONS (32-bit Windows from Linux):
 *      i686-w64-mingw32-gcc -static -o smb2server.exe smb2server.c -lwsock32 -lws2_32
 *      
 *  RUNTIME:
 *      ./smb2server.exe [--port PORT] [--share PATH]
 *      
 *  TEST CONNECTION FROM WINDOWS:
 *      net use Z: \\127.0.0.1\share
 *      dir Z:\
 *  
 *  AUTHOR: Anonymous (Public Domain Contribution)
 *  DATE: August 2025
 *  
 *  REFERENCES:
 *    - MS-SMB2 Protocol Specification: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
 *    - RFC 4506 (XDR): For certain type mappings
 *  
 *  WARNING: This is EDUCATIONAL CODE ONLY. It lacks:
 *    - Authentication (NTLM/Kerberos)
 *    - Encryption (SMB3 signing/GCM)
 *    - Proper ACL handling
 *    - Buffer overflow protections
 *    - Input validation sanitization
 *    - Reentrancy/thread safety
 *    - Memory leak prevention
 *    - Resource limits
 *    - Anti-replay protection
 *    - Oplock/lease support
 *    - Compound request batching
 *  ============================================================================
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h> /* <-- ADDED MISSING HEADER */

#pragma comment(lib, "ws2_32.lib")

/* ============================================================================
 *  Constants and Configuration
 * ============================================================================ */

#define SMB2_SERVER_VERSION   "0.1-public-domain"
#define DEFAULT_PORT          445
#define DEFAULT_SHARE_PATH    "."
#define MAX_CONNECTIONS       10
#define BUFFER_SIZE           65536
#define SMB2_HEADER_SIZE      64
#define MAX_OPEN_FILES        64
#define MAX_PATH_LEN          1024
#define SERVER_GUID_SIZE      16

/* Dialect versions */
#define SMB2_DIALECT_0202     0x0202  /* SMB 2.0.2 */
#define SMB2_DIALECT_0210     0x0210  /* SMB 2.1 */
#define SMB2_DIALECT_0300     0x0300  /* SMB 3.0 */
#define SMB2_DIALECT_0302     0x0302  /* SMB 3.0.2 */
#define SMB2_DIALECT_0311     0x0311  /* SMB 3.1.1 */

/* SMB2 Commands */
#define SMB2_NEGOTIATE        0x0000
#define SMB2_SESSION_SETUP    0x0001
#define SMB2_LOGOFF           0x0002
#define SMB2_TREE_CONNECT     0x0003
#define SMB2_TREE_DISCONNECT  0x0004
#define SMB2_CREATE           0x0005
#define SMB2_CLOSE            0x0006
#define SMB2_FLUSH            0x0007
#define SMB2_READ             0x0008
#define SMB2_WRITE            0x0009
#define SMB2_LOCK             0x000A
#define SMB2_IOCTL            0x000B
#define SMB2_CANCEL           0x000C
#define SMB2_ECHO             0x000D
#define SMB2_QUERY_DIRECTORY  0x000E
#define SMB2_CHANGE_NOTIFY    0x000F
#define SMB2_QUERY_INFO       0x0010
#define SMB2_SET_INFO         0x0011
#define SMB2_OPLOCK_BREAK     0x0012

/* NT Status Codes (stub - partial list) */
#define STATUS_SUCCESS              0x00000000
#define STATUS_NOT_IMPLEMENTED      0xC0000002
#define STATUS_INVALID_PARAMETER    0xC000000D
#define STATUS_ACCESS_DENIED        0xC0000022
#define STATUS_FILE_CLOSED          0xC0000094
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_BUFFER_OVERFLOW      0x80000005
#define STATUS_END_OF_FILE          0xC0000011
#define STATUS_NOT_SUPPORTED        0xC00000BB

/* Share types */
#define SMB2_share_type_DISK        0x00000001
#define SMB2_share_type_PIPE        0x00000002
#define SMB2_share_type_PRINT       0x00000003

/* ============================================================================
 *  SMB2 Packet Structures (per MS-SMB2 spec)
 * ============================================================================ */

#pragma pack(push, 1)

/* SMB2 Common Header (64 bytes) */
typedef struct {
    uint8_t  ProtocolId[4];         /* "SMB" = 0xFE534D42 */
    uint16_t StructureSize;         /* Must be 64 for SMB2+ */
    uint16_t CreditCharge;          /* Credits charged/requested */
    union {
        uint32_t ChannelSequence;
        uint32_t Status;
    };
    uint16_t Command;               /* Command type */
    union {
        uint16_t CreditRequestResponse;
        uint16_t Reserved;
    };
    uint32_t Flags;                 /* 0=sync, 1=async, 2=redirect */
    uint32_t NextCommand;           /* Offset to next compound request */
    union {
        uint64_t MessageId;         /* Unique message identifier */
        uint64_t AsyncId;           /* Used when async flag set */
    } MessageIdUnion;
    uint64_t SessionId;             /* Session identifier */
    uint8_t  Signature[16];         /* HMAC-SHA256 if signing enabled */
} Smb2Header_t;

/* NEGOTIATE Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 36 */
    uint16_t SecurityMode;          /* Signing options */
    uint16_t Capabilities;          /* DFS, Leasing, etc. */
    uint32_t Guid[4];               /* Client GUID */
    uint32_t NegotiateContextCount; /* Extended capabilities count */
    uint16_t Dialects[];            /* Array of supported dialects */
} Smb2NegotiateRequest_t;

/* NEGOTIATE Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 65 + SecurityBlobOffset */
    uint16_t SecurityMode;          /* Selected security mode */
    uint16_t DialectRevision;       /* Selected dialect version */
    uint16_t NegotiateContextCount; /* Context items for SMB3+ */
    uint8_t  ServerGuid[16];        /* Unique server identifier */
    uint32_t Capabilities;          /* Server capabilities */
    uint32_t MaxTransactSize;       /* Maximum transaction size */
    uint32_t MaxReadSize;           /* Maximum read size */
    uint32_t MaxWriteSize;          /* Maximum write size */
    uint64_t SystemTime;            /* Server time (FILETIME format) */
    uint64_t ServerStartTime;       /* Server boot time */
    uint16_t SecurityBufferOffset;  /* Offset to security blob */
    uint16_t SecurityBufferLength;  /* Length of security data */
    uint32_t NegotiateContextOffset;/* Start of contexts */
} Smb2NegotiateResponse_t;

/* SESSION_SETUP Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 25 */
    uint8_t  Flags;                 /* Session flags */
    uint8_t  SecurityMode;          /* Session security mode */
    uint32_t Capabilities;          /* Session capabilities */
    uint32_t Channel;               /* Channel type */
    uint16_t SecurityBufferOffset;  /* Offset to security blob */
    uint16_t SecurityBufferLength;  /* Length of security buffer */
    uint64_t PreviousSessionId;     /* For reconnection */
} Smb2SessionSetupRequest_t;

/* SESSION_SETUP Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 9 */
    uint16_t SessionFlags;          /* Session flags */
    uint16_t SecurityBufferOffset;  /* Offset to security blob */
    uint16_t SecurityBufferLength;  /* Length of security buffer */
} Smb2SessionSetupResponse_t;

/* TREE_CONNECT Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 9 */
    uint16_t Reserved;
    uint16_t PathOffset;            /* Offset to path */
    uint16_t PathLength;            /* Length of path */
} Smb2TreeConnectRequest_t;

/* TREE_CONNECT Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 16 */
    uint8_t  ShareType;             /* Disk, Pipe, Print */
    uint8_t  Reserved;
    uint32_t ShareFlags;            /* Share-specific flags */
    uint32_t Capability;            /* Share capabilities */
    uint32_t AccessMask;            /* Granted access */
} Smb2TreeConnectResponse_t;

/* CREATE Request (open/create file) */
typedef struct {
    uint16_t StructureSize;         /* Must be 57 */
    uint8_t  SecurityContextFlags;
    uint16_t CreateFlags;
    uint32_t Reserved;
    uint64_t AllocationSize;
    uint32_t NamedPipeType;
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    uint8_t  Buffer[];
} Smb2CreateRequest_t;

/* CREATE Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 89 */
    uint8_t  OplockLevel;
    uint8_t  Flags;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint16_t CreateContextsOffset;
    uint16_t CreateContextsLength;
    uint8_t  FileKey[16];
} Smb2CreateResponse_t;

/* CLOSE Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 24 */
    uint16_t Flags;                 /* 0 or 1 = flush before close */
    uint64_t PersistentFileID;
    uint64_t VolatileFileID;
} Smb2CloseRequest_t;

/* CLOSE Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 24 */
    uint16_t Reserved;
    uint32_t Flags;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t DeletePending;
} Smb2CloseResponse_t;

/* READ Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 49 */
    uint8_t  Padding;
    uint8_t  Flags;
    uint32_t Length;                /* Number of bytes to read */
    uint64_t Offset;                /* Byte offset */
    uint64_t FileID[2];
    uint32_t MinimumCount;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t ReadChannelInfoOffset;
    uint16_t ReadChannelInfoLength;
    uint32_t BufferOffset;
} Smb2ReadRequest_t;

/* READ Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 17 */
    uint8_t  DataOffset;            /* Offset to data */
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Flags;
} Smb2ReadResponse_t;

/* WRITE Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 49 */
    uint16_t DataOffset;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileID[2];
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
} Smb2WriteRequest_t;

/* WRITE Response */
typedef struct {
    uint16_t StructureSize;         /* Must be 17 */
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
} Smb2WriteResponse_t;

/* QUERY_DIRECTORY Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 33 */
    uint8_t  FileInformationClass;
    uint8_t  Flags;
    uint32_t FileIndex;
    uint64_t FileID[2];
    uint16_t FileNameOffset;
    uint16_t FileNameLength;
    uint32_t OutputBufferLength;
} Smb2QueryDirectoryRequest_t;

/* QUERY_DIRECTORY Response */
typedef struct {
    uint16_t StructureSize;         /* Varies */
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
} Smb2QueryDirectoryResponse_t;

/* QUERY_INFO Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 41 */
    uint8_t  InfoType;
    uint8_t  FileInfoClass;
    uint32_t OutputBufferLength;
    uint16_t AdditionalInformation;
    uint16_t Flags;
    uint64_t FileID[2];
} Smb2QueryInfoRequest_t;

/* QUERY_INFO Response */
typedef struct {
    uint16_t StructureSize;
    uint16_t OutputBufferOffset;
    uint32_t OutputBufferLength;
} Smb2QueryInfoResponse_t;

/* FLUSH Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 24 */
    uint16_t Reserved;
    uint64_t PersistentFileID;
    uint64_t VolatileFileID;
} Smb2FlushRequest_t;

/* LOCK Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 57 */
    uint16_t LockCount;
    uint32_t Reserved;
    uint64_t FileID[2];
} Smb2LockRequest_t;

/* IOCTL Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 57 */
    uint16_t Flags;
    uint32_t CtlCode;
    uint64_t FileID[2];
    uint32_t InputOffset;
    uint32_t InputLength;
    uint32_t MaxOutputResponse;
    uint32_t OutputOffset;
    uint32_t ControlFlags;
} Smb2IoctlRequest_t;

/* ECHO Request/Response - minimal same structure */
typedef struct {
    uint16_t StructureSize;         /* Must be 4 */
    uint16_t Reserved;
} Smb2EchoRequest_t;

/* CANCEL Request */
typedef struct {
    uint16_t StructureSize;         /* Must be 8 */
    uint8_t  Reserved;
    uint8_t  CancelRequestId;
} Smb2CancelRequest_t;

/* FILE_ID_BOTH_DIR_INFO - directory entry */
typedef struct {
    uint32_t NextEntryOffset;
    uint32_t FileIndex;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t EndOfFile;
    uint64_t AllocationSize;
    uint32_t FileAttributes;
    uint32_t FileNameLength;
    uint32_t EaSize;
    uint8_t  ShortNameLength;
    uint8_t  ShortName[24];
    uint8_t  FileName[];
} FileInfoFileBothDir_t;

#pragma pack(pop)

/* ============================================================================
 *  Internal Types
 * ============================================================================ */

typedef enum {
    STATE_UNINITIALIZED = 0,
    STATE_NEGOTIATING,
    STATE_SESSION_REQUIRED,
    STATE_SESSION_ESTABLISHED,
    STATE_TREE_CONNECTED,
    STATE_CLOSED
} ConnectionState_t;

typedef struct {
    HANDLE hFile;
    char   Path[MAX_PATH_LEN];
    int    IsOpen;
    int    IsDirectory;
    uint64_t FileKey[2];  /* Persistent + Volatile ID */
} FileHandle_t;

typedef struct {
    SOCKET      Socket;
    struct sockaddr_in Address; /* <-- ADDED struct KEYWORD */
    ConnectionState_t State;
    uint64_t    SessionId;
    uint64_t    TreeId;
    FileHandle_t OpenFiles[MAX_OPEN_FILES];
    int         NumOpenFiles;
    uint8_t     ServerGuid[SERVER_GUID_SIZE];
} ClientContext_t;

typedef struct {
    uint16_t Port;
    char     SharePath[MAX_PATH_LEN];
    int      ShareReadOnly;
    int      VerboseLogging;
} ServerConfig_t;

/* Global configuration */
static ServerConfig_t g_Config = {
    .Port = DEFAULT_PORT,
    .SharePath = DEFAULT_SHARE_PATH,
    .ShareReadOnly = 0,
    .VerboseLogging = 0
};

/* Global state */
static volatile int g_Running = 1;
static CRITICAL_SECTION g_FileMutex;

/* ============================================================================
 *  Utility Functions
 * ============================================================================ */

/* Generate random GUID (for server identification) */
static void GenerateGUID(uint8_t *guid) {
    GUID sysGuid;
    CoInitialize(NULL);
    CoCreateGuid(&sysGuid);
    memcpy(guid, &sysGuid, sizeof(GUID));
    CoUninitialize();
}

/* Convert UTF-8 to wide string (Windows Unicode) */
static wchar_t* Utf8ToWide(const char *utf8) {
    if (!utf8) return NULL;
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t *wide = (wchar_t*)malloc(len * sizeof(wchar_t));
    if (!wide) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, len);
    return wide;
}

/* Convert wide string to UTF-8 */
static char* WideToUtf8(const wchar_t *wide) {
    if (!wide) return NULL;
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char *utf8 = (char*)malloc(len);
    if (!utf8) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, len, NULL, NULL);
    return utf8;
}

/* Get file time as 64-bit value */
static uint64_t GetFileTimeAsUInt64(FILETIME ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

/* Get current time as SMB2-compatible FILETIME */
static void GetCurrentFileTime(FILETIME *ft) {
    GetSystemTimeAsFileTime(ft);
}

/* Initialize client context */
static void InitClientContext(ClientContext_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->Socket = INVALID_SOCKET;
    ctx->State = STATE_UNINITIALIZED;
    GenerateGUID(ctx->ServerGuid);
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        ctx->OpenFiles[i].hFile = INVALID_HANDLE_VALUE;
        ctx->OpenFiles[i].IsOpen = 0;
    }
}

/* Find free file handle slot */
static int AllocateFileSlot(ClientContext_t *ctx) {
    EnterCriticalSection(&g_FileMutex);
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (!ctx->OpenFiles[i].IsOpen) {
            ctx->OpenFiles[i].IsOpen = 1;
            ctx->NumOpenFiles++;
            LeaveCriticalSection(&g_FileMutex);
            return i;
        }
    }
    LeaveCriticalSection(&g_FileMutex);
    return -1;
}

/* Free file handle slot */
static void FreeFileSlot(ClientContext_t *ctx, int slot) {
    EnterCriticalSection(&g_FileMutex);
    if (slot >= 0 && slot < MAX_OPEN_FILES && ctx->OpenFiles[slot].IsOpen) {
        if (ctx->OpenFiles[slot].hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(ctx->OpenFiles[slot].hFile);
            ctx->OpenFiles[slot].hFile = INVALID_HANDLE_VALUE;
        }
        ctx->OpenFiles[slot].IsOpen = 0;
        memset(ctx->OpenFiles[slot].Path, 0, MAX_PATH_LEN);
        ctx->NumOpenFiles--;
    }
    LeaveCriticalSection(&g_FileMutex);
}

/* Find file handle by ID */
static int FindFileByFileID(ClientContext_t *ctx, uint64_t persistent, uint64_t volatile_id) {
    (void)volatile_id;  /* For now, ignore volatile part */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (ctx->OpenFiles[i].IsOpen && 
            ctx->OpenFiles[i].FileKey[0] == persistent) {
            return i;
        }
    }
    return -1;
}

/* Build error response packet */
static int SendErrorResponse(SOCKET sock, const Smb2Header_t *req, uint32_t status, uint8_t *outbuf) {
    Smb2Header_t *hdr = (Smb2Header_t *)outbuf;
    
    memset(hdr, 0, sizeof(Smb2Header_t));
    memcpy(hdr->ProtocolId, "\xFE\x53\x4D\x42", 4);
    hdr->StructureSize = SMB2_HEADER_SIZE;
    hdr->CreditCharge = req->CreditCharge > 0 ? req->CreditCharge : 1;
    hdr->Status = status;
    hdr->Command = req->Command;
    hdr->CreditRequestResponse = 0;
    hdr->Flags = req->Flags | 0x0001;  /* Response flag */
    hdr->NextCommand = 0;
    hdr->MessageIdUnion.MessageId = req->MessageIdUnion.MessageId;
    hdr->SessionId = req->SessionId;
    memset(hdr->Signature, 0, 16);
    
    return send(sock, (char*)outbuf, SMB2_HEADER_SIZE, 0);
}

/* Build success response header only */
static void BuildSuccessHeader(Smb2Header_t *hdr, const Smb2Header_t *req, uint16_t size) {
    memset(hdr, 0, sizeof(Smb2Header_t));
    memcpy(hdr->ProtocolId, "\xFE\x53\x4D\x42", 4);
    hdr->StructureSize = size;
    hdr->CreditCharge = req->CreditCharge > 0 ? req->CreditCharge : 1;
    hdr->Status = STATUS_SUCCESS;
    hdr->Command = req->Command;
    hdr->CreditRequestResponse = 1;
    hdr->Flags = req->Flags | 0x0001;  /* Response flag */
    hdr->NextCommand = 0;
    hdr->MessageIdUnion.MessageId = req->MessageIdUnion.MessageId;
    hdr->SessionId = req->SessionId;
}

/* Send buffer with optional logging */
static int SendWithLog(SOCKET sock, const void *buf, size_t len, int log_size) {
    if (g_Config.VerboseLogging && log_size) {
        printf("[SEND %zu bytes]\n", len);
    }
    int sent = send(sock, (char*)buf, (int)len, 0);
    if (sent < 0) {
        fprintf(stderr, "send() failed: %d\n", WSAGetLastError());
    }
    return sent;
}

/* Receive exact number of bytes */
static int RecvExact(SOCKET sock, void *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int rcvd = recv(sock, (char*)buf + total, (int)(len - total), 0);
        if (rcvd <= 0) return rcvd;
        total += rcvd;
    }
    return (int)total;
}

/* ============================================================================
 *  SMB2 Command Handlers - STUB FUNCTIONS
 * ============================================================================ */

/*
 *  HANDLER: NEGOTIATE (Command 0x0000)
 *  Purpose: Establish SMB protocol version between client and server
 */
static int HandleNegotiate(ClientContext_t *ctx, const Smb2Header_t *req_hdr, 
                           const uint8_t *payload, size_t payload_len,
                           uint8_t *outbuf) {
    (void)payload_len;
    
    if (payload_len < sizeof(Smb2NegotiateRequest_t)) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_INVALID_PARAMETER, outbuf);
    }
    
    const Smb2NegotiateRequest_t *neg_req = (const Smb2NegotiateRequest_t *)payload;
    
    /* Log negotiation details */
    if (g_Config.VerboseLogging) {
        printf("NEGOTIATE: SecurityMode=%u, Dialects=%u\n", 
               neg_req->SecurityMode,
               (unsigned int)((payload_len - sizeof(Smb2NegotiateRequest_t)) / sizeof(uint16_t)));
    }
    
    ctx->State = STATE_NEGOTIATING;
    
    /* Build NEGOTIATE Response */
    Smb2NegotiateResponse_t *neg_resp = (Smb2NegotiateResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, 
                       SMB2_HEADER_SIZE + sizeof(Smb2NegotiateResponse_t));
    
    neg_resp->StructureSize = sizeof(Smb2NegotiateResponse_t);
    neg_resp->SecurityMode = 0;  /* No signing */
    neg_resp->DialectRevision = SMB2_DIALECT_0210;  /* Select SMB 2.1 */
    neg_resp->NegotiateContextCount = 0;
    memcpy(neg_resp->ServerGuid, ctx->ServerGuid, 16);
    neg_resp->Capabilities = 0;
    neg_resp->MaxTransactSize = 16777216;    /* 16 MB max transaction */
    neg_resp->MaxReadSize = 16777216;       /* 16 MB max read */
    neg_resp->MaxWriteSize = 16777216;      /* 16 MB max write */
    GetCurrentFileTime((FILETIME*)&neg_resp->SystemTime);
    GetCurrentFileTime((FILETIME*)&neg_resp->ServerStartTime);
    neg_resp->SecurityBufferOffset = 0;
    neg_resp->SecurityBufferLength = 0;
    neg_resp->NegotiateContextOffset = 0;
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2NegotiateResponse_t), 1);
}

/*
 *  HANDLER: SESSION_SETUP (Command 0x0001)
 *  Purpose: Authenticate client and establish session
 *  NOTE: This is a STUB - no actual authentication!
 */
static int HandleSessionSetup(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                               const uint8_t *payload, size_t payload_len,
                               uint8_t *outbuf) {
    (void)payload;
    (void)payload_len;
    
    if (ctx->State != STATE_NEGOTIATING && ctx->State != STATE_SESSION_REQUIRED) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    /* STUB: Accept any credentials (INSECURE!) */
    ctx->State = STATE_SESSION_ESTABLISHED;
    ctx->SessionId = ((uint64_t)rand() << 32) | rand();
    
    Smb2SessionSetupResponse_t *resp = (Smb2SessionSetupResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2SessionSetupResponse_t));
    
    resp->StructureSize = sizeof(Smb2SessionSetupResponse_t);
    resp->SessionFlags = 0;  /* Guest or no encryption */
    resp->SecurityBufferOffset = 0;
    resp->SecurityBufferLength = 0;
    
    printf("SESSION_SETUP: Session established (ID=0x%llX)\n", 
           (unsigned long long)ctx->SessionId);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2SessionSetupResponse_t), 1);
}

/*
 *  HANDLER: LOGOFF (Command 0x0002)
 *  Purpose: Terminate session gracefully
 */
static int HandleLogoff(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                        const uint8_t *payload, size_t payload_len,
                        uint8_t *outbuf) {
    (void)payload;
    (void)payload_len;
    
    /* Close all open files first */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (ctx->OpenFiles[i].IsOpen) {
            FreeFileSlot(ctx, i);
        }
    }
    
    ctx->State = STATE_SESSION_REQUIRED;
    ctx->SessionId = 0;
    ctx->TreeId = 0;
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: TREE_CONNECT (Command 0x0003)
 *  Purpose: Connect to shared resource (disk share, pipe, print)
 */
static int HandleTreeConnect(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                              const uint8_t *payload, size_t payload_len,
                              uint8_t *outbuf) {
    (void)payload_len;
    
    if (ctx->State != STATE_SESSION_ESTABLISHED) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    const Smb2TreeConnectRequest_t *tc_req = (const Smb2TreeConnectRequest_t *)payload;
    
    /* Parse path (should be UTF-16LE encoded) */
    wchar_t path_utf16[MAX_PATH_LEN];
    if (tc_req->PathLength > sizeof(path_utf16)) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_INVALID_PARAMETER, outbuf);
    }
    memcpy(path_utf16, payload + tc_req->PathOffset, tc_req->PathLength);
    path_utf16[tc_req->PathLength / sizeof(wchar_t)] = L'\0';
    
    if (g_Config.VerboseLogging) {
        char *path_str = WideToUtf8(path_utf16);
        printf("TREE_CONNECT: Path=%s\n", path_str ? path_str : "(invalid)");
        free(path_str);
    }
    
    /* STUB: Accept all tree connects to our configured share */
    ctx->State = STATE_TREE_CONNECTED;
    ctx->TreeId = ((uint64_t)rand() << 32) | rand();
    
    Smb2TreeConnectResponse_t *resp = (Smb2TreeConnectResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2TreeConnectResponse_t));
    
    resp->StructureSize = sizeof(Smb2TreeConnectResponse_t);
    resp->ShareType = SMB2_share_type_DISK;
    resp->Reserved = 0;
    resp->ShareFlags = 0x80;  /* Continuously available */
    resp->Capability = 0;
    resp->AccessMask = 0x001FFFFF;  /* Full access (STUB) */
    
    printf("TREE_CONNECT: Tree established (ID=0x%llX)\n", 
           (unsigned long long)ctx->TreeId);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2TreeConnectResponse_t), 1);
}

/*
 *  HANDLER: TREE_DISCONNECT (Command 0x0004)
 *  Purpose: Disconnect from shared resource
 */
static int HandleTreeDisconnect(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t *outbuf) {
    (void)payload;
    (void)payload_len;
    
    /* Close all files associated with this tree */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (ctx->OpenFiles[i].IsOpen) {
            FreeFileSlot(ctx, i);
        }
    }
    
    ctx->State = STATE_SESSION_ESTABLISHED;
    ctx->TreeId = 0;
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: CREATE (Command 0x0005)
 *  Purpose: Open or create a file/directory
 */
static int HandleCreate(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t *outbuf) {
    (void)payload_len;
    
    if (ctx->State != STATE_TREE_CONNECTED) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    const Smb2CreateRequest_t *create_req = (const Smb2CreateRequest_t *)payload;
    uint16_t name_offset = create_req->NameOffset;
    uint16_t name_length = create_req->NameLength;
    
    /* Extract filename (UTF-16) */
    wchar_t filename_utf16[MAX_PATH_LEN];
    if (name_offset + name_length > payload_len || 
        name_length > sizeof(filename_utf16)) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_INVALID_PARAMETER, outbuf);
    }
    memcpy(filename_utf16, payload + name_offset, name_length);
    filename_utf16[name_length / sizeof(wchar_t)] = L'\0';
    
    char *filename = WideToUtf8(filename_utf16);
    if (!filename) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_INVALID_PARAMETER, outbuf);
    }
    
    if (g_Config.VerboseLogging) {
        printf("CREATE: Name=%s, Disp=%u, Options=0x%08X\n",
               filename, create_req->CreateDisposition, create_req->CreateOptions);
    }
    
    /* Allocate file slot */
    int slot = AllocateFileSlot(ctx);
    if (slot < 0) {
        free(filename);
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    /* Construct full path */
    snprintf(ctx->OpenFiles[slot].Path, MAX_PATH_LEN, "%s\\%S", 
             g_Config.SharePath, filename_utf16);
    strncpy(ctx->OpenFiles[slot].Path, g_Config.SharePath, MAX_PATH_LEN - 1);
    strncat(ctx->OpenFiles[slot].Path, "\\", MAX_PATH_LEN - strlen(ctx->OpenFiles[slot].Path) - 1);
    size_t pos = strlen(ctx->OpenFiles[slot].Path);
    WideCharToMultiByte(CP_UTF8, 0, filename_utf16, -1, 
                       ctx->OpenFiles[slot].Path + pos, (int)(MAX_PATH_LEN - pos), NULL, NULL);
    
    /* Determine access modes based on create disposition */
    DWORD desired_access = 0;
    DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD creation_disposition;
    DWORD file_attributes = FILE_ATTRIBUTE_NORMAL;
    
    switch (create_req->CreateDisposition) {
        case 1: /* FILE_SUPERSEDE */
            creation_disposition = CREATE_ALWAYS;
            break;
        case 2: /* FILE_OPEN */
            creation_disposition = OPEN_EXISTING;
            break;
        case 3: /* FILE_CREATE */
            creation_disposition = CREATE_NEW;
            break;
        case 4: /* FILE_OPEN_IF */
            creation_disposition = OPEN_ALWAYS;
            break;
        case 5: /* FILE_OVERWRITE */
            creation_disposition = TRUNCATE_EXISTING;
            break;
        default:
            creation_disposition = OPEN_EXISTING;
    }
    
    if (create_req->DesiredAccess & GENERIC_READ)  desired_access |= GENERIC_READ;
    if (create_req->DesiredAccess & GENERIC_WRITE) desired_access |= GENERIC_WRITE;
    if (create_req->DesiredAccess & DELETE)        desired_access |= DELETE;
    
    /* Check if opening directory */
    BOOL is_directory = (create_req->CreateOptions & 0x00000001) ? TRUE : FALSE;
    ctx->OpenFiles[slot].IsDirectory = is_directory;
    
    /* Open the file */
    wchar_t *wide_path = Utf8ToWide(ctx->OpenFiles[slot].Path);
    HANDLE hFile = CreateFileW(wide_path,
                               desired_access,
                               share_mode,
                               NULL,
                               creation_disposition,
                               file_attributes,
                               NULL);
    free(wide_path);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        FreeFileSlot(ctx, slot);
        DWORD err = GetLastError();
        uint32_t status = (err == ERROR_FILE_NOT_FOUND) ? STATUS_OBJECT_NAME_NOT_FOUND : 
                          STATUS_ACCESS_DENIED;
        free(filename);
        return SendErrorResponse(ctx->Socket, req_hdr, status, outbuf);
    }
    
    ctx->OpenFiles[slot].hFile = hFile;
    
    /* Generate unique file key */
    srand((unsigned)time(NULL));
    ctx->OpenFiles[slot].FileKey[0] = ((uint64_t)rand() << 32) | rand();  /* Persistent */
    ctx->OpenFiles[slot].FileKey[1] = ((uint64_t)rand() << 32) | rand();  /* Volatile */
    
    free(filename);
    
    /* Build CREATE Response */
    Smb2CreateResponse_t *resp = (Smb2CreateResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2CreateResponse_t));
    
    resp->StructureSize = sizeof(Smb2CreateResponse_t);
    resp->OplockLevel = 0;
    resp->Flags = 0;
    resp->CreateAction = creation_disposition == CREATE_NEW ? 1 : 0;
    GetCurrentFileTime((FILETIME*)&resp->CreationTime);
    GetCurrentFileTime((FILETIME*)&resp->LastAccessTime);
    GetCurrentFileTime((FILETIME*)&resp->LastWriteTime);
    GetCurrentFileTime((FILETIME*)&resp->ChangeTime);
    resp->AllocationSize = 0;
    resp->EndOfFile = 0;
    resp->FileAttributes = file_attributes;
    resp->NameOffset = 0;
    resp->NameLength = 0;
    resp->CreateContextsOffset = 0;
    resp->CreateContextsLength = 0;
    memcpy(resp->FileKey, ctx->OpenFiles[slot].FileKey, 16);
    
    printf("CREATE: Slot=%d Key=[%016llX/%016llX]\n", 
           slot, (unsigned long long)ctx->OpenFiles[slot].FileKey[0],
           (unsigned long long)ctx->OpenFiles[slot].FileKey[1]);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2CreateResponse_t), 1);
}

/*
 *  HANDLER: CLOSE (Command 0x0006)
 *  Purpose: Close an open file handle
 */
static int HandleClose(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                        const uint8_t *payload, size_t payload_len,
                        uint8_t *outbuf) {
    (void)payload_len;
    
    const Smb2CloseRequest_t *close_req = (const Smb2CloseRequest_t *)payload;
    
    int slot = FindFileByFileID(ctx, close_req->PersistentFileID, close_req->VolatileFileID);
    if (slot < 0) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    char path[MAX_PATH_LEN];
    strncpy(path, ctx->OpenFiles[slot].Path, MAX_PATH_LEN - 1);
    
    FreeFileSlot(ctx, slot);
    
    if (g_Config.VerboseLogging) {
        printf("CLOSE: Path=%s\n", path);
    }
    
    Smb2CloseResponse_t *resp = (Smb2CloseResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2CloseResponse_t));
    
    resp->StructureSize = sizeof(Smb2CloseResponse_t);
    resp->Reserved = 0;
    resp->Flags = 0;
    resp->CreationTime = 0;
    resp->LastAccessTime = 0;
    resp->LastWriteTime = 0;
    resp->ChangeTime = 0;
    resp->AllocationSize = 0;
    resp->EndOfFile = 0;
    resp->DeletePending = 0;
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2CloseResponse_t), 1);
}

/*
 *  HANDLER: FLUSH (Command 0x0007)
 *  Purpose: Flush cached data to disk
 *  NOTE: This is a STUB - always succeeds
 */
static int HandleFlush(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                        const uint8_t *payload, size_t payload_len,
                        uint8_t *outbuf) {
    (void)payload;
    (void)payload_len;
    
    const Smb2FlushRequest_t *flush_req = (const Smb2FlushRequest_t *)payload;
    int slot = FindFileByFileID(ctx, flush_req->PersistentFileID, flush_req->VolatileFileID);
    
    if (slot < 0) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    /* Flush file cache */
    FlushFileBuffers(ctx->OpenFiles[slot].hFile);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: READ (Command 0x0008)
 *  Purpose: Read data from an open file
 */
static int HandleRead(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *outbuf) {
    (void)payload_len;
    
    const Smb2ReadRequest_t *read_req = (const Smb2ReadRequest_t *)payload;
    
    int slot = FindFileByFileID(ctx, read_req->FileID[0], read_req->FileID[1]);
    if (slot < 0) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    uint32_t length = read_req->Length;
    uint64_t offset = read_req->Offset;
    
    if (length > 65536) length = 65536;  /* Limit to 64KB per read */
    
    /* Allocate buffer for reading */
    uint8_t *data_buf = (uint8_t*)malloc(length);
    if (!data_buf) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    /* Seek and read */
    LARGE_INTEGER li;
    li.QuadPart = offset;
    SetFilePointerEx(ctx->OpenFiles[slot].hFile, li, NULL, FILE_BEGIN);
    
    DWORD bytes_read = 0;
    if (!ReadFile(ctx->OpenFiles[slot].hFile, data_buf, length, &bytes_read, NULL)) {
        free(data_buf);
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    /* Build READ Response */
    Smb2ReadResponse_t *resp = (Smb2ReadResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2ReadResponse_t) + bytes_read);
    
    resp->StructureSize = sizeof(Smb2ReadResponse_t);
    resp->DataOffset = sizeof(Smb2ReadResponse_t);
    resp->Reserved = 0;
    resp->DataLength = bytes_read;
    resp->DataRemaining = 0;
    resp->Flags = 0;
    
    /* Copy data after header */
    memcpy(outbuf + SMB2_HEADER_SIZE + sizeof(Smb2ReadResponse_t), data_buf, bytes_read);
    
    free(data_buf);
    
    if (g_Config.VerboseLogging) {
        printf("READ: Offset=%llu Len=%u Read=%u\n", 
               (unsigned long long)offset, length, (unsigned int)bytes_read);
    }
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2ReadResponse_t) + bytes_read, 1);
}

/*
 *  HANDLER: WRITE (Command 0x0009)
 *  Purpose: Write data to an open file
 */
static int HandleWrite(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                        const uint8_t *payload, size_t payload_len,
                        uint8_t *outbuf) {
    (void)payload_len;
    
    const Smb2WriteRequest_t *write_req = (const Smb2WriteRequest_t *)payload;
    
    int slot = FindFileByFileID(ctx, write_req->FileID[0], write_req->FileID[1]);
    if (slot < 0) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    /* Check read-only mode */
    if (g_Config.ShareReadOnly) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    uint32_t length = write_req->Length;
    uint64_t offset = write_req->Offset;
    uint16_t data_offset = write_req->DataOffset;
    
    /* Calculate actual data location */
    const uint8_t *data = payload + data_offset;
    
    /* Seek and write */
    LARGE_INTEGER li;
    li.QuadPart = offset;
    SetFilePointerEx(ctx->OpenFiles[slot].hFile, li, NULL, FILE_BEGIN);
    
    DWORD bytes_written = 0;
    if (!WriteFile(ctx->OpenFiles[slot].hFile, data, length, &bytes_written, NULL)) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    /* Build WRITE Response */
    Smb2WriteResponse_t *resp = (Smb2WriteResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2WriteResponse_t));
    
    resp->StructureSize = sizeof(Smb2WriteResponse_t);
    resp->Reserved = 0;
    resp->Count = bytes_written;
    resp->Remaining = 0;
    resp->WriteChannelInfoOffset = 0;
    resp->WriteChannelInfoLength = 0;
    resp->Flags = 0;
    
    if (g_Config.VerboseLogging) {
        printf("WRITE: Offset=%llu Len=%u Written=%u\n",
               (unsigned long long)offset, length, (unsigned int)bytes_written);
    }
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2WriteResponse_t), 1);
}

/*
 *  HANDLER: LOCK (Command 0x000A)
 *  Purpose: Lock/unlock byte ranges in a file
 *  NOTE: STUB - returns success without actually locking
 */
static int HandleLock(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *outbuf) {
    (void)payload;
    (void)payload_len;
    
    const Smb2LockRequest_t *lock_req = (const Smb2LockRequest_t *)payload;
    int slot = FindFileByFileID(ctx, lock_req->FileID[0], lock_req->FileID[1]);
    
    if (slot < 0) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    /* STUB: Always succeed */
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: IOCTL (Command 0x000B)
 *  Purpose: Device-specific control operations
 *  NOTE: STUB - limited support
 */
static int HandleIoctl(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                        const uint8_t *payload, size_t payload_len,
                        uint8_t *outbuf) {
    (void)payload_len;
    
    const Smb2IoctlRequest_t *ioctl_req = (const Smb2IoctlRequest_t *)payload;
    uint32_t ctl_code = ioctl_req->CtlCode;
    
    if (ctx->State != STATE_TREE_CONNECTED) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_ACCESS_DENIED, outbuf);
    }
    
    /* Support DISK_GET_VERIFY_STATUS (used by some clients) */
    if (ctl_code == 0x00090020) {
        /* Return minimal response */
        BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
        return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
    }
    
    /* Everything else not implemented */
    return SendErrorResponse(ctx->Socket, req_hdr, STATUS_NOT_SUPPORTED, outbuf);
}

/*
 *  HANDLER: QUERY_DIRECTORY (Command 0x000E)
 *  Purpose: Enumerate files in a directory
 */
static int HandleQueryDirectory(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t *outbuf) {
    (void)payload_len;
    
    const Smb2QueryDirectoryRequest_t *qdir_req = (const Smb2QueryDirectoryRequest_t *)payload;
    
    int slot = FindFileByFileID(ctx, qdir_req->FileID[0], qdir_req->FileID[1]);
    if (slot < 0) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
    }
    
    if (!ctx->OpenFiles[slot].IsDirectory) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_INVALID_PARAMETER, outbuf);
    }
    
    /* Use Windows FindFirst/FindNext for directory enumeration */
    WIN32_FIND_DATAW find_data;
    HANDLE hFind = FindFirstFileW(L".\\*", &find_data);
    
    if (hFind == INVALID_HANDLE_VALUE) {
        return SendErrorResponse(ctx->Socket, req_hdr, STATUS_OBJECT_NAME_NOT_FOUND, outbuf);
    }
    
    /* Build response with directory entries */
    uint8_t *info_buf = (uint8_t*)(outbuf + SMB2_HEADER_SIZE + sizeof(Smb2QueryDirectoryResponse_t));
    size_t info_offset = 0;
    size_t max_info = payload_len;  /* Use request buffer size as limit */
    
    do {
        FileInfoFileBothDir_t *entry = (FileInfoFileBothDir_t*)(info_buf + info_offset);
        
        /* Convert filename from UTF-16 to appropriate encoding */
        int name_bytes = WideCharToMultiByte(CP_UTF8, 0, find_data.cFileName, -1, 
                                            (char*)entry->FileName, 
                                            MAX_PATH_LEN, NULL, NULL);
        if (name_bytes <= 0) continue;
        
        entry->FileNameLength = name_bytes - 1;  /* Don't count null terminator */
        entry->NextEntryOffset = sizeof(FileInfoFileBothDir_t) + name_bytes;
        entry->FileIndex = 0;
        entry->CreationTime = GetFileTimeAsUInt64(find_data.ftCreationTime);
        entry->LastAccessTime = GetFileTimeAsUInt64(find_data.ftLastAccessTime);
        entry->LastWriteTime = GetFileTimeAsUInt64(find_data.ftLastWriteTime);
        entry->ChangeTime = GetFileTimeAsUInt64(find_data.ftLastWriteTime);
        entry->EndOfFile = find_data.nFileSizeHigh == 0 ? find_data.nFileSizeLow : 
                          (((uint64_t)find_data.nFileSizeHigh) << 32) | find_data.nFileSizeLow;
        entry->AllocationSize = entry->EndOfFile;
        entry->FileAttributes = find_data.dwFileAttributes;
        entry->EaSize = 0;
        entry->ShortNameLength = 0;
        
        info_offset += entry->NextEntryOffset;
        
        if (info_offset + 256 > max_info) break;  /* Prevent overflow */
    } while (FindNextFileW(hFind, &find_data) && info_offset < max_info - 256);
    
    FindClose(hFind);
    
    /* Build QUERY_DIRECTORY Response */
    Smb2QueryDirectoryResponse_t *resp = (Smb2QueryDirectoryResponse_t *)(outbuf + SMB2_HEADER_SIZE);
    
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                       SMB2_HEADER_SIZE + sizeof(Smb2QueryDirectoryResponse_t) + info_offset);
    
    resp->StructureSize = sizeof(Smb2QueryDirectoryResponse_t);
    resp->OutputBufferOffset = sizeof(Smb2QueryDirectoryResponse_t);
    resp->OutputBufferLength = (uint32_t)info_offset;
    
    if (g_Config.VerboseLogging) {
        printf("QUERY_DIRECTORY: Entries enumerated\n");
    }
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + sizeof(Smb2QueryDirectoryResponse_t) + info_offset, 1);
}

/*
 *  HANDLER: QUERY_INFO (Command 0x0010)
 *  Purpose: Query file/sytem information
 */
static int HandleQueryInfo(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *outbuf) {
    (void)payload_len;
    
    const Smb2QueryInfoRequest_t *qinfo_req = (const Smb2QueryInfoRequest_t *)payload;
    uint8_t info_type = qinfo_req->InfoType;
    
    /* Basic file info query */
    if (info_type == 1) {  /* SMB2_0_INFO_FILE */
        int slot = FindFileByFileID(ctx, qinfo_req->FileID[0], qinfo_req->FileID[1]);
        if (slot < 0) {
            return SendErrorResponse(ctx->Socket, req_hdr, STATUS_FILE_CLOSED, outbuf);
        }
        
        BY_HANDLE_FILE_INFORMATION fi;
        GetFileInformationByHandle(ctx->OpenFiles[slot].hFile, &fi);
        
        /* Return minimal file info (FILE_STANDARD_INFO) */
        uint64_t *resp_data = (uint64_t*)(outbuf + SMB2_HEADER_SIZE + 4);
        resp_data[0] = 0;  /* AllocationSize */
        resp_data[1] = 0;  /* EndOfFile */
        resp_data[2] = 0;  /* NumberOfLinks */
        resp_data[3] = ctx->OpenFiles[slot].IsDirectory ? 1 : 0;  /* DeletePending */
        resp_data[4] = ctx->OpenFiles[slot].IsDirectory ? 1 : 0;  /* Directory */
        
        BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr,
                           SMB2_HEADER_SIZE + 4 + 40);
        *(uint32_t*)(outbuf + SMB2_HEADER_SIZE) = 40;  /* OutputBufferOffset placeholder */
        *(uint32_t*)(outbuf + SMB2_HEADER_SIZE + 2) = 40;  /* OutputBufferLength */
        
        return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE + 44, 1);
    }
    
    /* Volume info or other info types */
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: SET_INFO (Command 0x0011)
 *  Purpose: Update file/sytem information
 *  NOTE: STUB - always succeeds without making changes
 */
static int HandleSetInfo(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *outbuf) {
    (void)ctx;
    (void)payload;
    (void)payload_len;
    
    /* STUB: Always succeed */
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: ECHO (Command 0x000D)
 *  Purpose: Keep-alive heartbeat request
 */
static int HandleEcho(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *outbuf) {
    (void)payload;
    (void)payload_len;
    
    /* Echo back with same structure */
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  HANDLER: CANCEL (Command 0x000C)
 *  Purpose: Cancel pending operation
 *  NOTE: STUB - acknowledges cancel without tracking pending ops
 */
static int HandleCancel(ClientContext_t *ctx, const Smb2Header_t *req_hdr,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t *outbuf) {
    (void)ctx;
    (void)payload;
    (void)payload_len;
    
    /* Acknowledge cancel */
    BuildSuccessHeader((Smb2Header_t*)outbuf, req_hdr, SMB2_HEADER_SIZE);
    return SendWithLog(ctx->Socket, outbuf, SMB2_HEADER_SIZE, 0);
}

/*
 *  MAIN DISPATCHER - Routes SMB2 commands to appropriate handlers
 */
static int ProcessSmb2Packet(ClientContext_t *ctx, const uint8_t *buf, size_t buf_len) {
    if (buf_len < SMB2_HEADER_SIZE) {
        fprintf(stderr, "Packet too short: %zu bytes (need %d)\n", buf_len, SMB2_HEADER_SIZE);
        return -1;
    }
    
    const Smb2Header_t *hdr = (const Smb2Header_t *)buf;
    
    /* Validate SMB signature */
    if (memcmp(hdr->ProtocolId, "\xFE\x53\x4D\x42", 4) != 0) {
        fprintf(stderr, "Invalid SMB signature: %02X%02X%02X%02X\n",
                hdr->ProtocolId[0], hdr->ProtocolId[1], 
                hdr->ProtocolId[2], hdr->ProtocolId[3]);
        return -1;
    }
    
    uint16_t command = hdr->Command;
    const uint8_t *payload = buf + SMB2_HEADER_SIZE;
    size_t payload_len = buf_len - SMB2_HEADER_SIZE;
    
    if (g_Config.VerboseLogging) {
        printf("COMMAND: 0x%04X, MsgID: 0x%llX, Session: 0x%llX\n",
               command, (unsigned long long)hdr->MessageIdUnion.MessageId,
               (unsigned long long)hdr->SessionId);
    }
    
    /* Allocate response buffer */
    uint8_t *outbuf = (uint8_t*)malloc(BUFFER_SIZE);
    if (!outbuf) {
        return -1;
    }
    
    int result;
    
    /* Dispatch to appropriate handler */
    switch (command) {
        case SMB2_NEGOTIATE:
            result = HandleNegotiate(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_SESSION_SETUP:
            result = HandleSessionSetup(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_LOGOFF:
            result = HandleLogoff(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_TREE_CONNECT:
            result = HandleTreeConnect(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_TREE_DISCONNECT:
            result = HandleTreeDisconnect(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_CREATE:
            result = HandleCreate(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_CLOSE:
            result = HandleClose(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_FLUSH:
            result = HandleFlush(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_READ:
            result = HandleRead(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_WRITE:
            result = HandleWrite(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_LOCK:
            result = HandleLock(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_IOCTL:
            result = HandleIoctl(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_QUERY_DIRECTORY:
            result = HandleQueryDirectory(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_QUERY_INFO:
            result = HandleQueryInfo(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_SET_INFO:
            result = HandleSetInfo(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_ECHO:
            result = HandleEcho(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        case SMB2_CANCEL:
            result = HandleCancel(ctx, hdr, payload, payload_len, outbuf);
            break;
            
        default:
            fprintf(stderr, "Unsupported command: 0x%04X\n", command);
            result = SendErrorResponse(ctx->Socket, hdr, STATUS_NOT_SUPPORTED, outbuf);
            break;
    }
    
    free(outbuf);
    return result;
}

/* ============================================================================
 *  Client Connection Handler
 * ============================================================================ */

static void HandleClientConnection(SOCKET client_sock, const struct sockaddr_in *addr) { /* <-- ADDED struct KEYWORD */
    printf("Connection from %s:%u\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    
    /* Create client context */
    ClientContext_t ctx;
    InitClientContext(&ctx);
    ctx.Socket = client_sock;
    ctx.Address = *addr;
    ctx.State = STATE_UNINITIALIZED;
    
    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
    
    /* Main receive loop for this connection */
    uint8_t *receive_buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!receive_buffer) {
        closesocket(client_sock);
        return;
    }
    
    while (g_Running) {
        /* Read SMB2 header first */
        int rcvd = RecvExact(client_sock, receive_buffer, SMB2_HEADER_SIZE);
        if (rcvd <= 0) {
            if (rcvd == 0 || WSAGetLastError() == WSAETIMEDOUT) {
                printf("Client disconnected (timeout or clean)\n");
            } else {
                fprintf(stderr, "recv() error: %d\n", WSAGetLastError());
            }
            break;
        }
        
        /* Validate minimum length */
        Smb2Header_t *hdr = (Smb2Header_t *)receive_buffer;
        uint16_t header_size = hdr->StructureSize;
        if (header_size < SMB2_HEADER_SIZE) {
            fprintf(stderr, "Invalid header size: %u\n", header_size);
            break;
        }
        
        /* Calculate total payload size */
        size_t total_size = header_size;
        if (header_size > BUFFER_SIZE) {
            fprintf(stderr, "Header size exceeds buffer: %u\n", header_size);
            break;
        }
        
        /* Read remaining header/payload */
        if (total_size > SMB2_HEADER_SIZE) {
            rcvd = RecvExact(client_sock, receive_buffer + SMB2_HEADER_SIZE, 
                            header_size - SMB2_HEADER_SIZE);
            if (rcvd <= 0) {
                fprintf(stderr, "Failed to read remaining header\n");
                break;
            }
        }
        
        /* Process the packet */
        int result = ProcessSmb2Packet(&ctx, receive_buffer, header_size);
        if (result < 0) {
            fprintf(stderr, "Packet processing failed\n");
            break;
        }
    }
    
    /* Cleanup */
    free(receive_buffer);
    closesocket(client_sock);
    
    /* <-- FIXED FORMATTING CORRUPTION BELOW --> */
    /* Free any remaining open files */
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (ctx.OpenFiles[i].IsOpen && ctx.OpenFiles[i].hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(ctx.OpenFiles[i].hFile);
            ctx.OpenFiles[i].hFile = INVALID_HANDLE_VALUE;
            ctx.OpenFiles[i].IsOpen = 0;
        }
    }
    printf("Connection closed.\n");
}

/* ============================================================================
 *  Command Line Parsing
 * ============================================================================ */
static void PrintUsage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\nOptions:\n");
    printf("  -p, --port PORT       Set listening port (default: %d)\n", DEFAULT_PORT);
    printf("  -s, --share PATH      Set shared directory path (default: %s)\n", DEFAULT_SHARE_PATH);
    printf("  -r, --readonly        Enable read-only mode\n");
    printf("  -v, --verbose         Enable verbose logging\n");
    printf("  -h, --help            Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -p 4455 -s /tmp/share -v\n", progname);
    printf("  %s --readonly --verbose\n", progname);
}

static int ParseArguments(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --port requires an argument\n");
                return -1;
            }
            g_Config.Port = (uint16_t)atoi(argv[++i]);
            if (g_Config.Port < 1 || g_Config.Port > 65535) {
                fprintf(stderr, "Error: Invalid port number (1-65535)\n");
                return -1;
            }
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--share") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --share requires an argument\n");
                return -1;
            }
            strncpy(g_Config.SharePath, argv[++i], MAX_PATH_LEN - 1);
            g_Config.SharePath[MAX_PATH_LEN - 1] = '\0';
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--readonly") == 0) {
            g_Config.ShareReadOnly = 1;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_Config.VerboseLogging = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            PrintUsage(argv[0]);
            return -1;
        }
    }
    return 0;
}

/* ============================================================================
 *  Signal Handling (Windows compatible)
 * ============================================================================ */
static void SignalHandler(int sig) {
    (void)sig;
    printf("\nShutdown requested...\n");
    g_Running = 0;
}

/* ============================================================================
 *  Server Initialization
 * ============================================================================ */
static int InitializeServer(void) {
    /* Initialize WinSock */
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return -1;
    }

    /* Verify WinSock version */
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        fprintf(stderr, "WinSock version mismatch\n");
        WSACleanup();
        return -1;
    }

    /* Initialize critical sections */
    InitializeCriticalSection(&g_FileMutex);

    /* Setup signal handlers */
    signal(SIGINT, SignalHandler);
#ifdef SIGTERM
    signal(SIGTERM, SignalHandler);
#endif

    /* Verify share directory exists */
    DWORD attrs = GetFileAttributesW(Utf8ToWide(g_Config.SharePath));
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "Warning: Share path '%s' does not exist, creating...\n", g_Config.SharePath);
        if (!CreateDirectoryA(g_Config.SharePath, NULL)) {
            fprintf(stderr, "Error: Cannot create share directory '%s'\n", g_Config.SharePath);
            WSACleanup();
            return -1;
        }
    } else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        fprintf(stderr, "Error: Share path '%s' is not a directory\n", g_Config.SharePath);
        WSACleanup();
        return -1;
    }

    printf("Share directory: %s\n", g_Config.SharePath);
    printf("Port: %u\n", g_Config.Port);
    printf("Mode: %s\n", g_Config.ShareReadOnly ? "READ ONLY" : "READ-WRITE");
    printf("Verbose: %s\n", g_Config.VerboseLogging ? "enabled" : "disabled");
    printf("\n");
    return 0;
}

/* ============================================================================
 *  Main Server Loop
 * ============================================================================ */
static SOCKET CreateListenSocket(uint16_t port) {
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed: %d\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    /* Allow socket reuse */
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    /* Bind to address */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    /* Listen for connections */
    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "listen() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return INVALID_SOCKET;
    }

    return listen_sock;
}

/* ============================================================================
 *  Entry Point
 * ============================================================================ */
int main(int argc, char *argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ SMB2 Server - Public Domain Edition v0.1                     ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ LICENSE: PUBLIC DOMAIN (NO WARRANTY - NOT FIT FOR USE)       ║\n");
    printf("║ WARNING: EDUCATIONAL PURPOSES ONLY                           ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    /* Parse arguments */
    if (ParseArguments(argc, argv) != 0) {
        return 1;
    }

    /* Initialize server */
    if (InitializeServer() != 0) {
        return 1;
    }

    /* Create listening socket */
    SOCKET listen_sock = CreateListenSocket(g_Config.Port);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "Failed to create listening socket\n");
        WSACleanup();
        return 1;
    }

    printf("Server started - waiting for connections...\n");
    printf("Press Ctrl+C to stop\n\n");

    /* Main accept loop */
    while (g_Running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        /* Accept incoming connection */
        SOCKET client_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &addr_len);
        if (client_sock == INVALID_SOCKET) {
            if (g_Running && WSAGetLastError() != WSAEINTR) {
                fprintf(stderr, "accept() failed: %d\n", WSAGetLastError());
            }
            continue;
        }

        /* Handle client in current thread (could be multithreaded) */
        HandleClientConnection(client_sock, &client_addr);
    }

    /* Cleanup */
    closesocket(listen_sock);
    DeleteCriticalSection(&g_FileMutex);
    WSACleanup();
    printf("Server shutdown complete.\n");
    return 0;
}

/* ============================================================================
 *  End of File
 * ============================================================================
 *
 *  NOTES FOR USERS:
 *
 *  1. This implementation intentionally lacks authentication to demonstrate
 *     the SMB2 protocol structure. DO NOT DEPLOY IN PRODUCTION.
 *
 *  2. Port 445 typically requires administrator/root privileges on most systems.
 *     Consider using a higher port number (e.g., 4455) for testing.
 *
 *  3. Windows firewall may block incoming connections on port 445 by default.
 *
 *  4. For testing connectivity from another machine:
 *     - net use Z: \\<server-ip>\ipc$
 *     - Or use smbclient (Linux): smbclient //<server-ip>/share -N
 *
 *  5. This code uses blocking sockets. For production use, consider:
 *     - Multithreading (one thread per client)
 *     - IOCP (I/O Completion Ports) on Windows
 *     - select()/poll()/epoll() for event-driven design
 *
 *  6. Memory allocation failures are handled minimally. Production code should
 *     implement proper error recovery and resource management.
 *
 *  7. File handle leaks are prevented only in normal flow. Exception handling
 *     paths may leave handles open.
 *
 *  THANK YOU FOR USING PUBLIC DOMAIN SOFTWARE.
 *  FEEL FREE TO MODIFY, REDISTRIBUTE, OR CLAIM AS YOUR OWN.
 *  NO ATTRIBUTION REQUIRED, NO LIABILITY ACCEPTED.
 *
 * ========================================================================= */