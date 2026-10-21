//DNS SERVER
//2026 HUGO
//RELEASED TO THE PUBLIC DOMAIN
//gcc dnsd.c -o dnsd.exe -O2 -lws2_32 -mwindows
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define DNS_PORT 53
#define BUF_SIZE 2048

#pragma pack(push, 1)
typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short qcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short adcount;
} DNS_HEADER;

typedef struct {
    unsigned short name_ptr;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned int ip;
} DNS_ANSWER;
#pragma pack(pop)

typedef struct HostEntry {
    char domain[256];
    unsigned int ip; 
    struct HostEntry* next;
} HostEntry;

HostEntry* hostList = NULL;

int logEnabled = 0;
char logPath[MAX_PATH];
char hostsPath[MAX_PATH]; 

int enableForwarding = 0;
char upstreamDNS[64];
int autoCacheForwarded = 0;

void LogMessage(const char* msg) {
    if (!logEnabled) return;
    FILE* f = fopen(logPath, "a");
    if (f) {
        time_t now = time(NULL);
        char* t = ctime(&now);
        t[strlen(t)-1] = '\0'; 
        fprintf(f, "[%s] %s\n", t, msg);
        fclose(f);
    }
}

// Memory-safe reading to avoid unaligned access crashes
unsigned short ReadUShort(unsigned char* ptr) {
    unsigned short v; memcpy(&v, ptr, 2); return ntohs(v);
}
unsigned int ReadUInt(unsigned char* ptr) {
    unsigned int v; memcpy(&v, ptr, 4); return ntohl(v);
}

void LoadHosts(const char* hostFile) {
    FILE* f = fopen(hostFile, "r");
    if (!f) return;

    char line[512], ip_str[64], domain_str[256];

    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        
        if (sscanf(line, "%63s %255s", ip_str, domain_str) == 2) {
            HostEntry* entry = (HostEntry*)malloc(sizeof(HostEntry));
            strncpy(entry->domain, domain_str, sizeof(entry->domain));
            entry->ip = inet_addr(ip_str);
            entry->next = hostList;
            hostList = entry;
        }
    }
    fclose(f);
    LogMessage("Hosts file loaded into memory.");
}

unsigned int ResolveDomain(const char* domain) {
    HostEntry* curr = hostList;
    while (curr) {
        if (_stricmp(curr->domain, domain) == 0) return curr->ip;
        curr = curr->next;
    }
    return INADDR_NONE;
}

void AddHost(const char* domain, unsigned int ip) {
    if (ResolveDomain(domain) != INADDR_NONE) return; // Prevent duplicates

    // Add to memory list
    HostEntry* entry = (HostEntry*)malloc(sizeof(HostEntry));
    strncpy(entry->domain, domain, sizeof(entry->domain));
    entry->ip = ip;
    entry->next = hostList;
    hostList = entry;

    // Append to file
    FILE* f = fopen(hostsPath, "a");
    if (f) {
        struct in_addr addr;
        addr.s_addr = ip;
        fprintf(f, "%-15s %s\n", inet_ntoa(addr), domain);
        fclose(f);
    }

    char logBuf[512];
    struct in_addr addr; addr.s_addr = ip;
    snprintf(logBuf, sizeof(logBuf), "Auto-cached to hosts: %s -> %s", domain, inet_ntoa(addr));
    LogMessage(logBuf);
}

void ConvertToDotFormat(unsigned char* dns, char* dot) {
    int p = 0, j = 0;
    while (dns[p] != 0) {
        int len = dns[p++];
        for (int i = 0; i < len; i++) dot[j++] = dns[p++];
        dot[j++] = '.';
    }
    if (j > 0) dot[j-1] = '\0'; else dot[0] = '\0';
}

int ForwardQuery(const char* query_buf, int query_len, char* response_buf) {
    SOCKET fwd_s = socket(AF_INET, SOCK_DGRAM, 0);
    if (fwd_s == INVALID_SOCKET) return -1;

    DWORD timeout = 2000;
    setsockopt(fwd_s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(upstreamDNS);

    if (sendto(fwd_s, query_buf, query_len, 0, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
        closesocket(fwd_s);
        return -1;
    }

    struct sockaddr_in from;
    int fromlen = sizeof(from);
    int recv_len = recvfrom(fwd_s, response_buf, BUF_SIZE, 0, (struct sockaddr*)&from, &fromlen);
    closesocket(fwd_s);
    return recv_len;
}

// Parses the raw UDP packet from the upstream DNS to extract the first IPv4 Address
unsigned int ExtractFirstA_Record(unsigned char* buf, int len) {
    if (len < sizeof(DNS_HEADER)) return INADDR_NONE;
    
    DNS_HEADER* dns = (DNS_HEADER*)buf;
    int qcount = ntohs(dns->qcount);
    int ancount = ntohs(dns->ancount);
    unsigned char* reader = buf + sizeof(DNS_HEADER);

    // Skip question section
    for (int i = 0; i < qcount; i++) {
        while (*reader != 0 && reader < buf + len) {
            if (*reader >= 192) { reader += 2; break; } // Pointer
            else reader += (*reader) + 1;
        }
        if (*reader == 0) reader++;
        reader += 4; // Skip QTYPE + QCLASS
    }

    // Parse answer section
    for (int i = 0; i < ancount; i++) {
        if (reader >= buf + len) break;
        
        // Skip name
        if (*reader >= 192) reader += 2; // Pointer
        else {
            while (*reader != 0 && reader < buf + len) reader += (*reader) + 1;
            reader++;
        }

        if (reader + 10 > buf + len) break;

        unsigned short type = ReadUShort(reader); reader += 2;
        unsigned short _class = ReadUShort(reader); reader += 2;
        reader += 4; // Skip TTL
        unsigned short rdlength = ReadUShort(reader); reader += 2;

        if (type == 1 && _class == 1 && rdlength == 4 && reader + 4 <= buf + len) { // Type A, Class IN
            unsigned int ip;
            memcpy(&ip, reader, 4); // Keep in network byte order
            return ip;
        }
        reader += rdlength;
    }
    return INADDR_NONE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server, client;
    char buffer[BUF_SIZE];
    int client_len = sizeof(client);

    char iniPath[MAX_PATH];
    GetModuleFileNameA(NULL, iniPath, MAX_PATH);
    char* lastSlash = strrchr(iniPath, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    strcat(iniPath, "settings.ini");

    GetPrivateProfileStringA("Settings", "HostsFile", "hosts.txt", hostsPath, MAX_PATH, iniPath);
    GetPrivateProfileStringA("Settings", "LogFile", "dns.log", logPath, MAX_PATH, iniPath);
    
    logEnabled = GetPrivateProfileIntA("Settings", "EnableLogging", 0, iniPath);
    enableForwarding = GetPrivateProfileIntA("Settings", "EnableForwarding", 0, iniPath);
    autoCacheForwarded = GetPrivateProfileIntA("Settings", "AutoCacheForwarded", 0, iniPath);
    GetPrivateProfileStringA("Settings", "UpstreamDNS", "8.8.8.8", upstreamDNS, sizeof(upstreamDNS), iniPath);

    LogMessage("DNS Daemon Started.");
    LoadHosts(hostsPath);

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) return 1;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(DNS_PORT);

    if (bind(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        LogMessage("Bind failed. Port 53 in use?");
        return 1;
    }

    LogMessage("Listening on UDP port 53...");

    while (1) {
        int recv_len = recvfrom(s, buffer, BUF_SIZE, 0, (struct sockaddr*)&client, &client_len);
        if (recv_len == SOCKET_ERROR) continue;

        DNS_HEADER* dns = (DNS_HEADER*)buffer;
        
        if ((ntohs(dns->flags) & 0x8000) == 0 && ntohs(dns->qcount) == 1) {
            unsigned char* qname = (unsigned char*)&buffer[sizeof(DNS_HEADER)];
            char domain[256];
            ConvertToDotFormat(qname, domain);

            unsigned int ip = ResolveDomain(domain);

            if (ip == INADDR_NONE) {
                if (enableForwarding) {
                    char fwd_buf[BUF_SIZE];
                    int fwd_len = ForwardQuery(buffer, recv_len, fwd_buf);

                    if (fwd_len > 0) {
                        sendto(s, fwd_buf, fwd_len, 0, (struct sockaddr*)&client, client_len);
                        
                        if (autoCacheForwarded) {
                            unsigned int resolvedIp = ExtractFirstA_Record((unsigned char*)fwd_buf, fwd_len);
                            if (resolvedIp != INADDR_NONE) {
                                AddHost(domain, resolvedIp);
                            }
                        }
                        continue;
                    }
                }
                dns->flags = htons(0x8183); // NXDOMAIN
                sendto(s, buffer, recv_len, 0, (struct sockaddr*)&client, client_len);
            } else {
                dns->flags = htons(0x8180); 
                dns->ancount = htons(1); 
                
                int qname_len = strlen((const char*)qname) + 1;
                int query_total_len = sizeof(DNS_HEADER) + qname_len + 4;
                
                DNS_ANSWER* answer = (DNS_ANSWER*)&buffer[query_total_len];
                answer->name_ptr = htons(0xC00C);
                answer->type = htons(1);          
                answer->_class = htons(1);        
                answer->ttl = htonl(300);         
                answer->data_len = htons(4);      
                answer->ip = ip;                  

                int resp_len = query_total_len + sizeof(DNS_ANSWER);
                sendto(s, buffer, resp_len, 0, (struct sockaddr*)&client, client_len);
            }
        }
    }

    closesocket(s);
    WSACleanup();
    return 0;
}