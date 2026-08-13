/*
 * THIS CODE IS RELEASED INTO THE PUBLIC DOMAIN.
 * 
 * DISCLAIMER:
 * This software is provided "as is", without warranty of any kind, express or implied.
 * It is NOT fit for any purpose, especially not for production use or secure environments.
 * The author assumes no responsibility for any damage, data loss, or security 
 * breaches caused by the use of this code. Use at your own risk.
 * 
 * COMPILE INSTRUCTIONS:
 * This code requires the GCC compiler (MinGW) on Windows.
 * Run the following command in your terminal to compile:
 * 
 * gcc ftp_server.c -o ftp_server.exe -lws2_32
 */

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 21
#define BUFFER_SIZE 1024

// Global for the passive data socket
SOCKET data_socket = INVALID_SOCKET;

void setup_passive_socket() {
    struct sockaddr_in data_addr;
    data_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = INADDR_ANY;
    data_addr.sin_port = 0; // Let OS pick a random port

    bind(data_socket, (struct sockaddr*)&data_addr, sizeof(data_addr));
    listen(data_socket, 1);
}

void send_pasv_response(SOCKET control_socket) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    getsockname(data_socket, (struct sockaddr*)&addr, &len);

    unsigned short port = ntohs(addr.sin_port);
    unsigned char *ip = (unsigned char *)&addr.sin_addr;

    char response[128];
    // Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    sprintf(response, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
            ip[0], ip[1], ip[2], ip[3], port >> 8, port & 0xFF);
    send(control_socket, response, (int)strlen(response), 0);
}

void send_binary_file(SOCKET control_socket, char *filename) {
    // Accept the connection on the data socket
    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    SOCKET client_data_conn = accept(data_socket, (struct sockaddr*)&client_addr, &addr_len);

    if (client_data_conn == INVALID_SOCKET) {
        send(control_socket, "425 Can't open data connection\r\n", 31, 0);
        return;
    }

    FILE *fp = fopen(filename, "rb"); // 'rb' for binary read
    if (!fp) {
        send(control_socket, "550 File not found\r\n", 21, 0);
        closesocket(client_data_conn);
        return;
    }

    send(control_socket, "150 Opening BINARY mode data connection\r\n", 41, 0);

    char file_buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, BUFFER_SIZE, fp)) > 0) {
        send(client_data_conn, file_buffer, (int)bytes_read, 0);
    }

    fclose(fp);
    closesocket(client_data_conn);
    send(control_socket, "226 Transfer complete\r\n", 23, 0);
}

void handle_client(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    send(client_socket, "220 Welcome to Win32 Binary FTP\r\n", 32, 0);

    while ((bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        printf("Client: %s", buffer);

        if (strncmp(buffer, "USER", 4) == 0) {
            send(client_socket, "331 Password required\r\n", 23, 0);
        } else if (strncmp(buffer, "PASS", 4) == 0) {
            send(client_socket, "230 Logged in\r\n", 15, 0);
        } else if (strncmp(buffer, "PASV", 4) == 0) {
            setup_passive_socket();
            send_pasv_response(client_socket);
        } else if (strncmp(buffer, "RETR", 4) == 0) {
            char filename[256];
            sscanf(buffer + 5, "%s", filename);
            send_binary_file(client_socket, filename);
        } else if (strncmp(buffer, "QUIT", 4) == 0) {
            send(client_socket, "221 Goodbye\r\n", 14, 0);
            break;
        } else {
            send(client_socket, "502 Not implemented\r\n", 22, 0);
        }
    }
    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return 1;
    }

    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = { AF_INET, htons(PORT), INADDR_ANY };

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed. Try running as Administrator.\n");
        return 1;
    }

    listen(server_socket, 3);
    printf("Binary FTP Server listening on port %d...\n", PORT);

    while (1) {
        SOCKET client_socket = accept(server_socket, NULL, NULL);
        if (client_socket != INVALID_SOCKET) {
            handle_client(client_socket);
        }
    }

    closesocket(server_socket);
    WSACleanup();
    return 0;
}
