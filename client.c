#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(void) {
    char filename[256];

    printf("Enter the file name to read: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        return 1;
    }
    filename[strcspn(filename, "\n")] = '\0';

    if (filename[0] == '\0') {
        printf("File name cannot be empty.\n");
        return 1;
    }

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket error");
        return 1;
    }

    struct sockaddr_in server_address = {0};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(5000);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(client_socket, (struct sockaddr *)&server_address,
                sizeof(server_address)) < 0) {
        perror("Connection error");
        close(client_socket);
        return 1;
    }

    const char start_packet[] = "(SS,RFMP,v1.0,0)";
    if (send(client_socket, start_packet, strlen(start_packet), 0) < 0) {
        perror("Send error");
        close(client_socket);
        return 1;
    }
    printf("Sent: %s\n", start_packet);

    char response[4096];
    int received = recv(client_socket, response, sizeof(response) - 1, 0);
    if (received <= 0) {
        printf("Server did not confirm the connection.\n");
        close(client_socket);
        return 1;
    }

    response[received] = '\0';
    printf("Received: %s\n", response);

    if (strcmp(response, "(CC)") != 0) {
        printf("Unexpected setup response.\n");
        close(client_socket);
        return 1;
    }

    char command_packet[300];
    int length = snprintf(command_packet, sizeof(command_packet),
                          "(CM,openRead,%s)", filename);

    if (length < 0 || length >= (int)sizeof(command_packet)) {
        printf("File name is too long.\n");
        close(client_socket);
        return 1;
    }

    if (send(client_socket, command_packet, (size_t)length, 0) < 0) {
        perror("Send error");
        close(client_socket);
        return 1;
    }
    printf("Sent: %s\n", command_packet);

    received = recv(client_socket, response, sizeof(response) - 1, 0);
    if (received > 0) {
        response[received] = '\0';
        printf("Server response: %s\n", response);
    } else {
        printf("Server did not send a file response.\n");
    }

    close(client_socket);
    return received > 0 ? 0 : 1;
}
