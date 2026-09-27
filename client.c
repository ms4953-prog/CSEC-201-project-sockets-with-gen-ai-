#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main() {
    char filename[256];

    printf("Enter the file name to read: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = '\0';

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket error");
        return 1;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(5000);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(client_socket, (struct sockaddr *)&server_address,
                sizeof(server_address)) < 0) {
        perror("Connection error");
        close(client_socket);
        return 1;
    }

    char start_packet[] = "(SS,RFMP,v1.0,0)";
    send(client_socket, start_packet, strlen(start_packet), 0);
    printf("Sent: %s\n", start_packet);

    char response[1024];
    int received = recv(client_socket, response, sizeof(response) - 1, 0);
    if (received <= 0) {
        printf("Server did not reply.\n");
        close(client_socket);
        return 1;
    }

    response[received] = '\0';
    printf("Received: %s\n", response);

    close(client_socket);
    return 0;
}
