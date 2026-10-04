#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Send the entire packet, even if send() sends only part of it. */
int send_packet(int client_socket, char packet[]){
    size_t length = strlen(packet);
    size_t total = 0;

    while(total < length){
        ssize_t sent = send(client_socket, packet + total,
                            length - total, MSG_NOSIGNAL);

        if(sent < 0){
            if(errno == EINTR){
                continue;
            }

            perror("Send error");
            return -1;
        }
        else if(sent == 0){
            printf("Could not finish sending the packet.\n");
            return -1;
        }

        total = total + (size_t)sent;
    }

    return 0;
}

/* Validate the file name before creating a network connection. */
int read_filename(char filename[], size_t capacity){
    printf("Enter the file name to read: ");

    if(fgets(filename, capacity, stdin) == NULL){
        printf("Could not read the file name.\n");
        return -1;
    }

    if(strchr(filename, '\n') == NULL && !feof(stdin)){
        printf("File name is too long.\n");
        return -1;
    }

    filename[strcspn(filename, "\n")] = '\0';

    if(filename[0] == '\0'){
        printf("File name cannot be empty.\n");
        return -1;
    }

    for(int i = 0; filename[i] != '\0'; i++){
        if(filename[i] == ',' ||
           filename[i] == '(' ||
           filename[i] == ')' ||
           filename[i] == '\r'){
            printf("File name contains a character that conflicts with the packet format.\n");
            return -1;
        }
    }

    return 0;
}

/* Create the TCP socket and connect it to the Python server. */
int connect_to_server(const char server_ip[], unsigned short port){
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);

    if(client_socket < 0){
        perror("Socket error");
        return -1;
    }

    struct sockaddr_in server_address = {0};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    /* Convert the IP address text into an IPv4 address. */
    int address_result = inet_pton(AF_INET, server_ip,
                                   &server_address.sin_addr);

    if(address_result != 1){
        if(address_result == 0){
            printf("Invalid server IP address.\n");
        }
        else{
            perror("Address conversion error");
        }

        close(client_socket);
        return -1;
    }

    if(connect(client_socket,
               (struct sockaddr *)&server_address,
               sizeof(server_address)) < 0){
        perror("Connection error");
        close(client_socket);
        return -1;
    }

    return client_socket;
}

int main(void){
    char filename[256];
    char response[4096];
    char command_packet[300];

    /* Check the input before connecting to the server. */
    if(read_filename(filename, sizeof(filename)) < 0){
        return 1;
    }

    /* Use the same address and port as the Python programs. */
    int client_socket = connect_to_server("127.0.0.1", 5000);

    if(client_socket < 0){
        return 1;
    }

    /* Setup phase: request nonsecured communication. */
    char start_packet[] = "(SS,RFMP,v1.0,0)";

    if(send_packet(client_socket, start_packet) < 0){
        close(client_socket);
        return 1;
    }

    printf("Sent: %s\n", start_packet);

    ssize_t received = recv(client_socket, response,
                            sizeof(response) - 1, 0);

    if(received < 0){
        perror("Setup receive error");
        close(client_socket);
        return 1;
    }
    else if(received == 0){
        printf("Server closed the connection during setup.\n");
        close(client_socket);
        return 1;
    }

    response[received] = '\0';
    printf("Received: %s\n", response);

    if(strcmp(response, "(CC)") != 0){
        printf("Unexpected setup response.\n");
        close(client_socket);
        return 1;
    }

    /* Operation phase: create the openRead request. */
    int length = snprintf(command_packet,
                          sizeof(command_packet),
                          "(CM,openRead,%s)", filename);

    if(length < 0 || length >= (int)sizeof(command_packet)){
        printf("Could not create the file request.\n");
        close(client_socket);
        return 1;
    }

    if(send_packet(client_socket, command_packet) < 0){
        close(client_socket);
        return 1;
    }

    printf("Sent: %s\n", command_packet);

    /* Receive the file response. */
    received = recv(client_socket, response,
                    sizeof(response) - 1, 0);

    if(received < 0){
        perror("Receive error");
        close(client_socket);
        return 1;
    }
    else if(received == 0){
        printf("Server closed the connection without a file response.\n");
        close(client_socket);
        return 1;
    }

    response[received] = '\0';
    int server_error = 0;

    /* Display a server exception. */
    if(strncmp(response, "(EE,", 4) == 0){
        printf("Server reported an error: %s\n", response);
        server_error = 1;
    }

    /* Display file contents from a successful response. */
    else if(strncmp(response, "(SC,", 4) == 0 &&
            received >= 5 &&
            response[received - 1] == ')'){
        response[received - 1] = '\0';
        printf("File contents:\n%s\n", response + 4);
    }

    else{
        printf("Unexpected file response: %s\n", response);
        server_error = 1;
    }

    /* Closing phase: notify the server that we finished. */
    char end_packet[] = "(End)";

    if(send_packet(client_socket, end_packet) < 0){
        close(client_socket);
        return 1;
    }

    printf("Sent: %s\n", end_packet);

    close(client_socket);
    return server_error;
}
