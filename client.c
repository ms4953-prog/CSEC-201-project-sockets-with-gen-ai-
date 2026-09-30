#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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

int main(){
    char filename[256];
    char response[4096];
    char command_packet[300];

    printf("Enter the file name to read: ");

    if(fgets(filename, sizeof(filename), stdin) == NULL){
        printf("Could not read the file name.\n");
        return 1;
    }

    if(strchr(filename, '\n') == NULL && !feof(stdin)){
        printf("File name is too long.\n");
        return 1;
    }

    filename[strcspn(filename, "\n")] = '\0';

    if(filename[0] == '\0'){
        printf("File name cannot be empty.\n");
        return 1;
    }

    for(int i = 0; filename[i] != '\0'; i++){
        if(filename[i] == ',' ||
           filename[i] == '(' ||
           filename[i] == ')' ||
           filename[i] == '\r'){
            printf("File name contains a character that conflicts with the packet format.\n");
            return 1;
        }
    }

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);

    if(client_socket < 0){
        perror("Socket error");
        return 1;
    }

    struct sockaddr_in server_address = {0};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(5000);
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(client_socket,
               (struct sockaddr *)&server_address,
               sizeof(server_address)) < 0){
        perror("Connection error");
        close(client_socket);
        return 1;
    }

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
    else{
        response[received] = '\0';

        if(strncmp(response, "(EE,", 4) == 0){
            printf("Server reported an error: %s\n", response);
            close(client_socket);
            return 1;
        }
        else{
            printf("Server response: %s\n", response);
        }
    }

    close(client_socket);
    return 0;
}
