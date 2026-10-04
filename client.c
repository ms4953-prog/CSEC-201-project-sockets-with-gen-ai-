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

/* Receive one TCP chunk and retry interrupted recv() calls. */
ssize_t receive_response(int client_socket,
                         char response[],
                         size_t capacity){
    if(capacity < 2){
        printf("Response buffer is too small.\n");
        return -1;
    }

    ssize_t received;

    do{
        received = recv(client_socket, response, capacity - 1, 0);
    }while(received < 0 && errno == EINTR);

    if(received < 0){
        perror("Receive error");
        return -1;
    }

    if(received == 0){
        printf("Server closed the connection without a response.\n");
        return 0;
    }

    response[received] = '\0';
    return received;
}

/* Display file contents or the exception's code and description.
 * Return 0 for success and 1 for an error or invalid response. */
int display_file_response(char response[], size_t length){
    if(length < 5 ||
       response[0] != '(' ||
       response[length - 1] != ')'){
        printf("Unexpected file response: %s\n", response);
        return 1;
    }

    /* An exception has the format (EE,Error Code,Description). */
    if(strncmp(response, "(EE,", 4) == 0){
        char *separator = strchr(response + 4, ',');

        if(separator == NULL ||
           separator == response + 4 ||
           separator + 1 >= response + length - 1){
            printf("Invalid exception packet: %s\n", response);
            return 1;
        }

        /* Check that the error code contains only digits. */
        for(char *digit = response + 4; digit < separator; digit++){
            if(*digit < '0' || *digit > '9'){
                printf("Invalid exception error code: %s\n", response);
                return 1;
            }
        }

        printf("Server reported an error: %s\n", response);

        /* Separate the fields after displaying the full packet. */
        response[length - 1] = '\0';
        *separator = '\0';

        printf("Error code: %s\n", response + 4);
        printf("Description: %s\n", separator + 1);

        return 1;
    }

    /* A successful read has the format (SC,file contents). */
    if(strncmp(response, "(SC,", 4) == 0){
        response[length - 1] = '\0';
        printf("File contents:\n%s\n", response + 4);
        return 0;
    }

    printf("Unexpected file response: %s\n", response);
    return 1;
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

    ssize_t received = receive_response(client_socket, response,
                                         sizeof(response));

    if(received <= 0){
        close(client_socket);
        return 1;
    }

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

    received = receive_response(client_socket, response,
                                sizeof(response));

    if(received <= 0){
        close(client_socket);
        return 1;
    }

    /* Check the reply and display its contents or error details. */
    int server_error = display_file_response(response, (size_t)received);

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
