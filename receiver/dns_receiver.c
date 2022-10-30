#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/socket.h>


#include "dns_receiver_events.h"
#include "../include/macros.h"
#include "../include/misc.c"
#include "../include/dns.h"


void parse_args(int argc, char** argv, 
                char** base_host, 
                char** dst_dirpath) {
                    
    if (argc != 3) {
        fprintf(
            stderr,
            "Wrong format of arguments!\n"
            "Valid format:\n"
            "\tdns_receiver {BASE_HOST} {DST_DIRPATH}\n"
        );
        exit(EXIT_FAILURE);
    }

    init_string(base_host, argv[1]);
    init_string(dst_dirpath, argv[2]);

    return;

}


void set_query(char *buffer, struct dns_query *query) {
    
}


int main(int argc, char** argv) {

    char *base_port, *dst_dirpath;
    parse_args(argc, argv, &base_port, &dst_dirpath);
    
    int socket_fd;
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        exit_w_error("Socket creation failed!");
    }

    struct sockaddr_in server_address, client_address;
    memset((char *)&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(DNS_PORT);
    if (bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        exit_w_error("Socket binding failed");
    }

    char buffer[MAX_BUFFER_SIZE];
    socklen_t client_address_len;
    int nread;

    while (true) {
        client_address_len = sizeof(client_address);
        if ((nread = recvfrom(socket_fd, buffer, MAX_BUFFER_SIZE, MSG_WAITALL, (struct sockaddr*)&client_address, &client_address_len)) == -1) {
            continue;
        }
        char client_address_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_address.sin_addr), client_address_str, INET_ADDRSTRLEN);
        // print("Received %d bytes from %s\n", nread, client_address_str);
        struct dns_header *header = (struct dns_header *)buffer;

        struct dns_query *query;
        set_query(buffer, &query);
        
    }

    free(base_port);
    free(dst_dirpath);
    
}