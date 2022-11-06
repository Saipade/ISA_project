#ifndef __USE_POSIX
#define __USE_POSIX 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <iso646.h>
#include <libgen.h>


#include "dns_receiver_events.h"
#include "../include/macros.h"
#include "../include/misc.h"
#include "../include/dns.h"
#include "../include/logger.h"
#include "../include/base64.h"


/**
 * @brief 
 * 
 * @param argc number of arguments
 * @param argv arguments
 * @param base_host reference to host's base
 * @param dst_dirpath reference to destination directory
 */
void parse_args(int argc, char** argv, char** base_host, char** dst_dirpath) {
                    
    if (argc != 3) {
        fprintf(
            stderr,
            "Wrong format of arguments!\n"
            "Valid format:\n"
            "\tdns_receiver {BASE_HOST} {DST_DIRPATH}\n"
        );
        exit(EXIT_FAILURE);
    }
    *base_host = strdup(argv[1]);
    *dst_dirpath = strdup(argv[2]);

}


/**
 * @brief Validates destination file path
 * 
 * @param dst_filepath destination file path
 * @param full is set when we need to check the validity of entire path (combined paths from client and server)
 */
void validate__dst_dirpath(char* path, bool full) {
    
    DIR* directory_ptr;
    int path_length = strlen(path);
    char filepath_buffer[path_length];

    if (full) {
        int i = 0;
        char c = 0;
        memset(filepath_buffer, 0, path_length);
        /* find last slash */
        for (i=path_length-1; c!='/' and i>0; i--) { c = path[i]; }
        strncpy(filepath_buffer, path, i+1);
    }
    char* full_path = full ? filepath_buffer : path;
    /* path already exists */
    if (opendir(full_path) != NULL) { return; }
    /* path does not exist */
    char current_path[strlen(path)];
    memset(current_path, 0, strlen(path));
    char* p = strtok(full_path, "/");
    strcat(current_path, p);
    while (p != NULL) {
        if ((opendir(current_path) == NULL)) {
            FLOG("Directory \"%s\" does not exist\nCreating...\n", current_path);
            mkdir(current_path, 0b111111101);
        }
        strcat(current_path, "/");
        p = strtok(NULL, "/");
        if (p != NULL) { strcat(current_path, p); }
    }

}


bool save_data(char* query, char* base_host, char* dst_dirpath) {

    char* data = (char*)(query+sizeof(struct dns_header));

    char base_host_label[MAX_LABEL_LENGTH], base_host_c;
    memset(base_host_label, 0, MAX_LABEL_LENGTH);
    int base_host_cnt;
    for (base_host_cnt=0; base_host_cnt<strlen(base_host) and base_host_c != '.'; base_host_cnt++) {
        base_host_c = base_host[base_host_cnt];
    }
    strncpy(base_host_label, base_host, base_host_cnt-1);

    char filename[MAX_LABEL_LENGTH], actual_data[MAX_QUERY_LENGTH];
    memset(filename, 0, MAX_LABEL_LENGTH);
    memset(actual_data, 0, MAX_QUERY_LENGTH);
    int filename_length, label_length = 1, actual_data_offset = 0;

    /* read destination file name */
    filename_length = (int)data[0];
    strncpy(filename, data+1, filename_length);
    /* read actual data + host's base */
    bool read_base_host = false;
    int base_label_cnt = 0;
    for (int i=filename_length+1; label_length!=0; i+=label_length+1) {
        char label[label_length];
        memset(label, 0, label_length);
        label_length = (int)data[i];
        strncpy(label, data+i+1, label_length);
        /* if reading labels of host's base */
        if (read_base_host and strlen(base_host) > base_host_cnt) {
            memset(base_host_label, 0, MAX_LABEL_LENGTH);
            int start_pos = base_host_cnt;
            /* find next '.' */
            base_host_c = 1;
            /* read next host's base label */
            for (base_host_cnt; base_host_cnt<=strlen(base_host) and base_host_c != '.'; base_host_cnt++) { 
                base_host_c = base_host[base_host_cnt]; 
            }
            strncpy(base_host_label, base_host+start_pos, base_host_cnt-start_pos-1);
            /* compare */
            if (strcmp(base_host_label, label)) {
                FLOG("Label \"%s\" does not correspond to the \"%s\" in host's base \"%s\"\nSkipping this chunk\n", label, base_host_label, base_host);
                return false;
            }
            base_label_cnt++;
        /* reading actual data */
        } else {
            /* if current label is first label in host's base */
            if (not strcmp(base_host_label, label)) { 
                read_base_host = true;
                continue;
            }
            /* copy to data buffer */
            strncpy(actual_data + actual_data_offset, label, label_length);
            actual_data_offset += label_length;
        }
    }
    /* host's base wasn't found */
    if (not read_base_host) {
        LOG("Host's bases are not the same\nSkipping this chunk\n");
        return false;
    }
    
    /* decode */
    int decoded_filename_length = Base64decode_len(filename);
    int decoded_actual_data_length = Base64decode_len(actual_data);
    char decoded_filename[decoded_filename_length];
    char decoded_actual_data[decoded_actual_data_length];
    Base64decode(decoded_filename, filename);
    Base64decode(decoded_actual_data, actual_data);
    
    /* concatenate full path and validate it */
    int full_path_length = sizeof(dst_dirpath)+1+decoded_filename_length;
    char full_path[full_path_length];
    memset(full_path, 0, full_path_length);
    strcat(full_path, dst_dirpath);
    strcat(full_path, "/");
    strcat(full_path, decoded_filename);
    validate__dst_dirpath(full_path, true);

    /* write to file */
    FILE* file_ptr;
    file_ptr = fopen(full_path, "a");
    fprintf(file_ptr, "%s", decoded_actual_data);
    fclose(file_ptr);

    return true;

}


int main(int argc, char** argv) {

    char *base_host, *dst_dirpath;
    parse_args(argc, argv, &base_host, &dst_dirpath);

    validate__base_host(base_host);

    int socket_fd; 
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) { ERROR("Socket creation failed!\n"); }

    struct sockaddr_in server_address, client_address;
    memset((char *)&server_address, 0, sizeof(server_address));
    memset((char *)&client_address, 0, sizeof(client_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;     
    server_address.sin_port = htons(12345);
    const int True = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &True, sizeof(int)) == -1) { ERROR("Set socket option error\n"); }
    if (bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) { FERROR("Error code: %d\nSocket binding failed\n", errno); }

    char query_buffer[MAX_QUERY_LENGTH];
    socklen_t client_address_len = sizeof(client_address);
    int nread;

    while (true) {
        /* read data */
        memset(query_buffer, 0, MAX_QUERY_LENGTH);
        nread = recvfrom(socket_fd, query_buffer, MAX_QUERY_LENGTH, 0, (struct sockaddr*)&client_address, &client_address_len);
        
        /* initialise dns response */
        int response_buffer_length = nread+sizeof(struct dns_response);
        char response_buffer[response_buffer_length];
        memset(response_buffer, 0, response_buffer_length);
        memcpy(&response_buffer, query_buffer, nread);

        /* write data to destination file */
        if (not save_data(query_buffer, base_host, dst_dirpath)) { continue; }

        /* edit header */
        struct dns_header* dns_header_ptr = (struct dns_header*)response_buffer;
        dns_header_ptr->qr = htons(1);  // it's a response
        dns_header_ptr->ra = htons(1);
        dns_header_ptr->ancount = htons(1);  // single answer to a single question

        /* make response */
        struct dns_response* dns_response_ptr = (struct dns_response*)(response_buffer + nread);
        dns_response_ptr->response_type = htons(DNS_RESPONSE__PTR);
        dns_response_ptr->offset = htons(DNS_RESPONSE__QNAME_PTR);  // points to qname of query
        dns_response_ptr->record_type = htons(DNS_A);  // A record
        dns_response_ptr->record_class = htons(1);  // internet
        dns_response_ptr->ttl = htonl(1200);  // doesn't really matter
        dns_response_ptr->rdata_length = htons(4);  // is 4 for A record
        inet_pton(AF_INET, "131.224.220.22", &dns_response_ptr->rdata);

        if (sendto(socket_fd, response_buffer, response_buffer_length, 
                   0, (struct sockaddr*)&client_address, sizeof(struct sockaddr_in)) == -1) {
            FERROR("Error sending response #%d\n", dns_header_ptr->id);
        }

    }

    free(base_host); free(dst_dirpath);
    
}