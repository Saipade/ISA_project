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
#include <sys/time.h>

#include "dns_receiver_events.h"
#include "../include/macros.h"
#include "../include/misc.h"
#include "../include/dns.h"
#include "../include/logger.h"
#include "../include/base32.h"


/* Globals */
struct sockaddr_in server_address, client_address;
struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
int nread, socket_fd, True = 1;
char query_buffer[MAX_QUERY_LENGTH];
char filepath[MAX_PATH_LENGTH];
FILE* file_ptr;
bool receiving_dirpath = true, transfer_started = false;
bool write_init = false;  /* if we should print the [INIT] message */


/**
 * @brief Parses arguments
 * 
 * @param argc number of arguments
 * @param argv arguments
 * @param base_host reference to host's base
 * @param dst_dirpath reference to destination directory
 */
void parse_args(int argc, char** argv, char** base_host, char** dst_dirpath) {
                    
    if (argc != 3) {
        ERROR(
            "Invalid format of arguments!\n"
            "Valid format:\n"
            "\tdns_receiver {BASE_HOST} {DST_DIRPATH}\n"
        );
    }
    *base_host = strdup(argv[1]);
    *dst_dirpath = strdup(argv[2]);

}


/**
 * @brief Returns the size of file provided by `filepath`
 * 
 * @return size of file
 */
uint16_t get_filesize() {

    file_ptr = fopen(filepath, "a");
    fseek(file_ptr, 0L, SEEK_END);
    uint16_t file_size = ftell(file_ptr);
    fclose(file_ptr);
    return file_size;

}


/**
 * @brief Validates destination file path, creates directories if path does not exist
 * 
 * @param dst_filepath destination file path
 * @param full is set when we need to check the validity of entire path (combined paths from client and server)
 */
void validate__dst_dirpath(char* path) {
    
    int path_length = strlen(path);
    char filepath_buffer[path_length];

    memset(filepath_buffer, 0, path_length);
    /* find last slash */
    int i = 0;
    char c = 0;
    for (i=path_length-1; c!='/' and i>0; i--) { c = path[i]; }
    strncpy(filepath_buffer, path, i+1);

    DIR* ptr;
    /* path already exists */
    if ((ptr = opendir(filepath_buffer)) != NULL) { 
        closedir(ptr); 
        return;
    }
    closedir(ptr); 

    /* path does not exist */
    char current_path[strlen(path)];
    memset(current_path, 0, strlen(path));
    char* p = strtok(filepath_buffer, "/");
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

/**
 * @brief Parses query and saves it either to filepath variable or to file
 * 
 * @param query query to be parsed
 * @param base_labels host's labels
 * @param base_label_count count of host's base labels
 * @param dst_dirpath destination directory
 * @param reading_dirpath set if parsing query with filename
 * @return 1 if procedure was successful; 0 if it wasn't; 2 if it's the last packet in a sequence
 */
int save_data(char* query, char** base_labels, int base_label_count, char* dst_dirpath, bool* reading_dirpath) {
    
    /* payload after dns header */
    char* data = (char*)(query+sizeof(struct dns_header));

    /* initiate dns header structure for logging chunk id in case of error */
    struct dns_header* dns_header_ptr = (struct dns_header*)query;
    int id = ntohs(dns_header_ptr->id);
    /* id is less than offset -> not file name */
    if (id < ID_OFFSET and *reading_dirpath) {
        *reading_dirpath = false;
        validate__dst_dirpath(filepath);
        /* create file or clear it */
        file_ptr = fopen(filepath, "w");
        fclose(file_ptr);
    }

    /* id is 65535 -> end */
    if (id == DNS_MAX_ID) { return 2; }

    int base_host_cnt = 0;

    /* init filename and data to be written */
    char actual_data[MAX_QUERY_LENGTH];
    memset(actual_data, 0, MAX_QUERY_LENGTH);
    int label_length = 1, actual_data_offset = 0;

    /* parse qname */
    bool read_base_host = false;
    int base_label_cnt = 0;
    for (int i=0; ; i+=label_length+1) {

        if ((label_length = (int)data[i]) == 0) { break; }

        char label[label_length+1];
        memset(label, 0, label_length+1);
        strncpy(label, data+i+1, label_length);
        /* if reading labels of host's base */
        if (read_base_host) {
            if (base_host_cnt > base_label_count) {
                FLOG("Number of host labels differs\nSkipping chunk #%d...\n", dns_header_ptr->id);
                return 0;
            }
            if (strcmp(base_labels[base_host_cnt], label)) {
                FLOG("Label \"%s\" does not correspond to the \"%s\" in host's base\nSkipping chunk #%d\n", label, base_labels[base_host_cnt], dns_header_ptr->id);
                return 0;
            }
            base_host_cnt++;
        /* reading actual data */
        } else {
            /* if current label is first label in host's base */
            if (!strcmp(base_labels[base_host_cnt], label)) {
                read_base_host = true;
                base_host_cnt++;
                continue;
            }
            /* copy to data buffer */
            strncpy(actual_data + actual_data_offset, label, label_length);
            actual_data_offset += label_length;
        }

    }

    /* host's base wasn't found -> skip this query */
    if (not read_base_host) {
        FLOG("Host's bases are not the same\nSkipping the chunk #%d...\n", dns_header_ptr->id);
        return 0;
    }
    if (write_init) {
        dns_receiver__on_transfer_init(&client_address.sin_addr);
    }

    /* decode */
    char decoded_actual_data_buffer[512];
    base32_decode(actual_data, decoded_actual_data_buffer, 512);
    char decoded_actual_data[strlen(decoded_actual_data_buffer)+1];
    memset(decoded_actual_data, 0, strlen(decoded_actual_data_buffer)+1);
    strcpy(decoded_actual_data, decoded_actual_data_buffer);

    dns_receiver__on_query_parsed(dst_dirpath, decoded_actual_data);
    dns_receiver__on_chunk_received(&client_address.sin_addr, dst_dirpath, dns_header_ptr->id, nread-sizeof(struct dns_header)-2*sizeof(uint16_t));

    /* append to filepath */
    if (*reading_dirpath) {
        strcat(filepath+strlen(filepath), decoded_actual_data);
        return 1; 
    }

    /* write to file if it's not last packet */
    if (id != DNS_MAX_ID) {
        file_ptr = fopen(filepath, "a");
        fprintf(file_ptr, "%s", decoded_actual_data);
        fclose(file_ptr);
    }
    return 1;

}


int main(int argc, char** argv) {

    /* parse args */
    char *base_host, *dst_dirpath;
    parse_args(argc, argv, &base_host, &dst_dirpath);

    /* validate args */
    validate__base_host(base_host);
    /* append '/' to destination file path */
    if (dst_dirpath[strlen(dst_dirpath)-1] != '/') {
        dst_dirpath = realloc(dst_dirpath, sizeof(dst_dirpath)+1);
        dst_dirpath[strlen(dst_dirpath)] = '/';
    }
    strncpy(filepath, dst_dirpath, strlen(dst_dirpath));

    /* set socket and server address */
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) { ERROR("Socket creation failed!\n"); }
    memset((char *)&server_address, 0, sizeof(server_address));
    memset((char *)&client_address, 0, sizeof(client_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);     
    server_address.sin_port = htons(DNS_PORT);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &True, sizeof(int)) == -1 or 
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) { ERROR("Socket options settting failed\n"); }
    if (bind(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) { FERROR("Error code: %d\nSocket binding failed\n", errno); }

    /* parse base host */
    size_t length = strlen(base_host);
    char host[length];
    strcpy(host, base_host);
    int base_label_cnt = 0;
    for (int i=0; host[i]; i++) { if (host[i] == '.') { base_label_cnt++; } }
    char* base_labels[base_label_cnt+1];
    base_label_cnt = 0;
    char* p = strtok(host, ".");
    while (p != NULL) {
        base_labels[base_label_cnt++] = p;
        p = strtok(NULL, ".");
    }

    socklen_t client_address_length = sizeof(client_address);
    uint32_t ip_fsize = 0;
    while (true) {

        /* read data */
        memset(query_buffer, 0, MAX_QUERY_LENGTH);
        if ((nread = recvfrom(socket_fd, query_buffer, MAX_QUERY_LENGTH, 0, (struct sockaddr*)&client_address, &client_address_length)) == -1) {
            /* no queries for 2 seconds -> leave file as it is */
            if (transfer_started) {
                FLOG("No packets were recieved in the last 2 seconds for %s\n", filepath);
                ip_fsize = get_filesize();
                dns_receiver__on_transfer_completed(filepath, ip_fsize);
                memset(filepath, 0, MAX_PATH_LENGTH);
                strcpy(filepath, dst_dirpath);
                receiving_dirpath = true;
                transfer_started = false;
                write_init = false;
                continue;
            }
            continue;
        }

        if (not transfer_started) { write_init = true; }
        
        transfer_started = true;
        /* initialise dns response */
        int response_buffer_length = nread+sizeof(struct dns_response);
        char response_buffer[response_buffer_length];
        memset(response_buffer, 0, response_buffer_length);
        memcpy(&response_buffer, query_buffer, nread);

        /* parse data and save */
        int res = save_data(query_buffer, base_labels, base_label_cnt, dst_dirpath, &receiving_dirpath);
        if (not res) { continue; }  // error occured
        
        /* edit header */
        struct dns_header* dns_header_ptr = (struct dns_header*)response_buffer;
        dns_header_ptr->flags = htons(0x8180);  // now it's response
        dns_header_ptr->ancount = htons(1);  // single answer to a single question

        /* make response */
        struct dns_response* dns_response_ptr = (struct dns_response*)(response_buffer + nread);
        dns_response_ptr->response_type = DNS_RESPONSE__PTR;  // type=pointer
        dns_response_ptr->offset = DNS_RESPONSE__QNAME_PTR;  // points to the qname of query
        dns_response_ptr->record_type = htons(1);  // A record
        dns_response_ptr->record_class = htons(1);  // internet
        dns_response_ptr->ttl = htonl(1200);  // time to live doesn't really matter
        dns_response_ptr->rdata_length = htons(4);  // A record

        /* last packet, successful transfer */
        if (res == 2) {  // encode file size into rdata
            ip_fsize = get_filesize();
            dns_response_ptr->rdata = htonl(ip_fsize);
        /* rdata doesn't matter if it's not the last packet */
        } else {
            inet_pton(AF_INET, "131.224.220.22", &dns_response_ptr->rdata);
        }
        
        /* send response */
        if (sendto(socket_fd, response_buffer, response_buffer_length, 
                   0, (struct sockaddr*)&client_address, sizeof(struct sockaddr_in)) == -1) {
            FLOG("Error on sending response #%d\n", dns_header_ptr->id);
        }

        /* reset */
        if (res == 2) {
            dns_receiver__on_transfer_completed(filepath, ip_fsize);
            memset(filepath, 0, MAX_PATH_LENGTH);
            strcpy(filepath, dst_dirpath);
            receiving_dirpath = true;
            transfer_started = false;
            write_init = false;
        }

        write_init = false;

    }

    free(base_host); free(dst_dirpath);  // free args
    
}
