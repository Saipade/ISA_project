#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <regex.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <iso646.h>
#include <sys/time.h>

#include "dns_sender_events.h"
#include "../include/macros.h"
#include "../include/misc.h"
#include "../include/dns.h"
#include "../include/logger.h"
#include "../include/base32.h"


/* Globals */
int data_length, response_length, socket_fd;
struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
char packed_data_buffer[MAX_QUERY_LENGTH];
bool sending_filename = true;


/**
 * @brief Validates upstream ip
 * 
 * @param upstream_dns_ip 
 */
void validate__upstream_dns_ip(char** upstream_dns_ip) {

    /* if no dns ip provided -> get default one */
    if (*upstream_dns_ip == NULL) {
        LOG("Upstream dns ip is not provided, using default one\n");
        char buffer[1024];
        bool get_dns = false;
        FILE* file_ptr;
        if ((file_ptr = fopen("/etc/resolv.conf", "r")) == NULL) { 
            fclose(file_ptr);
            ERROR("Failed opening /etc/resolv.conf\n"); 
        }
        while (fscanf(file_ptr, " %1023s", buffer) == 1) {
            if (get_dns) { 
                *upstream_dns_ip = strdup(buffer); 
                break;
            }
            if (not strcmp(buffer, "nameserver")) get_dns = true;
        }
        fclose(file_ptr);
    }
    else {
        regex_t regex;
        int comp_res = regcomp(&regex, IP_REGEX, REG_EXTENDED);
        int not_valid = regexec(&regex, *upstream_dns_ip, 0, NULL, 0);
        regfree(&regex);
        if (not_valid) { ERROR("Upstream dns address should be valid IPv4 address\n"); }
    }

}


/**
 * @brief Validates source file path
 * 
 * @param src_filepath 
 */
void validate__src_filepath(char* src_filepath) {
    /* check if source file exists */
    if (src_filepath != NULL and access(src_filepath, F_OK) != 0) { ERROR("Source file does not exist!\n"); }
    /* check if both --src_filepath and stdin are NULL */
    if (src_filepath == NULL and stdin == NULL) { ERROR("No source file has been passed either by --src_filepath parameter or by stdin\n"); }
}
/**
 * @brief Validates destination file path
*/
void validate__dst_filepath(char* dst_filepath) {
    if (strlen(dst_filepath) > MAX_PATH_LENGTH) { ERROR("Destination filepath's length exceeds unix path length limit\n"); }
}


/**
 * @brief Parses arguments
 * 
 * @param argc number of arguments
 * @param argv arguments
 * @param upstream_dns_ip upstream ip
 * @param base_host host's base
 * @param dst_filepath destination file path
 * @param src_filepath source file path
 */
void parse_args(int argc, char** argv, char** upstream_dns_ip, char** base_host, char** dst_filepath, char** src_filepath) {
    if (argc > 6 or argc < 3) {
        ERROR(
            "Invalid input format!\n"
            "Valid format:\n"
            "\tdns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]\n"
        );
    }
    int opt, posopt_cnt = 0;
    while ((opt = getopt(argc, argv, "-u:")) != -1) {
        switch(opt) {
            case 'u': {
                *upstream_dns_ip = strdup(optarg);
                break;
            }
            /* parse positional arguments */
            default: {
                /* base host */
                if (posopt_cnt == 0) { *base_host = strdup(optarg); }
                /* dst_filepath */
                else if (posopt_cnt == 1) { *dst_filepath = strdup(optarg); }
                /* src_filepath */
                else if (posopt_cnt == 2) { *src_filepath = strdup(optarg); }
                posopt_cnt++;
                break;
            }
        }
    }

}


/**
 * @brief Packs chunk of data into dns query
 * 
 * @param packed_data pointer to packed data
 * @param data data to be packed
 * @param data_length length of data
 * @param base_labels array of host's base labels
 * @param n_base_labels number of host's base labels
 * @param packing_filename if packing filename
 * @return number of bytes in packet
 */
int pack_data(char* packed_data, char* data, int data_length, char** base_labels, int n_base_labels, bool packing_filename) {

    /* encode data to base32 */
    char encoded_data_buffer[512];  // buffer large enough
    base32_encode(data, data_length, encoded_data_buffer, 512);
    size_t encoded_length = strlen(encoded_data_buffer);
    char encoded_data[encoded_length];
    strcpy(encoded_data, encoded_data_buffer);

    /* define pointers to two parts of the query */
    struct dns_header* dns_header_ptr = (struct dns_header*)packed_data;
    char* dns_payload_ptr = packed_data + sizeof(struct dns_header);

    /* set header */
    uint16_t unique_id = packing_filename ? (rand() % 20) + ID_OFFSET : rand() % ID_OFFSET;
    dns_header_ptr->id = htons(unique_id); // 65515+ for packets with filename
    dns_header_ptr->flags = htons(0x0100);  // recursion desired flag
    dns_header_ptr->qwcount = htons(1);  // only one question per query

    int encoded_data_offset = 0;
    bool last_label = false;
    size_t label_length = 0;
    char label_buffer[MAX_LABEL_LENGTH+1];
    memset(label_buffer, 0, MAX_LABEL_LENGTH+1);

    /* encode data into labels */
    while (true) {
        /* read 63 characters from encoded data */
        memset(label_buffer, 0, MAX_LABEL_LENGTH);
        strncpy(label_buffer, encoded_data + encoded_data_offset, MAX_LABEL_LENGTH);
        if ((label_length = strlen(label_buffer)) == 0) { break; }
        encoded_data_offset += label_length;

        *(dns_payload_ptr++) = (uint8_t)label_length;
        strncpy(dns_payload_ptr, label_buffer, label_length);
        dns_payload_ptr += label_length;
    }

    /* add base */
    size_t base_label_length = 0;
    for (int i=0; i<n_base_labels; i++) {
        base_label_length = strlen(base_labels[i]);

        *(dns_payload_ptr++) = (uint8_t)base_label_length;
        strncpy(dns_payload_ptr, base_labels[i], base_label_length);
        dns_payload_ptr += base_label_length;
    }
    /* add terminator */
    *(dns_payload_ptr++) = '\0';
    /* qclass, set to Internet */
    *((uint16_t *)(dns_payload_ptr)) = htons(1);
    dns_payload_ptr += 2;
    /* qtype, set to A */
    *((uint16_t *)(dns_payload_ptr)) = htons(1);
    dns_payload_ptr += 2;
    /* find octets that were actually used */
    char c = 0;
    int bytes = 0;
    for (bytes=MAX_QUERY_LENGTH-1; c==0; (bytes)--) c = packed_data[bytes];
    return bytes + 2;

}


int main(int argc, char** argv) {

    /* parse args */
    char *upstream_dns_ip = NULL, *base_host = NULL, *dst_filepath = NULL, *src_filepath = NULL;
    parse_args(argc, argv, &upstream_dns_ip, &base_host, &dst_filepath, &src_filepath);

    /* validate args */
    validate__upstream_dns_ip(&upstream_dns_ip);    
    validate__base_host(base_host);
    validate__src_filepath(src_filepath);
    validate__dst_filepath(dst_filepath);

    FILE* file_ptr = src_filepath == NULL ? stdin : fopen(src_filepath, "r");

    int n_bytes_to_read = SENDER_READ_BUFFER - strlen(base_host) - 1;  // reduce buffer size by the length of ".{base_host}"
    char buffer[n_bytes_to_read];
    bool got_file_name = false;

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

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(DNS_PORT);
    server_address.sin_addr.s_addr = inet_addr(upstream_dns_ip);
    
    
    dns_sender__on_transfer_init(&server_address.sin_addr);

    int dst_filename_offset = 0;
    while (not feof(file_ptr)) {

        memset(buffer, 0, n_bytes_to_read);
        /* read filepath */
        if (sending_filename and dst_filename_offset < strlen(dst_filepath)) {
            strncpy(buffer, dst_filepath+dst_filename_offset, n_bytes_to_read);
            data_length = strlen(buffer);
            dst_filename_offset += n_bytes_to_read;
        } 
        /* read file */
        else {
            sending_filename = false;
            data_length = fread(buffer, 1, n_bytes_to_read, file_ptr);
        }
        /* pack data */
        memset(packed_data_buffer, 0, MAX_QUERY_LENGTH);
        int bytes = pack_data(packed_data_buffer, buffer, data_length, base_labels, base_label_cnt, sending_filename);

        /* trim trailing zeros */
        char packed_data[bytes];
        memcpy(packed_data, packed_data_buffer, bytes);
        struct dns_header* dns_header_ptr = (struct dns_header*)packed_data;
        
        dns_sender__on_chunk_encoded(dst_filepath, dns_header_ptr->id, packed_data + sizeof(struct dns_header));

        if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) { ERROR("Socked creation failed\n"); }
    

send:
        /* send query to server */
        if (sendto(socket_fd, packed_data, sizeof(packed_data), 
                   MSG_CONFIRM, (struct sockaddr*)&server_address, sizeof(struct sockaddr_in)) == -1) {
            FERROR("Error sending query #%d\n", dns_header_ptr->id);
        }
        
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        dns_sender__on_chunk_sent(&server_address.sin_addr, dst_filepath, dns_header_ptr->id, data_length);
        
        /* get response from server */
        char response_buffer[sizeof(packed_data)+sizeof(struct dns_response)];
        socklen_t socklen = sizeof(struct sockaddr_in);
        if (recvfrom(socket_fd, response_buffer, sizeof(response_buffer), 
                     MSG_WAITALL, (struct sockaddr *)&server_address, &socklen) == -1) {
            goto send;  // goto bad
        }

        close(socket_fd);
        
    }

    /* last packet */
    int bytes = pack_data(packed_data_buffer, "bye", data_length, base_labels, base_label_cnt, sending_filename);
    char packed_data[bytes];
    memcpy(packed_data, packed_data_buffer, bytes);
    struct dns_header* dns_header_ptr = (struct dns_header*)packed_data;
    dns_header_ptr->id = htons(DNS_MAX_ID);

    dns_sender__on_chunk_encoded(dst_filepath, dns_header_ptr->id, packed_data + sizeof(struct dns_header));

    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) { ERROR("Socked creation failed\n"); }

end:
    if (sendto(socket_fd, packed_data, sizeof(packed_data), 
           MSG_CONFIRM, (struct sockaddr*)&server_address, sizeof(struct sockaddr_in)) == -1) {
        ERROR("Error sending last query\n");
    }

    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    dns_sender__on_chunk_sent(&server_address.sin_addr, dst_filepath, dns_header_ptr->id, 0);

    char response_buffer[sizeof(packed_data)+sizeof(struct dns_response)];
    socklen_t socklen = sizeof(struct sockaddr_in);
    if (recvfrom(socket_fd, response_buffer, sizeof(response_buffer), 
                     MSG_WAITALL, (struct sockaddr *)&server_address, &socklen) == -1) {
            goto end;  // goto bad
    }

    struct dns_response* dns_response_ptr = (struct dns_response*)(response_buffer+sizeof(packed_data));
    /* get size of result file from final chunk */
    dns_sender__on_transfer_completed(dst_filepath, ntohl(dns_response_ptr->rdata));

    free(upstream_dns_ip); free(base_host); free(dst_filepath); free(src_filepath);
    fclose(file_ptr);

}
