#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <uuid/uuid.h>
#include <regex.h>

#include "dns_sender_events.h"
#include "../include/macros.h"
#include "../include/misc.h"
#include "../include/dns.h"
#include "../include/base64.h"

#define DEBUG 1

/**
 * @brief Validates upstream dns ip
 * 
 * @param upstream_dns_ip 
 */
void validate__upstream_dns_ip(char* upstream_dns_ip) {
    /* if no dns ip provided -> get default one */
    if (upstream_dns_ip == NULL) {
        log_message("Upstream dns ip is not provided, using default one");
        get_default_dns(upstream_dns_ip);
    }
    else {
        regex_t regex;
        int comp_res = regcomp(&regex, IP_REGEX, REG_EXTENDED);
        int not_valid = regexec(&regex, upstream_dns_ip, 0, NULL, 0);
        if (not_valid) {
            exit_w_error("Upstream dns address should be valid IPv4 address");
        }
    }
}


/**
 * @brief Validates source file path
 * 
 * @param src_filepath 
 */
void validate__src_filepath(char* src_filepath) {
    /* check if source file exists */
    if (src_filepath != NULL && access(src_filepath, F_OK) != 0) {
        exit_w_error("Source file does not exist!");
    }
    /* check if both --src_filepath and stdin are NULL */
    if (src_filepath == NULL && stdin == NULL) {
        exit_w_error("No source file has been passed either by --src_filepath parameter or by stdin");
    }
}


/**
 * @brief Validates domain's base
 * 
 * @param base_host 
 */
void validate__base_host(char* base_host) {
    /* copy base_host to tmp variable */
    size_t length = strlen(base_host);
    char host[length];
    strcpy(host, base_host);
    /*  */
    if (host[0] == '.') {
        exit_w_error("Base host should not start with \'.\'");
    }
    /* should allow at least 1 character to be transfered */
    if (strlen(host) > MAX_LABEL_SIZE * 4 - 1) {
        exit_w_error("Domain's base is too long, it should be shorter tрan 251");
    }
    const char delim[2] = ".";
    char* label = strtok(host, delim);
    while (label != NULL) {
        if (strlen(label) > MAX_LABEL_SIZE) {
            fprintf(stderr, "Label %s ", label);
            exit_w_error("in domain's base exceeds the maximum length for a single label");
        }
        label = strtok(NULL, delim);
    }
}


void parse_args(int argc, char** argv, char** upstream_dns_ip, char** base_host, char** dst_filepath, char** src_filepath) {
                    
    if (argc > 6 || argc < 3) {
        exit_w_error(
            "Wrong input format!\n"
            "Valid format:\n"
            "\tdns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]"
        );
    }

    int opt, posopt_cnt = 0;
    while ((opt = getopt(argc, argv, "-u:")) != -1) {
        switch(opt) {
            case 'u': {
                init_string(upstream_dns_ip, optarg);
                break;
            }
            /* parse positional arguments */
            default: {
                /* base host */
                if (posopt_cnt == 0) {
                    init_string(base_host, optarg);
                }
                /* dst_filepath */
                else if (posopt_cnt == 1) {
                    init_string(dst_filepath, optarg);
                }
                /* src_filepath */
                else if (posopt_cnt == 2) {
                    init_string(src_filepath, optarg);
                }
                posopt_cnt++;
                break;
            }
        }
    }

}


/**
 * @brief Craetes dns packet
 * 
 */
void pack_data(char* packed_data, int* bytes, char* data, char* base_host, int data_length) {
    /* parse base */
    size_t length = strlen(base_host);
    char host[length];
    strcpy(host, base_host);
    int cnt = 0;
    for (int i=0; host[i]; i++) {
        if (host[i] == '.') cnt++;
    }
    char* base_labels[cnt+1];
    cnt = 0;
    char* p = strtok(host, ".");
    while (p != NULL) {
        base_labels[cnt++] = p;
        p = strtok(NULL, ".");
    }

    /* encode data to base64 */
    int encoded_length = Base64encode_len(data_length);
    char* encoded_data = (char*)malloc(encoded_length * sizeof(char));
    Base64encode(encoded_data, data, data_length);

    struct dns_header* dns_header_ptr = (struct dns_header*)packed_data;
    char* dns_payload_ptr = packed_data + sizeof(struct dns_header);

    int random_id = rand() % 65536;
    dns_header_ptr->id = htons(random_id);
    dns_header_ptr->rd = htons(1);
    
    int question_count = 0, encoded_data_offset = 0;
    char domain_name_buffer[MAX_DOMAIN_NAME_SIZE];
    memset(domain_name_buffer, 0, MAX_DOMAIN_NAME_SIZE);
    bool last_query = false;
    uint8_t domain_name_length = 0;
    uint8_t base_len = (uint8_t)strlen(base_host);
    while (!last_query) {
        /* copy first N characters from encoded data */
        strncpy(domain_name_buffer, encoded_data + encoded_data_offset, MAX_DOMAIN_NAME_SIZE - base_len);

        if ((domain_name_length = strlen(domain_name_buffer)) < MAX_DOMAIN_NAME_SIZE - base_len) {
            last_query = true;
        }
        encoded_data_offset += domain_name_length;
        /* parse domain name label */
        bool last_label = false;
        uint8_t label_length = 0, domain_name_offset = 0, label_count = 0;
        char label_buffer[MAX_LABEL_SIZE];
        memset(label_buffer, 0, MAX_LABEL_SIZE);

        while (!last_label) {
            strncpy(label_buffer, domain_name_buffer + domain_name_offset, MAX_LABEL_SIZE);
            
            if ((label_length = (uint8_t)strlen(label_buffer)) < MAX_LABEL_SIZE) {
                last_label = true;
            }
            *(dns_payload_ptr++) = label_length;
            strncpy(dns_payload_ptr, label_buffer, label_length);
            dns_payload_ptr += label_length;
            domain_name_offset += label_length;
            label_count++;
        }
        /* add base */
        uint8_t base_label_length;
        for (int i=0; i<sizeof(base_labels)/sizeof(char*); i++) {
            base_label_length = (uint8_t)strlen(base_labels[i]);
            *(dns_payload_ptr++) = base_label_length;
            strncpy(dns_payload_ptr, base_labels[i], MAX_LABEL_SIZE);
            dns_payload_ptr += base_label_length;
        }
        /* terminator */
        *(dns_payload_ptr++) = '\0';
        /* qclass, set to Internet */
        *((uint16_t *)(dns_payload_ptr)) = htons(1);
        dns_payload_ptr += 2;
        /* qtype, set to A */
        *((uint16_t *)(dns_payload_ptr)) = htons(1);
        dns_payload_ptr += 2;
        question_count++;
    }

    dns_header_ptr->qdcount = htons(question_count);
    free(encoded_data);

    /* find octets that were actually used */
    char c = 0;
    for (*bytes=2023; c==0; (*bytes)--) c = packed_data[*bytes];
    *bytes = (*bytes) + 2;

}


int main(int argc, char** argv) {

    char* upstream_dns_ip = NULL, *base_host = NULL, *dst_filepath = NULL, *src_filepath = NULL;
    parse_args(argc, argv, &upstream_dns_ip, &base_host, &dst_filepath, &src_filepath);

    validate__upstream_dns_ip(upstream_dns_ip);
    validate__src_filepath(src_filepath);
    validate__base_host(base_host);

    FILE* f_ptr = src_filepath == NULL ? stdin : fopen(src_filepath, "r");
    int n_chars_to_read = MAX_LABEL_SIZE * 4 - strlen(base_host);

    int data_length;
    char payload_id[16], buffer[MAX_BUFFER_SIZE];

    while (!feof(f_ptr)) {
        /* read 63 * 4 - number of characters */
        data_length = fread(buffer, 1, MAX_BUFFER_SIZE, f_ptr);
        /* pack data */
        /* allocate buffer large enough */
        char packed_data_buffer[2024];
        memset(packed_data_buffer, 0, 2024);
        int bytes;
        pack_data(packed_data_buffer, &bytes, buffer, base_host, data_length);
        char packed_data[bytes];
        for (int i=0; i<bytes; i++) packed_data[i] = packed_data_buffer[i];
        struct dns_header* dns_header = (struct dns_header*)packed_data;
        char* data;
    }

    fclose(f_ptr);

}