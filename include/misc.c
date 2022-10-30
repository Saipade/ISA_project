#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>


void init_string(char** dst, char* src) {
    *dst = (char*)malloc(sizeof(char) * strlen(src));
    strcpy(*dst, src);
}


void log_message(char* message) {
    fprintf(stderr, "%s\n", message);
}


void exit_w_error(char* message) {
    log_message(message);
    exit(EXIT_FAILURE);
}


void get_default_dns(char* dns_ip) {
    char buffer[1024];
    bool get_dns = false;
    FILE* f_ptr;
    if ((f_ptr = fopen("/etc/resolv.conf", "r")) == NULL) {
        exit_w_error("Failed opening /etc/resolv.conf");
    }
    while (fscanf(f_ptr, " %1023s", buffer) == 1) {
        if (get_dns) {
            init_string(dns_ip, buffer);
            return;
        }
        if (!strcmp(buffer, "nameserver")) {
            get_dns = true;
        }
    }
}
