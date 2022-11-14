#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include "logger.h"
#include "dns.h"


void validate__base_host(char* base_host) {
    
    /* copy base_host to tmp variable */
    size_t length = strlen(base_host);
    char host[length];
    strcpy(host, base_host);
    /* check if the first (0.) character is period */
    if (host[0] == '.') { ERROR("Base host should not start with \'.\'\n"); }
    
    /* should allow at least 1 character to be transfered */
    if (strlen(host) > 150) {
        ERROR("Domain's base is too long, it should be shorter than 150\n");
    }
    const char delim[2] = ".";
    char* label = strtok(host, delim);
    while (label != NULL) {
        if (strlen(label) > MAX_LABEL_LENGTH) { FERROR("Label %s in domain's base exceeds the maximum length for a single label", label); }
        label = strtok(NULL, delim);
    }

}
