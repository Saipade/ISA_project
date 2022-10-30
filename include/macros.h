#ifndef _MACROS_H
#define _MACROS_H

#define print printf

#define MAX_LABEL_SIZE 63           // maximum label size in domain name
#define MAX_DOMAIN_NAME_SIZE 252    // maximum domain name size
#define MAX_BUFFER_SIZE 1024        // maximum size of buffer
#define DNS_PORT 53                 // dns port

#define IP_REGEX "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))." \
                 "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."  \
                 "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."  \
                 "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$"

#endif  // _MACROS_H
