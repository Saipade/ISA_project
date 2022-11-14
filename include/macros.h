#ifndef _MACROS_H
#define _MACROS_H

#include <unistd.h>

#define print printf

#define SENDER_READ_BUFFER 150      // should be enough for a single query.
#define MAX_PATH_LENGTH 4096        // unix file path limit
#define ID_OFFSET 65514             // id offset to decide whether query contains filename or actual data
#define DNS_MAX_ID 65535            // max id number, used to identify the end of packet sequence

#define IP_REGEX "^([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))." \
                 "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."  \
                 "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))."  \
                 "([0-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5]))$"

#endif  // _MACROS_H
