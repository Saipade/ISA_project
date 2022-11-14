#include <stdio.h>

/* prints log message to stderr */
#define LOG(f_string) fprintf(stderr, f_string);

/* prints formatted log message to stderr */
#define FLOG(f_string, ...) fprintf(stderr, f_string, __VA_ARGS__);

/* prints error to stderr */
#define ERROR(f_string) fprintf(stderr, f_string); \
                        exit(EXIT_FAILURE);

/* prints formatted error to stderr */
#define FERROR(f_string, ...) fprintf(stderr, f_string, __VA_ARGS__); \
                             exit(EXIT_FAILURE);
