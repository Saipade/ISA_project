#ifndef _MISC_H
#define _MISC_H


/**
 * @brief Initializes string with value given by `src`
 * 
 * @param dst string to be initialized
 * @param src init value
 */
void init_string(char** dst, char* src);


/**
 * @brief Prints message to stderr
 * 
 * @param message message to be printed
 */
void log_message(char* message);


/**
 * @brief Prints error message to stderr, exits with error
 * 
 * @param message message to be printed
 */
void exit_w_error(char* message);


/**
 * @brief Get the default dns server address
 * 
 * @param dns_ip dns ip to be set
 */
void get_default_dns(char* dns_ip);


#endif // _MISC_H
