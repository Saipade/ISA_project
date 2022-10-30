#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dns_sender_events.h"

#define NETADDR_STRLEN (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)
#define CREATE_IPV4STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET, src, dst, NETADDR_STRLEN)
#define CREATE_IPV6STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET6, src, dst, NETADDR_STRLEN)


void dns_sender__on_chunk_encoded(char *file_path, int chunk_id, char *encoded_data) {
	fprintf(stderr, "[ENCD] %s %9d '%s'\n", file_path, chunk_id, encoded_data);
}

void on_chunk_sent(char *source, char *file_path, int chunk_id, int chunk_size) {
	fprintf(stderr, "[SENT] %s %9d %dB to %s\n", file_path, chunk_id, chunk_size, source);
}

void dns_sender__on_chunk_sent(struct in_addr *dest, char *file_path, int chunk_id, int chunk_size) {
	CREATE_IPV4STR(address, dest);
	on_chunk_sent(address, file_path, chunk_id, chunk_size);
}

void dns_sender__on_chunk_sent6(struct in6_addr *dest, char *file_path, int chunk_id, int chunk_size) {
	CREATE_IPV6STR(address, dest);
	on_chunk_sent(address, file_path, chunk_id, chunk_size);
}

void on_transfer_init(char *source) {
	fprintf(stderr, "[INIT] %s\n", source);
}

void dns_sender__on_transfer_init(struct in_addr *dest) {
	CREATE_IPV4STR(address, dest);
	on_transfer_init(address);
}

void dns_sender__on_transfer_init6(struct in6_addr *dest) {
	CREATE_IPV6STR(address, dest);
	on_transfer_init(address);
}

void dns_sender__on_transfer_completed(char *file_path, int file_size) {
	fprintf(stderr, "[CMPL] %s of %dB\n", file_path, file_size);
}