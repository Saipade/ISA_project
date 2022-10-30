#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#include "dns_receiver_events.h"
#include "../include/dns.h"


#define NETADDR_STRLEN (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)
#define CREATE_IPV4STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET, src, dst, NETADDR_STRLEN)
#define CREATE_IPV6STR(dst, src) char dst[NETADDR_STRLEN]; inet_ntop(AF_INET6, src, dst, NETADDR_STRLEN)


struct dns_header dns_header;


void dns_receiver__on_query_parsed(char *file_path, char *encoded_data) {
	fprintf(stderr, "[PARS] %s '%s'\n", file_path, encoded_data);
}

void on_chunk_received(char *source, char *file_path, int chunk_id, int chunk_size) {
	fprintf(stderr, "[RECV] %s %9d %dB from %s\n", file_path, chunk_id, chunk_size, source);
}

void dns_receiver__on_chunk_received(struct in_addr *source, char *file_path, int chunk_id, int chunk_size) {
	CREATE_IPV4STR(address, source);
	on_chunk_received(address, file_path, chunk_id, chunk_size);
}

void dns_receiver__on_chunk_received6(struct in6_addr *source, char *file_path, int chunk_id, int chunk_size)
{
	CREATE_IPV6STR(address, source);
	on_chunk_received(address, file_path, chunk_id, chunk_size);
}

void on_transfer_init(char *source) {
	fprintf(stderr, "[INIT] %s\n", source);
}

void dns_receiver__on_transfer_init(struct in_addr *source) {
	CREATE_IPV4STR(address, source);
	on_transfer_init(address);
}

void dns_receiver__on_transfer_init6(struct in6_addr *source) {
	CREATE_IPV6STR(address, source);
	on_transfer_init(address);
}

void dns_receiver__on_transfer_completed(char *file_path, int file_size) {
	fprintf(stderr, "[CMPL] %s of %dB\n", file_path, file_size);
}