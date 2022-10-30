#ifndef _DNS_H
#define _DNS_H

#include <stdint.h>
#include <sys/types.h>


#pragma pack(1)


/**
 * Structure that represents dns header
 */
struct dns_header {
    /* id */
    uint16_t            id;             // unique identifier, same for both query and response
    /* flags */
    unsigned char       qr : 1;         // 0 for query, 1 for response
    unsigned char       opcode : 4;     // specifies kind of query
    unsigned char       aa : 1;         // whether or not the response is authoritative
    unsigned char       tc : 1;         // specifies that this message was truncated
    unsigned char       rd : 1;         // if recursion is desired
    unsigned char       ra : 1;         // if recursive query support is available
    unsigned char       z : 3;          // reserved
    unsigned char       rcode : 4;      // response code
    /* counts */
    uint16_t            qdcount;        // number of entries in the question section
    uint16_t            ancount;        // number of resource records in the answer section
    uint16_t            nscount;        // number of name server resource records in the authority records section 
    uint16_t            arcount;        // number of resource records in the additional records section
    
};


/**
 *  Structure that represents dns response
 */
struct dns_response {
	char*		        name;
	uint16_t	        record_type;
	uint16_t	        record_class;
	uint32_t	        ttl;
	uint16_t	        rdata_length;
	char*		        rdata;
};


/**
 *  Structure that represents dns query
 */
struct dns_query {
    char*               qname;          // query name with domain name
    uint16_t            qtype;
    uint16_t            qclass;
};


struct packet_data {
    struct dns_header   header;
    char*               payload;    
};

#endif  // _DNS_H
