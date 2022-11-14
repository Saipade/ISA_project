#ifndef _DNS_H
#define _DNS_H

#include <stdint.h>
#include <sys/types.h>

#define DNS_RESPONSE__PTR 192
#define DNS_RESPONSE__QNAME_PTR 12
#define MAX_LABEL_LENGTH 63             // maximum label size in domain name
#define DNS_PORT 53                     // dns port

#define MAX_QUERY_LENGTH 269            // dns header (12) + single dns query (257)
#define MAX_RESPONSE_LENGTH 285         // dns query (269) + single dns response (16)

#pragma pack(1)


/**
 * Structure that represents dns header
 */
struct dns_header {
    /* id */
    uint16_t            id;             // unique identifier, same for both query and response
    /* flags */
    uint16_t            flags;          // qr : 1
                                        // opcode : 4
                                        // aa : 1
                                        // tc : 1
                                        // rd : 1
                                        // ra : 1
                                        // z : 3
                                        // rcode : 4
    /* counts */
    uint16_t            qwcount;        // number of entries in the question section
    uint16_t            ancount;        // number of resource records in the answer section
    uint16_t            nscount;        // number of name server resource records in the authority records section 
    uint16_t            arcount;        // number of resource records in the additional records section
    
};


/**
 *  Structure that represents dns query
 */
struct dns_query {
    char*               qname;          // query name with domain name
    uint16_t            qtype;
    uint16_t            qclass;
};


/**
 *  Structure that represents dns response
 */
struct dns_response {
	uint8_t             response_type;  // always c0 (PTR)
    uint8_t             offset;         // always 0c (pointer to the qname)
	uint16_t	        record_type;
	uint16_t	        record_class;   
	uint32_t	        ttl;            // time to live
	uint16_t	        rdata_length;   // length of rdata
	uint32_t	        rdata;          // ip
};


#endif  // _DNS_H
