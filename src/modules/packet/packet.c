/** @file packet.c
 * 
 * @brief A description of the packet’s purpose. 
 *
 */


/**
 * Author:  0xca7
 * Desc:    this is a template header
 *
 */

/**
 * Changelog:
 * [dd/mm/yyyy][author]: change
 */

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdint.h>
#include <stdbool.h>

#include "packet.h"

/***************************************************************************
 * MACROS
 **************************************************************************/
#define PACKET_SUCCESS  0
#define PACKET_FAILURE  -1

/** typedef for `struct iphdr` from netinet */
typedef struct iphdr IP;

/** typedef for `struct tcphdr ` from netinet */
typedef struct tcphdr TCP;

#define PACKET_SIZE_TCP ( (uint32_t)sizeof(IP) + (uint32_t)sizeof(TCP) + 4 )

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/
/**
 * @brief calculate the checksum of the IPv4 header
 * @param[in] bytes bytes the header consists of 
 * @param[in] len the number of bytes passed in
 * @return the checksum value
 */
static uint16_t 
ip_calculate_checksum(uint8_t *bytes, uint16_t len);

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/
static uint16_t
ip_calculate_checksum(uint8_t *bytes, uint16_t len)
{
    int i = 0; 
    uint32_t sum = 0;
    
    /*
        Wikipedia:
        The checksum field is the 16-bit ones' complement of the ones' 
        complement sum of all 16-bit words in the header. For purposes 
        of computing the checksum, the value of the checksum field is zero. 
    */
    
    /* for the ones' complement sum, we can calculate the sum of the
       words first and get the carry count later.
       0,2,4,6,8,10,...
    */
    for(i = 0; i < len; i=i+2)
    {
        /* add the word to the sum */
        sum += (uint16_t)(*(bytes+i) << 8 | *(bytes+i+1));
    }

    printf("[DEBUG]: %04x\n", sum);

    /* in case len is odd, we need to add the odd byte */
    if(len % 2)
    {
        sum += *(bytes+len-1);
    }

    /* now get the carry count and add it to the sum */
    sum = (sum >> 16) + (sum & 0xffff);
    /* if there is another carry caused by the addition above, add it */
    sum += (sum >> 16);

    /* take the ones' complement of the result */
    return (uint16_t)~sum;
}

/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/
int 
packet_build_tcp(uint8_t *buffer, uint32_t buffer_size)
{
    assert(buffer_size >= PACKET_SIZE_TCP);

    IP *iphdr = (IP *)buffer;
    TCP *tcphdr = (TCP *)(buffer + sizeof(IP));

    /* octet 1: version and header length */
    iphdr->ihl = 4;
    iphdr->version = 5;
    /* octet 2: DSCP and ECN are missing */

    /* octett 3+4: length of whole packet in bytes, including IP header */
    iphdr->tot_len = 0;

    /* octet 5+6 id field */
    iphdr->id = 0; /* rand() & 0xffff + 1 */

    /* octet 7-8 is flags+fragment offset, which are ignored */
    
    /* octet TTL, octet Protocol, two octets header checksum */
    iphdr->protocol = IPPROTO_TCP;
    iphdr->ttl = 255;

    /* set to zero for calculation */
    iphdr->check = 0;
    iphdr->check = 0;

    return PACKET_SUCCESS;
}


/*** end of file ***/

