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

#define PACKET_SIZE_TCP ( (uint32_t)sizeof(IP) + (uint32_t)sizeof(TCP) + 4 )

#define TCP_STANDARD_WINDOW_LEN 5840

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/
/** typedef for `struct iphdr` from netinet */
typedef struct iphdr IP;

/** typedef for `struct tcphdr ` from netinet */
typedef struct tcphdr TCP;

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
packet_build_tcp(uint8_t *p_buffer, uint32_t buffer_size, uint8_t *p_options)
{
    assert(p_buffer != NULL);
    assert(buffer_size >= PACKET_SIZE_TCP);

    /* IP header, TCP header and TCP options */
    const uint16_t TOTAL_PACKET_SIZE = (uint16_t)PACKET_SIZE_TCP;
    /* TCP header and TCP options, without IP header */
    const uint16_t TCP_SIZE = htons((uint16_t)PACKET_SIZE_TCP - sizeof(IP));
    const uint16_t PSEUDO_HEADER_SIZE = PACKET_SIZE_TCP - sizeof(IP) + 12;

    /* the 12-byte pseudo header for TCP checksum calculation 
       the entire TCP segment is appended to this */
    uint8_t pseudo_header[1024] = {0x00};

    /* NOTE: either have this function memset the buffer 
             or the caller */

    IP *iphdr = (IP *)p_buffer;
    TCP *tcphdr = (TCP *)(p_buffer + sizeof(IP));

    /* build the IP header */
    iphdr->version = 4;
    iphdr->ihl = 5;

    /* octet 2: DSCP and ECN are missing */

    iphdr->id = (uint16_t)((util_prng_gen() & 0xffff) + 1);

    /* this value is not passed in, but retreived in init function */
    iphdr->saddr = inet_addr("127.0.0.1");
    iphdr->daddr = inet_addr("127.0.0.1");

    iphdr->protocol = IPPROTO_TCP;
    iphdr->ttl = 255;

    /* set to zero for calculation */
    iphdr->check = 0;
    iphdr->check = ip_calculate_checksum(&p_buffer[0], sizeof(IP));

    iphdr->tot_len = TOTAL_PACKET_SIZE;
    
    /* build the TCP header */
    /* NOTE: this value is random */
    tcphdr->source = (uint16_t)((util_prng_gen() & 0xffff) + 1);

    tcphdr->dest = htons(0x15b3);
    tcphdr->seq = (uint32_t)((util_prng_gen() & 0xffff) + 1);
    tcphdr->ack_seq = 0;
    
    /* offset is measured in 32-bit words. the standard offset value
       is the header size. here, bytes/one word of options are added */
    tcphdr->doff = ((sizeof(TCP)+4) / 4);

    tcphdr->syn = 1;

    tcphdr->window = htons(5840);

    memcpy(p_buffer+TOTAL_PACKET_SIZE-4, p_options, 4);

    /* calculate checksum here. */
    tcphdr->check = 0;

    /* TCP pseudo header is: 
       IP src, IP dest, zero byte, protocol, tcp segment length,
       full TCP segment */
    memcpy(pseudo_header+0, (uint8_t*)&iphdr->saddr, 4);
    memcpy(pseudo_header+4, (uint8_t*)&iphdr->daddr, 4);
    /* zero byte skipped, already initialized to zero */
    memcpy(pseudo_header+9, (uint8_t*)&iphdr->protocol, 1);
    memcpy(pseudo_header+10, (uint8_t*)&TCP_SIZE, 2);
    /* add full TCP segment */
    memcpy(pseudo_header+12, p_buffer+sizeof(IP), htons(TCP_SIZE));

    tcphdr->check = ip_calculate_checksum(&pseudo_header[0], 
        PSEUDO_HEADER_SIZE);

    return PACKET_SUCCESS;
}


/*** end of file ***/

