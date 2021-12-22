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

/** @brief the size of a tcp packet excluding the option size */
#define PACKET_SIZE_TCP ( (uint32_t)sizeof(IP) + (uint32_t)sizeof(TCP) )

/** @brief maximum size the pseudo header can have 
    @note this is the size of the TCP header + max. options size
          which is 40 bytes and the added 12 bytes of the pseudo
          header fields from the IP header */
#define PSEUDO_HEADER_MAX_SIZE  ( (uint32_t)(sizeof(TCP) + 40 + 12))

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
packet_build_tcp(uint8_t *p_buffer, uint32_t buffer_size, 
    uint8_t *p_options, uint8_t options_length,
    in_addr_t src, in_addr_t dst, uint16_t port)
{
    assert(p_buffer != NULL);

    const uint16_t TOTAL_PACKET_SIZE = 
        (uint16_t)PACKET_SIZE_TCP + (uint16_t)options_length;

    /* TCP header and TCP options, without IP header, 
       size for this packet */
    const uint16_t PSEUDO_HEADER_SIZE = sizeof(TCP) + options_length + 12;

    /* the pseudo header for TCP checksum calculation 
       the entire TCP segment is appended to this. 
       can hold the max. size of the pseudo-header */
    uint8_t pseudo_header[PSEUDO_HEADER_MAX_SIZE] = {0x00};

    assert(buffer_size >= TOTAL_PACKET_SIZE);

    IP *iphdr = (IP *)p_buffer;
    TCP *tcphdr = (TCP *)(p_buffer + sizeof(IP));

    /* build the IP header */
    iphdr->version = 4;
    iphdr->ihl = 5;

    /* octet 2: DSCP and ECN are missing */
    iphdr->tos = 0;

    iphdr->id = (uint16_t)((util_prng_gen() & 0xffff) + 1);

    /* this value is not passed in, but retreived in init function */
    iphdr->saddr = src;
    iphdr->daddr = dst;

    iphdr->protocol = IPPROTO_TCP;
    iphdr->ttl = 255;

    /* set to zero for calculation */
    iphdr->check = 0;
    iphdr->check = ip_calculate_checksum(&p_buffer[0], sizeof(IP));

    iphdr->tot_len = htons(TOTAL_PACKET_SIZE);
    
    /* build the TCP header */
    /* NOTE: this value is random */
    tcphdr->source = (uint16_t)((util_prng_gen() & 0xffff) + 1);

    tcphdr->dest = htons(port);
    tcphdr->seq = (uint32_t)((util_prng_gen() & 0xffff) + 1);
    tcphdr->ack_seq = 0;
    
    /* offset is measured in 32-bit words. the standard offset value
       is the header size. here, bytes/one word of options are added */
    tcphdr->doff = (sizeof(TCP)+options_length) / 4;

    /* syn flag is always set */
    tcphdr->syn = 1;

    tcphdr->window = htons(5840);

    /* add the options here */
    memcpy(p_buffer+TOTAL_PACKET_SIZE-options_length, 
        p_options, options_length);

    /* calculate checksum here. */
    tcphdr->check = 0;

    /* TCP pseudo header is: 
       IP src, IP dest, zero byte, protocol, tcp segment length,
       full TCP segment */
    memcpy(pseudo_header+0, (uint8_t*)&iphdr->saddr, 4);
    memcpy(pseudo_header+4, (uint8_t*)&iphdr->daddr, 4);
    /* zero byte skipped, already initialized to zero */
    *(pseudo_header+9) = IPPROTO_TCP;
    *((uint16_t*)(pseudo_header+10)) = htons(TOTAL_PACKET_SIZE-sizeof(IP));
    /* add full TCP segment */
    memcpy(pseudo_header+12, p_buffer+sizeof(IP), TOTAL_PACKET_SIZE-sizeof(IP));

    tcphdr->check = htons(ip_calculate_checksum(&pseudo_header[0], 
        PSEUDO_HEADER_SIZE));

    return TOTAL_PACKET_SIZE;
}

int 
packet_build_ip(uint8_t *p_buffer, uint32_t buffer_size, 
    uint8_t *p_options, uint8_t options_length,
    in_addr_t src, in_addr_t dst, uint16_t port)
{
    assert(p_buffer != NULL);

    const uint16_t TOTAL_PACKET_SIZE = 
        (uint16_t)PACKET_SIZE_TCP + (uint16_t)options_length;

    /* TCP header and TCP options, without IP header, 
       size for this packet */
    const uint16_t PSEUDO_HEADER_SIZE = sizeof(TCP) + options_length + 12;

    /* the pseudo header for TCP checksum calculation 
       the entire TCP segment is appended to this. 
       can hold the max. size of the pseudo-header */
    uint8_t pseudo_header[PSEUDO_HEADER_MAX_SIZE] = {0x00};

    assert(buffer_size >= TOTAL_PACKET_SIZE);

    IP *iphdr = (IP *)p_buffer;
    TCP *tcphdr = (TCP *)(p_buffer + sizeof(IP) + options_length);

    /* build the IP header */
    iphdr->version = 4;
    /* 32-bit multiple of the header length and options */
    iphdr->ihl = (sizeof(IP) + options_length) / 4;

    /* octet 2: DSCP and ECN are missing */
    iphdr->tos = 0;

    iphdr->id = (uint16_t)((util_prng_gen() & 0xffff) + 1);

    /* this value is not passed in, but retreived in init function */
    iphdr->saddr = src;
    iphdr->daddr = dst;

    iphdr->protocol = IPPROTO_TCP;
    iphdr->ttl = 255;

    /* set to zero for calculation */
    iphdr->check = 0;
    iphdr->check = ip_calculate_checksum(&p_buffer[0], sizeof(IP));

    iphdr->tot_len = htons(TOTAL_PACKET_SIZE);

    /* add the options here */
    memcpy(p_buffer+sizeof(IP),
        p_options, options_length);
    
    /* build the TCP header */
    /* NOTE: this value is random */
    tcphdr->source = (uint16_t)((util_prng_gen() & 0xffff) + 1);

    tcphdr->dest = htons(port);
    tcphdr->seq = (uint32_t)((util_prng_gen() & 0xffff) + 1);
    tcphdr->ack_seq = 0;
    
    tcphdr->doff = sizeof(TCP) / 4;

    /* syn flag is always set */
    tcphdr->syn = 1;

    tcphdr->window = htons(5840);


    /* calculate checksum here. */
    tcphdr->check = 0;

    /* TCP pseudo header is: 
       IP src, IP dest, zero byte, protocol, tcp segment length,
       full TCP segment */
    memcpy(pseudo_header+0, (uint8_t*)&iphdr->saddr, 4);
    memcpy(pseudo_header+4, (uint8_t*)&iphdr->daddr, 4);
    /* zero byte skipped, already initialized to zero */
    *(pseudo_header+9) = IPPROTO_TCP;
    *((uint16_t*)(pseudo_header+10)) = htons(TOTAL_PACKET_SIZE
        - sizeof(IP) - options_length);
    /* add full TCP segment */
    memcpy(pseudo_header+12, p_buffer+sizeof(IP)+options_length, 
        TOTAL_PACKET_SIZE-sizeof(IP));
    tcphdr->check = htons(ip_calculate_checksum(&pseudo_header[0], 
        PSEUDO_HEADER_SIZE));



    return TOTAL_PACKET_SIZE;
}


/*** end of file ***/

