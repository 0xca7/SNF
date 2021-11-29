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

    /* NOTE: either have this function memset the buffer 
             or the caller */

    IP *iphdr = (IP *)buffer;
    TCP *tcphdr = (TCP *)(buffer + sizeof(IP));
    uint8_t tcp_options[4] = { 0x00 };

    /* build the IP header */
    iphdr->version = 4;
    iphdr->ihl = 5;

    /* octet 2: DSCP and ECN are missing */

    /* NOTE: add PRNG here */
    iphdr->id = htons(0xdead) + 1; /* rand() & 0xffff + 1 */

    /* this value is not passed in, but retreived in init function */
    iphdr->saddr = inet_addr("127.0.0.1");

    iphdr->daddr = inet_addr("127.0.0.1");

    iphdr->protocol = IPPROTO_TCP;
    iphdr->ttl = 255;

    /* set to zero for calculation */
    iphdr->check = 0;
    iphdr->check = ip_calculate_checksum(&buffer[0], sizeof(IP));

    iphdr->tot_len = htons(sizeof(IP)+sizeof(TCP)+4);
    
    /* build the TCP header */
    /* NOTE: this value is random */
    tcphdr->source = htons(0x1e61);

    tcphdr->dest = 0x15b3;
    tcphdr->seq = 0;
    tcphdr->ack_seq = 1;
    
    /* offset is measured in 32-bit words. the standard offset value
       is the header size. here, bytes/one word of options are added */
    tcphdr->doff = ((sizeof(TCP)+4) / 4);

    tcphdr->syn = 1;
    tcphdr->window = htons(5840);
    tcphdr->check = 0;

    /* set dummy options */
    tcp_options[0] = 2;
    tcp_options[1] = 4;
    tcp_options[2] = 0;
    tcp_options[3] = 0xff;

    memcpy(buffer+sizeof(IP)+sizeof(TCP), tcp_options, 4);
    
    return PACKET_SUCCESS;
}


/*** end of file ***/

