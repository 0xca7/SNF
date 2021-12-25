/** @file packet.h
 * 
 * @brief A description of the module’s purpose. 
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

#ifndef PACKET_H
#define PACKET_H

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

/* project specific modules */
#include <global_cfg.h>
#include <util.h>

/***************************************************************************
 * MACROS
 **************************************************************************/

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/***************************************************************************
 * FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief builds a tcp packet
 * @param[inout] buffer stores the assembled TCP packet
 * @param[in] buffer_size size of the buffer param in bytes
 * @param[in] p_options the TCP options to add to the packet
 * @param[in] options_length the total length of options (incl. padding)
 * @param[in] src an in_addr_t, the source IP
 * @param[in] dst an in_addr_t, the destination IP
 * @param[in] port the destination port
 * @return -1 on failure, total packet length in bytes on success
 */
extern int 
packet_build_tcp(uint8_t *buffer, uint32_t buffer_size, 
    uint8_t *p_options, uint8_t options_length,
    in_addr_t src, in_addr_t dst, uint16_t port);

/**
 * @brief builds an ip packet
 * @param[inout] buffer stores the assembled IP packet
 * @param[in] buffer_size size of the buffer param in bytes
 * @param[in] p_options the TCP options to add to the packet
 * @param[in] options_length the total length of options (incl. padding)
 * @param[in] src an in_addr_t, the source IP
 * @param[in] dst an in_addr_t, the destination IP
 * @param[in] port the destination port
 * @return -1 on failure, total packet length in bytes on success
 */
extern int 
packet_build_ip(uint8_t *buffer, uint32_t buffer_size, 
    uint8_t *p_options, uint8_t options_length,
    in_addr_t src, in_addr_t dst, uint16_t port);



#endif /* PACKET_H */

/*** end of file ***/

