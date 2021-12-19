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
 * @param[inout] buffer stores the assembles TCP packet
 * @param[in] buffer_size size of the buffer param in bytes
 * @param[in] p_options the TCP options to add to the packet
 * @param[in] options_length the total length of options (incl. padding)
 * @return -1 on failure, total packet length in bytes on success
 */
extern int 
packet_build_tcp(uint8_t *buffer, uint32_t buffer_size, 
    uint8_t *p_options, uint8_t options_length);


#endif /* PACKET_H */

/*** end of file ***/

