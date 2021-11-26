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
#include <sys/socket.h>
#include <arpa/inet.h>

#include <assert.h>

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
 * @brief initializes the packet functionality
 * @param[in] protocol specifier for protocol to use see @protos
 *            is one of: 
 *            [IPPROTO_TCP, IPPROTO_RAW, IPPROTO_UDP, IPPROTO_ICMP]
 * @return -1 on failure, 0 on success
 */
extern int 
packet_init(int protocol);

/**
 * @brief send data via initialized packet module
 * @param buffer the buffer to send
 * @param buffer_size the size of the buffer / bytes in buffer
 * @return -1 on failure, 0 on success
 */
extern int 
packet_send(uint8_t *buffer, uint32_t buffer_size);

/**
 * @brief de-initializes the packet functionality 
 * @ return -1 on failure, 0 on success
 */
extern int 
packet_deinit(void);

#endif /* PACKET_H */

/*** end of file ***/

