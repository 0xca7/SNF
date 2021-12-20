/** @file networking.h
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

#ifndef NETWORKING_H
#define NETWORKING_H

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

/* project specific module */
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
 * @brief initializes the networking functionality
 * @param[in] protocol specifier for protocol to use see @protos
 *            is one of: 
 *            [IPPROTO_TCP, IPPROTO_RAW, IPPROTO_UDP, IPPROTO_ICMP]
 * @return -1 on failure, 0 on success
 */
extern int 
networking_init(int protocol);

/**
 * @brief send data via initialized networking module
 * @param buffer the buffer to send
 * @param buffer_size the size of the buffer / bytes in buffer
 * @param src the source address as a be32 
 * @return -1 on failure, 0 on success
 */
extern int 
networking_send(uint8_t *buffer, uint32_t buffer_size, in_addr_t src);

/**
 * @brief de-initializes the networking functionality 
 * @ return -1 on failure, 0 on success
 */
extern int 
networking_deinit(void);

#endif /* NETWORKING_H */

/*** end of file ***/

