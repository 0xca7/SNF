/** @file util.h
 * 
 * @brief contains uncategorized utility functions
 * 
 */ 

/**
 * Author:  0xca7
 * Desc:    various utility functions for the fuzzer
 *
 */

/**
 * Changelog:
 * [dd/mm/yyyy][author]: change
 */

#ifndef UTIL_H
#define UTIL_H

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
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
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
 * @brief initialized the module internal prng
 * @return -1 on failure, 0 on success
 */
extern int util_prng_init(void);

/**
 * @brief generate a random u64 value
 * @warning caller must ensure util_prng_init is called before
 *          using this function!
 * @return -1 on failure, 0 on success
 */
extern uint64_t util_prng_gen(void);

/**
 * @brief get the ip address assigned to a NIC, if it exists
 * @warning caller must make sure `ip` is large enough to hold result
 * @param[in] ifname the name of the interface to query
 * @param[inout] ip buffer to hold the IP
 * @return -1 on failure, 0 on success
 */
extern int util_get_nic_ip(char *ifname, char *ip);


#endif /* UTIL_H */

/*** end of file ***/

