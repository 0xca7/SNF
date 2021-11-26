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

#define IP struct iphdr
#define TCP struct tcphdr

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

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/
int 
packet_build_tcp(uint8_t *buffer, uint32_t buffer_size)
{
    assert(buffer_size >= PACKET_SIZE_TCP);

    IP *iphdr = (IP *)buffer;
    TCP *tcphdr = (TCP *)(buffer + sizeof(IP));

    return PACKET_SUCCESS;
}


/*** end of file ***/

