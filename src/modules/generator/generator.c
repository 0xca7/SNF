/** @file generator.c
 * 
 * @brief the generator generates packet options
 *
 */


/**
 * Author:  0xca7
 * Desc:    the generator is responsible for generating
 *          packet options
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

#include "generator.h"

/***************************************************************************
 * MACROS
 **************************************************************************/
#define GENERATOR_SUCCESS  0
#define GENERATOR_FAILURE  -1

#define TCP_OPTS_NO_VALUES  42

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/** @brief possible TCP option values for KIND field */
const uint8_t g_TCP_OPT_KIND[TCP_OPTS_NO_VALUES] = { 
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x45, 0x46, 0x4c, 0x4d, 0x4e, 
    0xfd, 0xfe 
};

/** @brief possible TCP option values for LEN field 
    @note
    -1: there is no value given in the documentation for the length
        of this field
    -2: the documentation says that the length is 'N'
    -3: the documentation says the length is 'variable'
*/
const int8_t g_TCP_OPT_LEN[TCP_OPTS_NO_VALUES] = { 
    0, 0, 4, 3, 2, -2, 6, 6, 10, 2, 3, -1, -1, -1, 3, -2, -1, -1, 3, 
    18, -1, -1, -1, -1, -1, -1, -1, 8, 4, -1, -2, -1, -1, -1, -3, -2, 
    -1, -1, -1, -1, -2, -2 
};

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/
/**
 * @brief generates the next option fields for a fuzz packet
 * @param[inout] p_tcp_options the buffer to hold options
 * @param[out] p_length the length field of the packet
 *        use this to determine the number of bytes to send 
 * @return combinations are left: 1, done: 0, error: -1
 */
static int
generator_cycle_tcp_options(uint8_t *p_tcp_options, int8_t *length) 
{
    /* 
        this function builds the next option array 
        of there are no more combinations left, this
        shall return 0. In case an option was selected,
        return 1. On error, return -1 
    */

    return 0;
}

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/

/*** end of file ***/

