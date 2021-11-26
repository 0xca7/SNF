/** @file networking.c
 * 
 * @brief A description of the networking’s purpose. 
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


#include "networking.h"

/***************************************************************************
 * MACROS
 **************************************************************************/
#define NETWORKING_SUCCESS  0
#define NETWORKING_FAILURE  -1

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/** @brief keeps track if module is initialized */
static bool g_initialized = false;
/** @brief the module global socket file descriptor */
static int g_sockfd = -1;

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/
/**
 * @brief checks if a protocol passed to networking_init is valid or not
 * @param[in] protocol the protocol specifier to check
 * @return true if valid, false otherwise
 */
static bool
networking_check_protocol(int protocol);


/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

static bool
networking_check_protocol(int protocol)
{
    int i = 0;
    bool ret = false;
    int valid[4] = { IPPROTO_TCP, IPPROTO_RAW, 
        IPPROTO_UDP, IPPROTO_ICMP };

    for(i = 0; i < 4; i++)
    {
        if(protocol == valid[i])
        {
            ret = true;
            break;
        }
    }
    return ret;
}


/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/

int 
networking_init(int protocol)
{
    int ret = NETWORKING_FAILURE;
    
    /* if the protocol is not valid, there is not point in 
       continuing */
    if(networking_check_protocol(protocol))
    {
        g_sockfd = socket(AF_INET, SOCK_RAW, protocol);
        if(g_sockfd == -1)
        {
            printf("[NETWORKING] (socket) %s\n", strerror(errno));
        }
        else
        {
            g_initialized = true;
            ret = NETWORKING_SUCCESS;
        }
    }

    return ret;
}

int 
networking_deinit(void)
{
    int ret = NETWORKING_FAILURE;

    assert(g_initialized);

    if(close(g_sockfd) == -1)
    {
        printf("[NETWORKING] (close) %s\n", strerror(errno));
    }
    else 
    {
        g_sockfd = -1;
        g_initialized = false;
        ret = NETWORKING_SUCCESS;
    }

    return ret;
}

/*** end of file ***/

