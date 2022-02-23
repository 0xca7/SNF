/*
    SNF - TCP/IP options fuzzing
    Copyright (C) 2022  0xca7

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/    

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
    int optval = 1;
    
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
            /* set the socket options for the created socket 
               so that no ip header is included, we write this
               ourselves */
            ret = setsockopt(g_sockfd, IPPROTO_IP, IP_HDRINCL,
                &optval, sizeof(optval));
            if(ret == -1)
            {
                printf("[NETWORKING] (setsockopt) %s\n", strerror(errno));
            }
            else 
            {
                g_initialized = true;
                ret = NETWORKING_SUCCESS;
            } /* setsockopt */
        } /* socket */
    } /* networking_check_protocol */


    return ret;
}

int
networking_send(uint8_t *buffer, uint32_t buffer_size, in_addr_t src) 
{
    assert(g_initialized);

    int ret = NETWORKING_FAILURE;
    struct sockaddr_in source = {0};
    
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = src;

    ret = sendto(g_sockfd, buffer, buffer_size, 0, (struct sockaddr *)&source, sizeof(source));

    if(ret == -1)
    {
        printf("[NETWORKING] (sendto) %s\n", strerror(errno));
    }
    else 
    {
        ret = NETWORKING_SUCCESS;
    }

    return ret;
}

int 
networking_deinit(void)
{
    int ret = NETWORKING_FAILURE;

    if(g_initialized) {
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
    }

    return ret;
}

/*** end of file ***/

