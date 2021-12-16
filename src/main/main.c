/** @file main.c
 * 
 * @brief the main application
 *
 */


/**
 * Author:  0xca7
 * Desc:    the main
 *
 */

/**
 * Changelog:
 * [dd/mm/yyyy][author]: change
 */

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdio.h>
#include <string.h>

#include <global_cfg.h>
#include <generator.h>
#include <packet.h>
#include <networking.h>

static void 
fuzz(void)
{
    int len = -1;
    uint8_t buffer[256] = { 0x00 };
    uint8_t tcp_options[32] = { 0x00 };

    if(networking_init(IPPROTO_TCP) == -1)
    {
        return;
    }

    if(util_prng_init() == -1)
    {
        return;
    }

    if(generator_init(FUZZ_MODE_TCP_OPTIONS) == -1)
    {
        return;
    }

    while( generator_run_tcp(&tcp_options[0]) )
    {
        len = packet_build_tcp(&buffer[0], 256, &tcp_options[0]);
        if(len == -1)
        {
            return;
        }
        else
        {
            printf("sending %d bytes\n", len);
        }
        if(networking_send(&buffer[0], len) == -1) 
        {
            return;
        }   
        memset(buffer, 0, 256);
    }

    if(networking_deinit() == -1)
    {
        return;
    }

}

int
main(int argc, char *argv[])
{
    fuzz();

    return 0;
}
