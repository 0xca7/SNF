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

/** @file fuzzer.c
 * 
 * @brief A description of the fuzzer’s purpose. 
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

#include <fuzzer.h>

/***************************************************************************
 * MACROS
 **************************************************************************/
#define FUZZER_SUCCESS  0
#define FUZZER_FAILURE  -1

/** @brief buffer size of options field */
#define OPT_BUFFER_SIZE  40
/** @brief send buffer size */
#define SEND_BUFFER_SIZE 256

#define MODE_STRING_IP_OPTIONS  "IP Options Fuzzing"
#define MODE_STRING_TCP_OPTIONS "TCP Options Fuzzing"
#define MODE_STRING_INVALID     "Invalid Mode"

/** @brief number of iterations between printing stats */
#define PRINT_INTERVAL          200

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/
static bool g_initialized = false;

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief this function checks if a suppored mode was passed 
 * @param[in] mode the mode that was passed in
 * @return 0 if mode ok, -1 on invalid mode
 */
static int 
fuzzer_check_mode(e_fuzz_mode_t mode);

/**
 * @brief get the protocol number for networking setup
 * @param[in] mode the mode to run the fuzzer in
 * @return protocol number, -1 on failure
 */
static int
fuzzer_get_proto(e_fuzz_mode_t mode);

/**
 * @brief this function checks if the target IP is valid and converts it
 *        to a struct in_addr  
 * @param[in] ip the ip as a string (15 bytes)
 * @param[out] ip_addr the ip as a struct in_addr
 * @return 0 if conversion ok, -1 if failure
 */
static int 
fuzzer_convert_ip(const char ip[15], struct in_addr *ip_addr);

/**
 * @brief get the mode as an ASCII string for printing
 * @param[in] mode the fuzzer mode
 * @return returns a string describing the mode
 */
static char*
fuzzer_mode_to_ascii(e_fuzz_mode_t mode);

/**
 * @brief prints current fuzzing stats 
 * @param[in] total the total number of iterations so far 
 * @return void
 */
static void
fuzzer_show_stats(fuzz_stats_t *p_stats);

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

static int 
fuzzer_check_mode(e_fuzz_mode_t mode)
{
    int ret = FUZZER_FAILURE;
    int i = 0;

    for(i = 0; i < FUZZ_MODE_INVALID; i++)
    {
        if((int)mode == i)
        {
            ret = FUZZER_SUCCESS;
            break;
        }
    }

    return ret;
}

static int
fuzzer_get_proto(e_fuzz_mode_t mode)
{
    int ret = FUZZER_FAILURE;

    switch(mode)
    {
        case FUZZ_MODE_TCP_OPTIONS:
            ret = IPPROTO_TCP;
        break;
        case FUZZ_MODE_IP_OPTIONS:
            ret = IPPROTO_TCP;
        break;
        default:
            printf("[FUZZER] invalid protocol\n");
        break;
    }

    return ret;
}

static int 
fuzzer_convert_ip(const char ip[15], struct in_addr *ip_addr)
{
    int ret = FUZZER_FAILURE;
    uint32_t converted_ip = 0;

    /* see: man inet_addr */
    converted_ip = inet_addr(ip);
    if(converted_ip != (in_addr_t)(-1))
    {
        ip_addr->s_addr = converted_ip;
        ret = FUZZER_SUCCESS;
    }

    return ret;
}

static char*
fuzzer_mode_to_ascii(e_fuzz_mode_t mode)
{
    char *p_mode_string = NULL;

    switch(mode)
    {
        case FUZZ_MODE_IP_OPTIONS:  
            p_mode_string = MODE_STRING_IP_OPTIONS;
        break;
        case FUZZ_MODE_TCP_OPTIONS:
            p_mode_string = MODE_STRING_TCP_OPTIONS;
        break;
        default:
            p_mode_string = MODE_STRING_INVALID;
        break;
    }
    return p_mode_string;
}


static void
fuzzer_show_stats(fuzz_stats_t *p_stats)
{
    system("clear");
    printf("\n\n\n\n");
    printf("PROGRESS ------------------------------------\n");
    printf("[+] total fuzz cases: %ld\n", p_stats->total);
    /*
        printf("[+] current phase:    %s\n", p_stats->phase);
    */
    printf("---------------------------------------------\n");
}


/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/
fuzz_config_t*
fuzzer_new(e_fuzz_mode_t mode, char *ifname,
    const char target_ip[15], uint16_t target_port)
{
    assert(ifname != NULL);
    assert(target_ip != NULL);

    int ret = FUZZER_FAILURE;
    char src_ip[16] = { 0x00 };
    fuzz_config_t *cfg = NULL;

    cfg = (fuzz_config_t*)malloc(sizeof(fuzz_config_t));
    if(cfg == NULL)
    {
        printf("[FUZZER] not able to alloc config memory\n");
        goto FUZZER_NEW_RETURN;
    }

    /* check if the mode field is valid */
    ret = fuzzer_check_mode(mode);
    if(ret == FUZZER_FAILURE)
    {
        printf("[FUZZER] invalid mode\n");
        goto FUZZER_NEW_FREE;
    }

    /* set the valid mode */
    cfg->mode = mode;

    /* get, set and check ip address for source and target */
    ret = util_get_nic_ip(ifname, &src_ip[0]);
    if(ret == FUZZER_FAILURE)
    {
        printf("[FUZZER] couldn't get IP for interface %s\n", ifname);
        goto FUZZER_NEW_FREE;
    }

    ret = fuzzer_convert_ip(src_ip, &cfg->src_ip);
    if(ret == FUZZER_FAILURE)
    {
        printf("[FUZZER] invalid source ip\n");
        goto FUZZER_NEW_FREE;
    }

    /* check if the ip addr is valid */
    ret = fuzzer_convert_ip(target_ip, &cfg->target_ip);
    if(ret == FUZZER_FAILURE)
    {
        printf("[FUZZER] invalid target ip\n");
        goto FUZZER_NEW_FREE;
    }

    if(target_port == 0)
    {
        printf("[FUZZER] port is zero\n");
        goto FUZZER_NEW_FREE;
    }

    /* if we get here, setup was successful */
    cfg->target_port = target_port;
    goto FUZZER_NEW_RETURN;

FUZZER_NEW_FREE:
    free(cfg);
    cfg = NULL;

FUZZER_NEW_RETURN:
    return cfg;
}

int 
fuzzer_init(fuzz_config_t *config)
{
    assert(config != NULL);

    int ret = FUZZER_FAILURE;

    ret = networking_init(fuzzer_get_proto(config->mode));
    if(ret == -1)
    {
        goto FUZZER_INIT_FAILURE;
    }

    ret = util_prng_init();
    if(ret == -1)
    {
        goto FUZZER_INIT_FAILURE;
    }

    ret = generator_init(config->mode);
    if(ret == -1)
    {
        goto FUZZER_INIT_FAILURE;
    }

    g_initialized = true;
    ret = FUZZER_SUCCESS;

FUZZER_INIT_FAILURE:
    return ret;
}

int
fuzzer_run(fuzz_config_t *p_config)
{
    int ret = FUZZER_SUCCESS;

    int len = -1;

    uint8_t buffer[SEND_BUFFER_SIZE] = { 0x00 };
    uint8_t options[OPT_BUFFER_SIZE] = { 0x00 };
    uint8_t options_length = 0;

    fuzz_stats_t stats = {
        .total = 0,
        .phase = { 0x00 }
    };

    if(CHECK_NULL(p_config))
    {
        NULL_PTR_EXCEPTION("fuzzer_run - p_config");
    }
   
    if(!g_initialized)
    {
        ret = FUZZER_FAILURE;
        return ret;
    }

    while( generator_run(&options[0], &options_length) )
    {

        if(p_config->mode == FUZZ_MODE_TCP_OPTIONS)
        {
            len = packet_build_tcp(&buffer[0], SEND_BUFFER_SIZE, 
                &options[0], options_length,
                p_config->src_ip.s_addr, p_config->target_ip.s_addr, 
                p_config->target_port);
        }

        if(p_config->mode == FUZZ_MODE_IP_OPTIONS)
        {
            len = packet_build_ip(&buffer[0], SEND_BUFFER_SIZE, 
                &options[0], options_length,
                p_config->src_ip.s_addr, p_config->target_ip.s_addr, 
                p_config->target_port);
        }

        if(len == -1)
        {
            printf("[FUZZER ERROR] - failed to build packet\n");
            ret = FUZZER_FAILURE;
            break;
        }
        else
        {
            stats.total++;
            if(stats.total % PRINT_INTERVAL == 0)
            {
                fuzzer_show_stats(&stats);
            }
        }

        if(networking_send(&buffer[0], len, p_config->target_ip.s_addr) == -1) 
        {
            printf("[FUZZER ERROR] - failed to send packet\n");
            ret = FUZZER_FAILURE;
            break;
        }   
        /* don't DOS */
        usleep(50);
        memset(buffer, 0, SEND_BUFFER_SIZE);
    } /* while */

    stats.total = 0;
    return ret;
}


int 
fuzzer_deinit(fuzz_config_t *config)
{
    assert(config != NULL);

    int ret = FUZZER_SUCCESS;

    ret = networking_deinit();
    if(ret == -1)
    {
        printf("[FUZZER] networking deinit failed\n");
    }

    free(config);
    config = NULL;

    return ret;
}

void
fuzzer_print_config(fuzz_config_t *p_config)
{
    printf("** FUZZING CONFIGURATION\n\n"); 
    printf("[+] Src IP:      %s\n", inet_ntoa(p_config->src_ip));
    printf("[+] Target IP:   %s\n", inet_ntoa(p_config->target_ip));
    printf("[+] Target Port: %d\n", p_config->target_port);
    printf("[+] Mode:        %s\n", fuzzer_mode_to_ascii(p_config->mode));
    printf("**\n");
}


/*** end of file ***/

