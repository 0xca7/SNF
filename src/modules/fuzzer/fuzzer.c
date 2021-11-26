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


#include "fuzzer.h"

/***************************************************************************
 * MACROS
 **************************************************************************/
#define FUZZER_SUCCESS  0
#define FUZZER_FAILURE  -1

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/

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
 * @brief this function checks if the target IP is valid and converts it
 *        to a struct in_addr  
 * @param[in] ip the ip as a string (15 bytes)
 * @param[out] ip_addr the ip as a struct in_addr
 * @return 0 if conversion ok, -1 if failure
 */
static int 
fuzzer_convert_ip(const char ip[15], struct in_addr *ip_addr);

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



/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/
fuzz_config_t*
fuzzer_new(e_fuzz_mode_t mode, 
    const char target_ip[15], uint16_t target_port)
{
    assert(target_ip != NULL);

    int ret = FUZZER_FAILURE;
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

    int ret = FUZZER_SUCCESS;

    return ret;
}

int 
fuzzer_deinit(fuzz_config_t *config)
{
    assert(config != NULL);

    free(config);
    config = NULL;

    return FUZZER_SUCCESS;
}

/*** end of file ***/

