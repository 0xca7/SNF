/** @file fuzzer.h
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

#ifndef FUZZER_H
#define FUZZER_H

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <assert.h>

#include <global_cfg.h>
#include <util.h>

/***************************************************************************
 * MACROS
 **************************************************************************/

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/**
 * @brief configuration for fuzzing
 * @fuzz_config
 */
typedef struct {
    struct in_addr src_ip;    /* see man ip(7) */
    struct in_addr target_ip; /* see man ip(7) */
    uint16_t target_port;     /* target port as number */
    e_fuzz_mode_t mode;       /* see global_cfg.h */
} fuzz_config_t;

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/***************************************************************************
 * FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief generates a new fuzz configuration 
 * @param[in] mode the fuzzer's modea
 * @param[in] ifname the interface to use for fuzzing
 * @param[in] target_ip the target's ip address as string
 * @param[in] target_port the target port 
 * @return an allocated fuzz_config_t or NULL on failure
 */
extern fuzz_config_t* fuzzer_new(e_fuzz_mode_t mode, char *ifname, 
    const char target_ip[15], uint16_t target_port);

/**
 * @brief initializes the fuzzer
 * @param[in] config the config to use for fuzzing, see @fuzz_config
 * @return -1 on failure, 0 on success
 */
extern int fuzzer_init(fuzz_config_t *config);

/**
 * @brief de-initializes the fuzzer
 * @param[in] an initialized fuzz configuration
 * @return -1 on failure, 0 on success
 */
extern int fuzzer_deinit(fuzz_config_t *config);

/**
 * @brief print a fuzzing configuration
 * @param p_config the configuration to print
 * @return void
 */
extern void
fuzzer_print_config(fuzz_config_t *p_config);


#endif /* FUZZER_H */

/*** end of file ***/

