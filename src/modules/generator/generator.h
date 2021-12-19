/** @file generator.h
 * 
 * @brief entity which generates (some) packet contents
 * 
 */ 

/**
 * Author:  0xca7
 * Desc:    generates packet contents, for example TCP options
 *          for TCP option fuzzing
 */

/**
 * Changelog:
 * [dd/mm/yyyy][author]: change
 */

#ifndef GENERATOR_H
#define GENERATOR_H

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <assert.h>

#include <util.h>
#include <global_cfg.h>

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
 * @brief initialize the generator to the first cycle
 * @param[in] mode the mode to use for fuzzing
 * @return 0 on success, -1 on failure
 */
extern int
generator_init(e_fuzz_mode_t mode);

/**
 * @brief get the next tcp options value
 * @warning the caller must ensure that TCP options is large enough
 *          to hold all options that can be generated!
 * @param[inout] p_tcp_options the tcp options array to write to
 * @param[inout] p_total_length the total length incl. padding
 * @return 0 if no more cycles, 1 if more cycles
 */
extern int
generator_run(uint8_t *p_tcp_options, uint8_t *p_total_length);

#endif /* GENERATOR_H */

/*** end of file ***/



