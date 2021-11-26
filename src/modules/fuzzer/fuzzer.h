/** @file module.h
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

/***************************************************************************
 * MACROS
 **************************************************************************/

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/**
 * @brief fuzz modes available
 * @fuzz_modes
 */
typedef enum 
{
    FUZZ_MODE_IP_OPTIONS,
    FUZZ_MODE_TCP_OPTIONS,
} e_fuzz_mode_t; 

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/***************************************************************************
 * FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief initializes the fuzzer
 * @param[in] mode the mode to use for fuzzing, see @fuzz_modes
 * @return -1 on failure, 0 on success
 */
int fuzzer_init(e_fuzz_mode_t mode);




#endif /* FUZZER_H */

/*** end of file ***/

