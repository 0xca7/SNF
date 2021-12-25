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

#ifndef GLOBAL_CFG_H
#define GLOBAL_CFG_H

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdio.h>

/***************************************************************************
 * MACROS
 **************************************************************************/

/** @brief checks if a value is NULL, returns 1 if true, 0 otherwise */
#define CHECK_NULL(v) ( (v == NULL) ? 1 : 0 )

/** brief on null pointer exception, print where it occured and exit */
#define NULL_PTR_EXCEPTION(s)\
    do\
    {\
        printf("NULL-Pointer Exception: ( %s )\n", s);\
        exit(1);\
    }\
    while(0)\

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/
typedef enum 
{
    FUZZ_MODE_IP_OPTIONS,   /* fuzz ip options */
    FUZZ_MODE_TCP_OPTIONS,  /* fuzz tcp options */
    /* NOTE: this must be in last place in the enum because of 
       internal checks. */
    FUZZ_MODE_INVALID,      /* placeholder for last item in enum */
} e_fuzz_mode_t; 

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/***************************************************************************
 * FUNCTIONS
 **************************************************************************/

#endif /* GLOBAL_CFG_H */

/*** end of file ***/
