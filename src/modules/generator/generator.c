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

#include <generator.h>

/***************************************************************************
 * MACROS
 **************************************************************************/
#define GENERATOR_SUCCESS  0
#define GENERATOR_FAILURE  -1

#define GENERATOR_CYCLE_NOT_DONE    1
#define GENERATOR_CYCLE_DONE        0

#define TCP_OPTS_NO_VALUES      14
#define TCP_OPTIONS_KIND        0
#define TCP_OPTIONS_LENGTH      1
#define TCP_OPTIONS_MAX_VARLEN  2

#define TCP_KIND_SACK 5
#define TCP_KIND_TCP_FAST_OPEN_COOKIE 34
#define TCP_KIND_TCP_ENCRYPTION_NEGOTIATION 69

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/** @brief the current cycle we are in */
static uint8_t g_cycle = 0;

/** @brief current fuzzing mode to use */
static e_fuzz_mode_t g_mode = FUZZ_MODE_INVALID;

/* kind, length, max length if variable */
const uint8_t g_TCP_OPTIONS[TCP_OPTS_NO_VALUES][3] = {

    /* END_OF_OPTION_LIST */
    { 0, 1, 0 },
    /* NOP */
    { 1, 1, 0 },
    /* MSS */
    { 2, 4, 0 },
    /* WINDOW_SCALE */
    { 3, 3, 0 },
    /* SACK_PERMITTED */
    { 4, 2, 0 },
    /* SACK */
    { 5, 10, 40 },
    /* TIMESTAMPS */
    { 8, 10, 0 },
    /* TRAILER_CHKSM */
    { 18, 3, 0 },
    /* QUICK_START_RESPONSE */
    { 27, 8, 0 },
    /* USER_TIMEOUT */
    { 28, 4, 0 },
    /* TCP_AUTH */
    { 29, 4, 0 },
    /* TCP_MULTIPATH */
    { 30, 4, 0 },
    /* TCP_FAST_OPEN_COOKIE */
    { 34, 4, 16 },
    /* TCP_ENCRYPTION_NEGOTIATION */
    { 69, 1, 40 }
};

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief generates the next option fields for a fuzz packet
 * @param[inout] p_tcp_options the buffer to hold options
 * @return combinations are left: 1, done: 0, error: -1
 */
static int
generator_cycle_tcp_options(uint8_t *p_tcp_options);

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

static int
generator_cycle_tcp_options(uint8_t *p_tcp_options) 
{
    /* 
        this function builds the next option array 
        if there are no more combinations left, this
        shall return 0. In case an option was selected,
        return 1. On error, return -1.
    */

    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;

    /* all cycles are complete */
    if(g_cycle == TCP_OPTS_NO_VALUES)
    {
        g_cycle = 0;
    }
    else
    {
        /* if there are still cycles to fuzz */
        ret = GENERATOR_CYCLE_NOT_DONE;

        /* first byte is the kind */
        *(p_tcp_options+0) = g_TCP_OPTIONS[g_cycle][TCP_OPTIONS_KIND];

        /* then comes the length, if it is variable, choose a random value 
           here, the length is the min value, where the MAX_VARLEN is the 
           max value */
        if(g_TCP_OPTIONS[g_cycle][TCP_OPTIONS_MAX_VARLEN] != 0) 
        {
            uint8_t rand = (uint8_t)util_prng_gen();
            uint8_t max = g_TCP_OPTIONS[g_cycle][TCP_OPTIONS_MAX_VARLEN];
            uint8_t min = g_TCP_OPTIONS[g_cycle][TCP_OPTIONS_LENGTH];
            
            /* lengths are not fully variable. this has to be refined. 
               for instance, TCP SACKs come in 10 byte blocks and can
               have a max of 4 blocks */

            switch(g_TCP_OPTIONS[g_cycle][TCP_OPTIONS_KIND]) 
            {
                case TCP_KIND_SACK:
                    /* there must be one block, max 4 blocks */
                    rand = rand % 4 + 1;
                    *(p_tcp_options+1) = 10 * rand;
                break;
                case TCP_KIND_TCP_FAST_OPEN_COOKIE:
                    /* this is ok, between 4 and 16 bytes */
                    *(p_tcp_options+1) = (rand % (max-min+1)) + min;
                break;
                case TCP_KIND_TCP_ENCRYPTION_NEGOTIATION:
                    /* more information needed here */
                    *(p_tcp_options+1) = (rand % (max-min+1)) + min;
                break;
                default:
                    printf("[GENERATOR] ERROR invalid KIND value for length\n");
                    *(p_tcp_options+1) = 0;
                break;
            }

        }
        else
        {
            *(p_tcp_options+1) = g_TCP_OPTIONS[g_cycle][TCP_OPTIONS_LENGTH];
        }

        /* depending on the length value, fill the rest of the bytes */
        for(i = 0; i < *(p_tcp_options+1); i++)
        {
            *(p_tcp_options+2+i) = (uint8_t)(util_prng_gen() & 0xff);   
        }

        g_cycle++;
    }

    return ret;
}

/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/

extern int
generator_init(e_fuzz_mode_t mode)
{
    g_mode = mode;
    g_cycle = 0;

    return 0;
}

extern int
generator_run_tcp(uint8_t *tcp_options)
{
    return generator_cycle_tcp_options(tcp_options);
}


/*** end of file ***/
