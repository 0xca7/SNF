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

/**
    TCP Options Fuzzing:
        1 - generate valid packets with valid options (kind, length paylaoad
            are all valid) to test the implementation.
        2 - generate packets with valid kind and random lengths and options
        3 - generate packets with valid kind and invalid length + random
            options (length is larger than bytes in options)
        4 - generate packets with random kind, valid length and random
            options of 4 bytes
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
#define GENERATOR_SUCCESS                   0
#define GENERATOR_FAILURE                   -1

#define GENERATOR_CYCLE_NOT_DONE            1
#define GENERATOR_CYCLE_DONE                0

#define TCP_OPTS_NO_VALUES                  14
#define TCP_OPTIONS_KIND                    0
#define TCP_OPTIONS_LENGTH                  1
#define TCP_OPTIONS_MAX_VARLEN              2

/** @brief number of packets to generate in fuzz iterations */
#define TCP_INVALID_COUNT                   50000

/** @brief the number of different mutations for TCP options */
#define TCP_NO_MUTATIONS                    4

#define TCP_KIND_SACK                       5
#define TCP_KIND_TCP_FAST_OPEN_COOKIE       34
#define TCP_KIND_TCP_ENCRYPTION_NEGOTIATION 69

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/
/** @brief used to set a generator function for the different fuzzing modes 
    */
typedef int (*gen_function_t)(uint8_t *, uint8_t *);

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/** @brief the function to use for generation of options */
static gen_function_t g_generate = NULL;

/** @brief the current cycle we are in */
static uint64_t g_cycle = 0;

/** @brief current fuzzing mode to use */
static e_fuzz_mode_t g_mode = FUZZ_MODE_INVALID;

static uint8_t g_current_mutation = 0;

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
 * @brief generates valid kind and length options
 * @param[inout] p_tcp_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static int
tcp_cycle_valid(uint8_t *p_tcp_options, uint8_t *p_total_length);

/**
 * @brief generates valid kind and random length options
 * @param[inout] p_tcp_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static int
tcp_cycle_random_length(uint8_t *p_tcp_options, uint8_t *p_total_length);

/**
 * @brief generates valid kind and length of payload is not length
 * @param[inout] p_tcp_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static int
tcp_cycle_invalid_length(uint8_t *p_tcp_options, uint8_t *p_total_length);

/**
 * @brief generates random, possibly invalid kind and an options length of 4
 * @param[inout] p_tcp_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static int
tcp_cycle_random_kind(uint8_t *p_tcp_options, uint8_t *p_total_length);

/**
 * @brief generates the next option fields for a fuzz packet
 * @param[inout] p_tcp_options the buffer to hold options
 * @param[inout] p_total_length options + padding length
 * @return combinations are left: 1, done: 0, error: -1
 */
static int
generator_tcp_options(uint8_t *p_tcp_options, uint8_t *p_total_length);

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

static int
tcp_cycle_valid(uint8_t *p_tcp_options, uint8_t *p_total_length) 
{
    /* 
        this function builds the next option array 
        if there are no more combinations left, this
        shall return 0. In case an option was selected,
        return 1. On error, return -1.
    */

    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;
    int padding = 0;

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

        /* if the options length is not a multiple of 32-bit wordlength
           then we have to pad with NOPs 
           calculation is as follows:

           residue classes:
           [0]: 0,4,8,12,...
           [1]: 1,5,9,...
           [2]: 2,6,10,...
           [3]: 3,7,11,...
            
           4 - [n] = number of bytes to pad
        */
        if(*(p_tcp_options+1) % 4 != 0)
        {
            padding = 4 - *(p_tcp_options+1) % 4;

            if(padding > 0) {
                memset(p_tcp_options+(*(p_tcp_options+1)), 0x01, padding);
            }
        }

        *p_total_length = *(p_tcp_options+1) + padding;

        g_cycle++;
    }

    return ret;
}

static int
tcp_cycle_random_length(uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    /* 
        this function builds the next option array 
        if there are no more combinations left, this
        shall return 0. In case an option was selected,
        return 1. On error, return -1.
    */

    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;
    int padding = 0;
    uint8_t rand = 0;

    /* all cycles are complete */
    if(g_cycle == TCP_INVALID_COUNT)
    {
        g_cycle = 0;
    }
    else
    {
        /* if there are still cycles to fuzz */
        ret = GENERATOR_CYCLE_NOT_DONE;

        /* get a random kind */
        rand = (uint8_t)util_prng_gen() % TCP_OPTS_NO_VALUES;
        *(p_tcp_options+0) = g_TCP_OPTIONS[rand][TCP_OPTIONS_KIND];

        /* get a random length. a valid tcp header has a max of 
           60 bytes WITH options. a tcp header without options is 
           20 bytes, thus a max. of 40 bytes can be added. we need
           at least 1 byte of options which are then padded. */
        rand = (uint8_t)util_prng_gen() % 40 + 1;
        *(p_tcp_options+1) = rand;

        /* depending on the length value, fill the rest of the bytes */
        for(i = 0; i < *(p_tcp_options+1); i++)
        {
            *(p_tcp_options+2+i) = (uint8_t)(util_prng_gen() & 0xff);   
        }

        /* if the options length is not a multiple of 32-bit wordlength
           then we have to pad with NOPs.
        */
        if(*(p_tcp_options+1) % 4 != 0)
        {
            padding = 4 - *(p_tcp_options+1) % 4;

            if(padding > 0) {
                memset(p_tcp_options+(*(p_tcp_options+1)), 0x01, padding);
            }
        }

        *p_total_length = *(p_tcp_options+1) + padding;

        g_cycle++;
    }

    return ret;
}

static int
tcp_cycle_invalid_length(uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    /* 
        this function builds the next option array 
        if there are no more combinations left, this
        shall return 0. In case an option was selected,
        return 1. On error, return -1.
    */

    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;
    int padding = 0;
    uint8_t rand = 0;
    uint8_t rand_min = 0;
    uint8_t rand_max = 0;

    /* all cycles are complete */
    if(g_cycle == TCP_INVALID_COUNT)
    {
        g_cycle = 0;
    }
    else
    {
        /* if there are still cycles to fuzz */
        ret = GENERATOR_CYCLE_NOT_DONE;

        /* get a random kind */
        rand = (uint8_t)util_prng_gen() % TCP_OPTS_NO_VALUES;
        *(p_tcp_options+0) = g_TCP_OPTIONS[rand][TCP_OPTIONS_KIND];

        /* get a random length. a valid tcp header has a max of 
           60 bytes WITH options. a tcp header without options is 
           20 bytes, thus a max. of 40 bytes can be added. we need
           at least 1 byte of options which are then padded. 
           
           set the length value to be larger than the options value.
           this means bytes will be missing.
        */
        rand_min = (uint8_t)util_prng_gen() % 40 + 1;
        rand_max = (uint8_t)util_prng_gen() % 40 + 1;
        
        /* swap if the minimum is greater than the maximum */
        if(rand_min > rand_max)
        {
            rand_min ^= rand_max;
            rand_max ^= rand_min;
            rand_min ^= rand_max;
        }
    
        *(p_tcp_options+1) = rand_max;

        /* fill in a random number of bytes for the "payload" */
        for(i = 0; i < rand_min; i++)
        {
            *(p_tcp_options+2+i) = (uint8_t)(util_prng_gen() & 0xff);   
        }

        /* if the options length is not a multiple of 32-bit wordlength
           then we have to pad with NOPs.
        */
        if(rand_min % 4 != 0)
        {
            padding = 4 - rand_min % 4;

            if(padding > 0) {
                memset(p_tcp_options+rand_min, 0x01, padding);
            }
        }

        /* make the length only what we actually have in data */
        *p_total_length = rand_min + padding;

        g_cycle++;
    }

    return ret;
}

static int
tcp_cycle_random_kind(uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    /* 
        this function builds the next option array 
        if there are no more combinations left, this
        shall return 0. In case an option was selected,
        return 1. On error, return -1.
    */

    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;
    uint8_t rand = 0;

    /* all cycles are complete */
    if(g_cycle == TCP_INVALID_COUNT)
    {
        g_cycle = 0;
    }
    else
    {
        /* if there are still cycles to fuzz */
        ret = GENERATOR_CYCLE_NOT_DONE;

        /* get a random completely kind */
        rand = (uint8_t)util_prng_gen() % 0xff;
        *(p_tcp_options+0) = rand;

        /* get a random length. a valid tcp header has a max of 
           60 bytes WITH options. a tcp header without options is 
           20 bytes, thus a max. of 40 bytes can be added. we need
           at least 1 byte of options which are then padded. */
        *(p_tcp_options+1) = 4;

        /* depending on the length value, fill the rest of the bytes */
        for(i = 0; i < *(p_tcp_options+1); i++)
        {
            *(p_tcp_options+2+i) = (uint8_t)(util_prng_gen() & 0xff);   
        }

        /* length is always 4 here */
        *p_total_length = *(p_tcp_options+1);

        g_cycle++;
    }

    return ret;
}

static int
generator_tcp_options(uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    int ret = GENERATOR_CYCLE_NOT_DONE;
    int cycle_done = GENERATOR_CYCLE_NOT_DONE;

    gen_function_t tcp_mutations[TCP_NO_MUTATIONS] = {
        &tcp_cycle_valid,
        &tcp_cycle_random_length,
        &tcp_cycle_invalid_length,
        &tcp_cycle_random_kind
    };

    gen_function_t mut = tcp_mutations[g_current_mutation];
        
    cycle_done = mut(p_tcp_options, p_total_length);
    if(cycle_done == -1)
    {
        ret = GENERATOR_FAILURE;
    }

    if(cycle_done == GENERATOR_CYCLE_DONE) {
        g_current_mutation++;
        if(g_current_mutation == TCP_NO_MUTATIONS)
        {
            g_current_mutation = 0;
            ret = GENERATOR_CYCLE_DONE;
        }
    }
    
    return ret;
}

/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/

extern int
generator_init(e_fuzz_mode_t mode)
{
    int ret = GENERATOR_FAILURE;

    g_cycle = 0;
    g_mode = mode;
    
    switch(g_mode)
    {
        case FUZZ_MODE_TCP_OPTIONS:
            g_generate = &generator_tcp_options;
            ret = GENERATOR_SUCCESS;
        break;
        case FUZZ_MODE_IP_OPTIONS:
            printf("[GENERATOR] IP Options Fuzzing - not implemented\n");
        break;
        default:
            printf("[GENERATOR] INVALID MODE\n");
        break;
    }

    return ret;
}

extern int
generator_run(uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    if(g_generate == NULL)
    {
        printf("[GENERATOR] null-pointer exception\n");
        return GENERATOR_FAILURE;
    }
    return g_generate(&p_tcp_options[0], p_total_length);
}


/*** end of file ***/
