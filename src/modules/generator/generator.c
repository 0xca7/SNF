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

/** @brief readable return value on success */
#define GENERATOR_SUCCESS                   0
/** @brief readable return value on failure */
#define GENERATOR_FAILURE                   -1

/** @brief indicates that a cycle of generating option values is not done */
#define GENERATOR_CYCLE_NOT_DONE            1
/** @brief indicates that a cycle of generating option values is done */
#define GENERATOR_CYCLE_DONE                0

/***************************************************************************
 * TCP specific
 */

/** @brief total number of options for TCP */
#define TCP_OPTS_NO_VALUES                  14
/** @brief index for the `kind` of an option */
#define TCP_OPTIONS_KIND                    0
/** @brief index for the `length` of an option */
#define TCP_OPTIONS_LENGTH                  1
/** @brief index for the maximum length  of an option */
#define TCP_OPTIONS_MAX_VARLEN              2

/** @brief number of packets to generate in fuzz iterations */
#define TCP_INVALID_COUNT                   50000

/** @brief the number of different mutations for TCP options */
#define TCP_NO_MUTATIONS                    3

/** @brief the kind number for the SACK option */
#define TCP_KIND_SACK                       5

/** @brief the kind number for the fast open cookie option */
#define TCP_KIND_TCP_FAST_OPEN_COOKIE       34

/** @brief the kind number for the encryption negotiation option */
#define TCP_KIND_TCP_ENCRYPTION_NEGOTIATION 69

/** @brief value to pad TCP options with */
#define TCP_PAD_VALUE                       0x01

/**************************************************************************/



/***************************************************************************
 * IP specific
 */

/** @brief total number of IP options */
#define IP_OPTS_NO_VALUES                   13

/** @brief index for the option type */
#define IP_OPTION_TYPE                      0

/** @brief index for the option length */
#define IP_OPTION_LENGTH                    1

/** @brief index for the maximum option length */
#define IP_OPTION_MAX_VARLEN                2

/** @brief the number of different mutations for IP options */
#define IP_NO_MUTATIONS                     2

/** @brief the number of invalid IP packets to send */
#define IP_NO_INVALID                  50000U

/** @brief value to pad TCP options with */
#define IP_PAD_VALUE                       0x00

/***************************************************************************
 * IP specific, from wireshark dissector 
 * https://github.com/wireshark/
 * wireshark/blob/master/epan/dissectors/packet-ip.c
 */

/* IP options */
#define IPOPT_COPY              0x80

#define IPOPT_CONTROL           0x00
#define IPOPT_RESERVED1         0x20
#define IPOPT_MEASUREMENT       0x40
#define IPOPT_RESERVED2         0x60

/* REF: http://www.iana.org/assignments/ip-parameters */
#define IPOPT_EOOL      (0 |IPOPT_CONTROL)
#define IPOPT_NOP       (1 |IPOPT_CONTROL)
#define IPOPT_SEC       (2 |IPOPT_COPY|IPOPT_CONTROL)       /* RFC 791/1108 */
#define IPOPT_LSR       (3 |IPOPT_COPY|IPOPT_CONTROL)
#define IPOPT_TS        (4 |IPOPT_MEASUREMENT)
#define IPOPT_ESEC      (5 |IPOPT_COPY|IPOPT_CONTROL)       /* RFC 1108 */
#define IPOPT_CIPSO     (6 |IPOPT_COPY|IPOPT_CONTROL)       /* draft-
                                                               ietf-cipso-
                                                               ipsecurity-01 */
#define IPOPT_RR        (7 |IPOPT_CONTROL)
#define IPOPT_SID       (8 |IPOPT_COPY|IPOPT_CONTROL)
#define IPOPT_SSR       (9 |IPOPT_COPY|IPOPT_CONTROL)
#define IPOPT_ZSU       (10|IPOPT_CONTROL)                  /* Zsu */
#define IPOPT_MTUP      (11|IPOPT_CONTROL)                  /* RFC 1063 */
#define IPOPT_MTUR      (12|IPOPT_CONTROL)                  /* RFC 1063 */
#define IPOPT_FINN      (13|IPOPT_COPY|IPOPT_MEASUREMENT)   /* Finn */
#define IPOPT_VISA      (14|IPOPT_COPY|IPOPT_CONTROL)       /* Estrin */
#define IPOPT_ENCODE    (15|IPOPT_CONTROL)                  /* VerSteeg */
#define IPOPT_IMITD     (16|IPOPT_COPY|IPOPT_CONTROL)       /* Lee */
#define IPOPT_EIP       (17|IPOPT_COPY|IPOPT_CONTROL)       /* RFC 1385 */
#define IPOPT_TR        (18|IPOPT_MEASUREMENT)              /* RFC 1393 */
#define IPOPT_ADDEXT    (19|IPOPT_COPY|IPOPT_CONTROL)       /* Ullmann IPv7 */
#define IPOPT_RTRALT    (20|IPOPT_COPY|IPOPT_CONTROL)       /* RFC 2113 */
#define IPOPT_SDB       (21|IPOPT_COPY|IPOPT_CONTROL)       /* RFC 1770 Graff */
#define IPOPT_UN        (22|IPOPT_COPY|IPOPT_CONTROL)       /* Released 18-Oct-2005 */
#define IPOPT_DPS       (23|IPOPT_COPY|IPOPT_CONTROL)       /* Malis */
#define IPOPT_UMP       (24|IPOPT_COPY|IPOPT_CONTROL)       /* Farinacci */
#define IPOPT_QS        (25|IPOPT_CONTROL)                  /* RFC 4782 */
#define IPOPT_EXP       (30|IPOPT_CONTROL)                  /* RFC 4727 */


/* IP option lengths */
#define IPOLEN_SEC_MIN          3
#define IPOLEN_LSR_MIN          3
#define IPOLEN_TS_MIN           4
#define IPOLEN_ESEC_MIN         3
#define IPOLEN_CIPSO_MIN        10
#define IPOLEN_RR_MIN           3
#define IPOLEN_SID              4
#define IPOLEN_SSR_MIN          3
#define IPOLEN_MTU              4
#define IPOLEN_TR               12
#define IPOLEN_RA               4
#define IPOLEN_SDB_MIN          6
#define IPOLEN_QS               8
#define IPOLEN_MAX              40

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

const uint8_t g_IP_OPTIONS[IP_OPTS_NO_VALUES][3] = {

    /* https://www.rfc-editor.org/rfc/rfc6814.html 
       the options commented below are deprecated 
       or not in wide use. however, I will leave them
       here for the sake of completeness and overview. 

       Options I could not find information on are
       marked by "no information available"
     */

    { IPOPT_EOOL, 1, 0 },
    { IPOPT_NOP, 1, 0},
    { IPOPT_SEC, IPOLEN_SEC_MIN, IPOLEN_MAX},
    { IPOPT_LSR, IPOLEN_LSR_MIN, IPOLEN_MAX},
    { IPOPT_TS, IPOLEN_TS_MIN, IPOLEN_MAX},
    { IPOPT_ESEC, IPOLEN_ESEC_MIN, IPOLEN_MAX},
    { IPOPT_CIPSO, IPOLEN_CIPSO_MIN, IPOLEN_MAX},
    { IPOPT_RR, IPOLEN_RR_MIN, IPOLEN_MAX},
    // { IPOPT_SID, IPOLEN_SID, 0},
    { IPOPT_SSR, IPOLEN_SSR_MIN, IPOLEN_MAX},

    /* no information available */
    // { IPOPT_ZSU, 1, 0},

    { IPOPT_MTUP, IPOLEN_MTU, 0},
    { IPOPT_MTUR, IPOLEN_MTU, 0},
    
    /* no information available */
    // { IPOPT_FINN, 1, 0 },

    // { IPOPT_VISA, 1, 0 },
    // { IPOPT_ENCODE, 1, 0 }, 

    /* no information available */
    // { IPOPT_IMITD, 1, 0 },

    // { IPOPT_EIP, 1, 0 },
    // { IPOPT_TR, IPOLEN_TR, 0 },
    // { IPOPT_ADDEXT, 1, 0 },
    { IPOPT_RTRALT, IPOLEN_RA, 0 },
    // { IPOPT_SDB, IPOLEN_SDB_MIN, IPOLEN_MAX },

    /* no information available */
    // { IPOPT_UN, 1, 0 },

    // { IPOPT_DPS, 1, 0 },
    // { IPOPT_UMP, 1, 0 },
    { IPOPT_QS, IPOLEN_QS, 0 },

    /* for experiments, left out 
       https://www.iana.org/go/rfc4727 
     */
    // { IPOPT_EXP, 1, 0 }
};

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief calculate the number of padding bytes
 * @param[inout] p_options holds the generated options
 * @param[in] pad_value the value to pad with
 * @return no. of padding bytes
 */
static uint8_t
calc_options_padding(uint8_t *p_options, uint8_t pad_value);

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

/**
 * @brief generates ip options with valid length ranges and valid type
 * @param[inout] p_ip_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static int
ip_cycle_valid(uint8_t *p_ip_options, uint8_t *p_total_length);

/**
 * @brief generates ip options with invalid lengths and a random kind
 * @param[inout] p_ip_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static int
ip_cycle_invalid(uint8_t *p_ip_options, uint8_t *p_total_length);


/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

static uint8_t
calc_options_padding(uint8_t *p_options, uint8_t pad_value)
{
    uint8_t padding = 0;

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
    if(*(p_options+1) % 4 != 0)
    {
        padding = 4 - *(p_options+1) % 4;

        if(padding > 0) {
            memset(p_options+(*(p_options+1)), pad_value, padding);
        } /* if there is padding to be done */
    } /* options not multiple of word-length */

    return padding;
}

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
    uint8_t padding = 0;

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

        padding = calc_options_padding(p_tcp_options, TCP_PAD_VALUE);
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
    uint8_t padding = 0;
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

        padding = calc_options_padding(p_tcp_options, TCP_PAD_VALUE);
        *p_total_length = *(p_tcp_options+1) + padding;

        /* set length field to zero at random 
           a zero length field is the reason for
           multiple vulnerabilities as documented
           in CVEs concerning TCP/IP stack bugs. */
        rand = (uint8_t)util_prng_gen() % 1000;
        {
            printf("[SET ZERO]\n");
            *(p_tcp_options+1) = 0x00;
        }

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
    uint8_t padding = 0;
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
                memset(p_tcp_options+rand_min, TCP_PAD_VALUE, padding);
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
        //&tcp_cycle_valid,
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

static int
ip_cycle_valid(uint8_t *p_ip_options, uint8_t *p_total_length)
{
    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;
    uint8_t padding = 0;

    /* all cycles are complete */
    if(g_cycle == IP_OPTS_NO_VALUES)
    {
        g_cycle = 0;
    }
    else
    {
        /* if there are still cycles to fuzz */
        ret = GENERATOR_CYCLE_NOT_DONE;

        /* first byte is the kind */
        *(p_ip_options+0) = g_IP_OPTIONS[g_cycle][IP_OPTION_TYPE];

        /* then comes the length, if it is variable, choose a random value 
           here, the length is the min value, where the MAX_VARLEN is the 
           max value */
        if(g_IP_OPTIONS[g_cycle][TCP_OPTIONS_MAX_VARLEN] != 0) 
        {
            uint8_t rand = (uint8_t)util_prng_gen();
            uint8_t max = g_IP_OPTIONS[g_cycle][IP_OPTION_MAX_VARLEN];
            uint8_t min = g_IP_OPTIONS[g_cycle][IP_OPTION_LENGTH];
            
            *(p_ip_options+1) = (rand % (max-min+1)) + min;
        }
        else
        {
            *(p_ip_options+1) = g_IP_OPTIONS[g_cycle][IP_OPTION_LENGTH];
        }

        /* depending on the length value, fill the rest of the bytes */
        for(i = 0; i < *(p_ip_options+1); i++)
        {
            *(p_ip_options+2+i) = (uint8_t)(util_prng_gen() & 0xff);   
        }

        padding = calc_options_padding(p_ip_options, IP_PAD_VALUE);        
        *p_total_length = *(p_ip_options+1) + padding;
        
        /* in the case we have a length of one, 
           the length field is overwritten by zero, so we have to increment
           the total length by one here. this happens when a NOP or EOL 
           is encountered */
        if(g_IP_OPTIONS[g_cycle][IP_OPTION_LENGTH] == 1) 
        {
            (*p_total_length)++;
        }

        g_cycle++;
    }

    return ret;
}

static int
ip_cycle_invalid(uint8_t *p_ip_options, uint8_t *p_total_length)
{
    int i = 0;
    uint8_t ret = GENERATOR_CYCLE_DONE;
    uint8_t padding = 0;
    uint8_t rand = 0;

    /* all cycles are complete */
    if(g_cycle == IP_NO_INVALID)
    {
        g_cycle = 0;
    }
    else
    {
        /* if there are still cycles to fuzz */
        ret = GENERATOR_CYCLE_NOT_DONE;

        rand = (uint8_t)util_prng_gen() % IP_OPTS_NO_VALUES;

        /* first byte is the type, choose at random */
        *(p_ip_options+0) = g_IP_OPTIONS[rand][IP_OPTION_TYPE];

        /* choose a random length, minimum is 4 */
        rand = (uint8_t)util_prng_gen() % 37 + 4;
        *(p_ip_options+1) = rand;

        /* depending on the length value, fill the rest of the bytes */
        for(i = 0; i < *(p_ip_options+1); i++)
        {
            *(p_ip_options+2+i) = (uint8_t)(util_prng_gen() & 0xff);   
        }

        padding = calc_options_padding(p_ip_options, IP_PAD_VALUE);
        *p_total_length = *(p_ip_options+1) + padding;

        g_cycle++;
    }

    return ret;
}

static int
generator_ip_options(uint8_t *p_ip_options, uint8_t *p_total_length)
{
    int ret = GENERATOR_CYCLE_NOT_DONE;
    int cycle_done = GENERATOR_CYCLE_NOT_DONE;

    gen_function_t ip_mutations[IP_NO_MUTATIONS] = {
        &ip_cycle_valid,
        &ip_cycle_invalid
    };

    gen_function_t mut = ip_mutations[g_current_mutation];
        
    cycle_done = mut(p_ip_options, p_total_length);
    if(cycle_done == -1)
    {
        ret = GENERATOR_FAILURE;
    }

    if(cycle_done == GENERATOR_CYCLE_DONE) {
        g_current_mutation++;
        if(g_current_mutation == IP_NO_MUTATIONS)
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
            g_generate = &generator_ip_options;
            ret = GENERATOR_SUCCESS;
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
