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

/** @brief readable return value on success */
#define GENERATOR_SUCCESS                   0
/** @brief readable return value on failure */
#define GENERATOR_FAILURE                   -1

/** @brief indicates that a cycle of generating option values is not done */
#define GENERATOR_CYCLE_NOT_DONE            1
/** @brief indicates that a cycle of generating option values is done */
#define GENERATOR_CYCLE_DONE                0

/** mutation options for the length field */

/** @brief a valid length is chosen */
#define MUT_LENGTH_VALID                    0

/** @brief length set to zero */
#define MUT_LENGTH_ZERO                     1

/** @brief a invalid length is chosen */
#define MUT_LENGTH_INVALID                  2

/** @brief indicates that there is no variable length for an option */
#define NO_VARLEN                           0

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
#define TCP_INVALID_COUNT                   10000

/** @brief value to pad TCP options with */
#define TCP_PAD_VALUE                       0x01

/***************************************************************************
 * TCP specific 
 */
#define TCP_EOL                             0
#define TCP_NOP                             1
#define TCP_MSS                             2
#define TCP_WIN_SCALE                       3
#define TCP_SACK_PERM                       4
#define TCP_SACK                            5
#define TCP_TIMESTAMP                       8
#define TCP_TRAILER_CHKSUM                  18
#define TCP_QUICK_START_RESPONSE            27
#define TCP_USER_TIMEOUT                    28
#define TCP_AUTH                            29
#define TCP_MULTIPATH                       30
#define TCP_FAST_OPEN_COOKIE                34
#define TCP_ENCRYPTION_NEGOTIATION          69

#define TCP_LEN_MSS                         4 
#define TCP_LEN_WIN_SCALE                   3
#define TCP_LEN_SACK_PERM                   2
#define TCP_LEN_SACK_MIN                    10
#define TCP_LEN_SACK_MAX                    40
#define TCP_LEN_TIMESTAMP                   10
#define TCP_LEN_TRAILER_CHKSUM              3
#define TCP_LEN_QUICKSTART_RESPONSE         8
#define TCP_LEN_USER_TIMEOUT                4
#define TCP_LEN_AUTH                        4
#define TCP_LEN_MULTIPATH                   4
#define TCP_LEN_FAST_OPEN_COOKIE_MIN        4
#define TCP_LEN_FAST_OPEN_COOKIE_MAX        16
#define TCP_LEN_ENCRYPTION_NEGOTIATION_MIN  1
#define TCP_LEN_ENCRYPTION_NEGOTIATION_MAX  40

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
#define IP_INVALID_COUNT                    10000U

/** @brief value to pad TCP options with */
#define IP_PAD_VALUE                        0x00

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

/**************************************************************************/


/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/
/** @brief used to set a generator function for the different fuzzing modes 
    */
typedef int (*gen_function_t)(uint8_t *, uint8_t *);

typedef enum 
{
    TCP_STATE_VALID,
    TCP_STATE_VALID_KIND_VALID_LENGTH,
    TCP_STATE_INVALID_KIND_VALID_LENGTH,
    TCP_STATE_VALID_KIND_INVALID_LENGTH,
    TCP_STATE_INVALID_KIND_INVALID_LENGTH,
    TCP_STATE_VALID_KIND_ZERO_LENGTH,
    TCP_STATE_INVALID_KIND_ZERO_LENGTH,
    /* nice, readable placeholder */
    TCP_STATE_DONE
}
e_TCP_FUZZ_STATE_t;


typedef enum 
{
    IP_STATE_VALID,
    IP_STATE_INVALID,
    IP_STATE_INVALID_INVALID_LENGTH,
    IP_STATE_INVALID_ZERO_LENGTH,
    IP_STATE_INVALID_RANDOM_TYPE,
    IP_STATE_INVALID_RANDOM_TYPE_ZERO_LENGTH,
    IP_STATE_INVALID_RANDOM_TYPE_INVALID_LENGTH,
    /* nice, readable placeholder */
    IP_STATE_DONE
}
e_IP_FUZZ_STATE_t;

/***************************************************************************
 * GLOBALS
 **************************************************************************/

/** @brief the function to use for generation of options */
static gen_function_t g_generate = NULL;

/** @brief the current cycle we are in */
static uint64_t g_cycle = 0;

/** @brief the current state of the TCP fuzzer */
static e_TCP_FUZZ_STATE_t g_tcp_state = TCP_STATE_VALID;

/** @brief the current state of the IP fuzzer */
static e_IP_FUZZ_STATE_t g_ip_state = IP_STATE_VALID;

/** @brief current fuzzing mode to use */
static e_fuzz_mode_t g_mode = FUZZ_MODE_INVALID;

/* kind, length, max length if variable */
const uint8_t g_TCP_OPTIONS[TCP_OPTS_NO_VALUES][3] = {
    /* END_OF_OPTION_LIST */
    { TCP_EOL, 1, NO_VARLEN },
    /* NOP */
    { TCP_NOP, 1, NO_VARLEN },
    /* MSS */
    { TCP_MSS, TCP_LEN_MSS, NO_VARLEN },
    /* WINDOW_SCALE */
    { TCP_WIN_SCALE, TCP_LEN_WIN_SCALE, NO_VARLEN },
    /* SACK_PERMITTED */
    { TCP_SACK_PERM, TCP_LEN_SACK_PERM, NO_VARLEN },
    /* SACK */
    { TCP_SACK, TCP_LEN_SACK_MIN, TCP_LEN_SACK_MAX },
    /* TIMESTAMPS */
    { TCP_TIMESTAMP, TCP_LEN_TIMESTAMP, NO_VARLEN },
    /* TRAILER_CHKSM */
    { TCP_TRAILER_CHKSUM, TCP_LEN_TRAILER_CHKSUM, NO_VARLEN },
    /* QUICK_START_RESPONSE */
    { TCP_QUICK_START_RESPONSE, TCP_LEN_QUICKSTART_RESPONSE, NO_VARLEN },
    /* USER_TIMEOUT */
    { TCP_USER_TIMEOUT, TCP_LEN_USER_TIMEOUT, NO_VARLEN },
    /* TCP_AUTH */
    { TCP_AUTH, TCP_LEN_AUTH, NO_VARLEN },
    /* TCP_MULTIPATH */
    { TCP_MULTIPATH, TCP_LEN_MULTIPATH, NO_VARLEN },
    /* TCP_FAST_OPEN_COOKIE */
    { TCP_FAST_OPEN_COOKIE, TCP_LEN_FAST_OPEN_COOKIE_MIN, 
        TCP_LEN_FAST_OPEN_COOKIE_MAX },
    /* TCP_ENCRYPTION_NEGOTIATION */
    { TCP_ENCRYPTION_NEGOTIATION, 
      TCP_LEN_ENCRYPTION_NEGOTIATION_MIN, 
      TCP_LEN_ENCRYPTION_NEGOTIATION_MAX }
};

const uint8_t g_IP_OPTIONS[IP_OPTS_NO_VALUES][3] = {

    /* https://www.rfc-editor.org/rfc/rfc6814.html 
       the options commented below are deprecated 
       or not in wide use. however, I will leave them
       here for the sake of completeness and overview. 

       Options I could not find information on are
       marked by "no information available"
     */

    // { IPOPT_SID, IPOLEN_SID, 0},
    // { IPOPT_VISA, 1, 0 },
    // { IPOPT_ENCODE, 1, 0 }, 
    // { IPOPT_EIP, 1, 0 },
    // { IPOPT_TR, IPOLEN_TR, 0 },
    // { IPOPT_ADDEXT, 1, 0 },
    // { IPOPT_SDB, IPOLEN_SDB_MIN, IPOLEN_MAX },
    // { IPOPT_DPS, 1, 0 },
    // { IPOPT_UMP, 1, 0 },

    /* for experiments, left out 
       https://www.iana.org/go/rfc4727 
     */
    // { IPOPT_EXP, 1, 0 }

    /* no information available */
    // { IPOPT_ZSU, 1, 0},
    // { IPOPT_FINN, 1, 0 },
    // { IPOPT_IMITD, 1, 0 },
    // { IPOPT_UN, 1, 0 },

    { IPOPT_EOOL, 1, NO_VARLEN },
    { IPOPT_NOP, 1,  NO_VARLEN },
    { IPOPT_SEC, IPOLEN_SEC_MIN, IPOLEN_MAX },
    { IPOPT_LSR, IPOLEN_LSR_MIN, IPOLEN_MAX },
    { IPOPT_TS, IPOLEN_TS_MIN, IPOLEN_MAX },
    { IPOPT_ESEC, IPOLEN_ESEC_MIN, IPOLEN_MAX },
    { IPOPT_CIPSO, IPOLEN_CIPSO_MIN, IPOLEN_MAX },
    { IPOPT_RR, IPOLEN_RR_MIN, IPOLEN_MAX },
    { IPOPT_SSR, IPOLEN_SSR_MIN, IPOLEN_MAX },
    { IPOPT_MTUP, IPOLEN_MTU, NO_VARLEN },
    { IPOPT_MTUR, IPOLEN_MTU, NO_VARLEN },
    { IPOPT_RTRALT, IPOLEN_RA, NO_VARLEN },
    { IPOPT_QS, IPOLEN_QS, NO_VARLEN },
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
 * @brief print the current mutation state TCP
 * @param void
 * @return void
 */
static void
print_tcp_state(void);

/**
 * @brief print the current mutation state of IP
 * @param void
 * @return void
 */
static void
print_ip_state(void);

/** TCP **/

/**
 * @brief generates valid kind and length options
 * @param[inout] p_tcp_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return void
 */
static void
tcp_cycle_valid(uint8_t *p_tcp_options, uint8_t *p_total_length);


/**
 * @brief generates a tcp options field
 * @note
        this function realizes six possible mutations depending on
        the tuple (randomize_kind, length_option)

        1 - (false, MUT_LENGTH_VALID) a kind is chosen at random, but is valid
            length is random and equal to the payload data bytes
        2 - (true, MUT_LENGTH_VALID) a kind is chosen at random, can be invalid
            length is random and equal to the payload data bytes
        3 - (false, MUT_LENGTH_ZERO) a kind is chosen at random, but is valid
            length is zero with a random number of data bytes
        4 - (true, MUT_LENGTH_ZERO) a kind is chosen at random, can be invalid
            length is zero with a random number of data bytes
        5 - (true, MUT_LENGTH_INVALID) a kind is chosen at random, but is valid
            length != random number of data bytes
        6 - (false, MUT_LENGTH_INVALID) a kind is chosen at random, can be invalid
            length != random number of data bytes
        
 * @param[in] randomize_kind allows for completely random kinds if true
              if false, kinds are chosen at random from valid kinds
 * @param[in] length_option choose what to mutate in the length field 
 * @param[inout] p_tcp_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return void
 */
static void
tcp_cycle_randomize(bool randomize_kind, uint8_t length_option,
    uint8_t *p_tcp_options, uint8_t *p_total_length);

/**
 * @brief generates the next option fields for a fuzz packet
 * @param[inout] p_tcp_options the buffer to hold options
 * @param[inout] p_total_length options + padding length
 * @return combinations are left: 1, done: 0, error: -1
 */
static int
generator_tcp_options(uint8_t *p_tcp_options, uint8_t *p_total_length);

/** IP **/

/**
 * @brief generates ip options with valid length ranges and valid type
 * @param[inout] p_ip_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return void
 */
static void
ip_cycle_valid(uint8_t *p_ip_options, uint8_t *p_total_length);

/**
 * @brief generates ip options with invalid lengths and a random kind
 * @note see tcp_cycle_randomize for more details
 * @param[in] random_type set a completely random, possibly invalid type
 * @param[in] length_option length is valid, zero or random
 * @param[inout] p_ip_options holds the generated options
 * @param[inout] p_total_length the total length of the options inc. padding
 * @return 1 if combinations are left, 0 if none are left, -1 on error
 */
static void
ip_cycle_randomize(bool random_type, uint8_t length_option,
    uint8_t *p_ip_options, uint8_t *p_total_length);

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

static void
print_tcp_state(void)
{
    switch(g_tcp_state)
    {
        case TCP_STATE_VALID:
            printf("[1] valid packets\n");
        break;
        case TCP_STATE_VALID_KIND_VALID_LENGTH:
            printf("[2] valid kind, valid length\n");
        break;
        case TCP_STATE_INVALID_KIND_VALID_LENGTH:
            printf("[3] invalid kind, valid length\n");
        break;
        case TCP_STATE_VALID_KIND_INVALID_LENGTH:
            printf("[4] valid kind, invalid length\n");
        break;
        case TCP_STATE_INVALID_KIND_INVALID_LENGTH:
            printf("[5] invalid kind, invalid length\n");
        break;
        case TCP_STATE_VALID_KIND_ZERO_LENGTH:
            printf("[6] valid kind, zero length\n");
        break;
        case TCP_STATE_INVALID_KIND_ZERO_LENGTH:
            printf("[7] invalid kind, zero length\n");
        break;
        case TCP_STATE_DONE:
            printf("[!] fuzzing done.\n");
        break;
        default:
            printf("[GENERATOR] Fatal: Unknown State\n");
            /* if this happens, just exit. */
            exit(1);
        break;
    }
 
}

static void
print_ip_state(void)
{
    switch(g_ip_state)
    {
        case IP_STATE_VALID:
            printf("[1] valid IP options]\n");
        break;
        case IP_STATE_INVALID:
            printf("[2] invalid IP options - valid type, valid length\n");
        break;
        case IP_STATE_INVALID_INVALID_LENGTH:
            printf("[3] invalid IP options - valid type, invalid length\n");
        break;
        case IP_STATE_INVALID_ZERO_LENGTH:
            printf("[4] invalid IP options - valid type, zero length\n");
        break;
        case IP_STATE_INVALID_RANDOM_TYPE:
            printf("[5] invalid IP options - invalid type\n");
        break;
        case IP_STATE_INVALID_RANDOM_TYPE_ZERO_LENGTH:
            printf("[6] invalid IP options - invalid type, zero length\n");
        break;
        case IP_STATE_INVALID_RANDOM_TYPE_INVALID_LENGTH:
            printf("[7] invalid IP options - invalid type, invalid length\n");
        break;
        case IP_STATE_DONE:
            printf("[!] fuzzing done. ]\n");
        break;
        default:
            printf("[GENERATOR] Fatal: Unknown State\n");
            /* if this happens, just exit. */
            exit(1);
        break;
    }
 
}

static void
tcp_cycle_valid(uint8_t *p_tcp_options, uint8_t *p_total_length) 
{
    int i = 0;
    uint8_t padding = 0;

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
            case TCP_SACK:
                /* there must be one block, max 4 blocks */
                rand = rand % 4 + 1;
                *(p_tcp_options+1) = TCP_LEN_SACK_MIN * rand;
            break;
            case TCP_FAST_OPEN_COOKIE:
                /* this is ok, between 4 and 16 bytes */
                *(p_tcp_options+1) = (rand % (max-min+1)) + min;
            break;
            case TCP_ENCRYPTION_NEGOTIATION:
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
}

static void
tcp_cycle_randomize(bool randomize_kind, uint8_t length_option,
    uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    int i = 0;
    uint8_t padding = 0;
    uint8_t rand = 0;

    /* choose between a fully random kind or a random, valid kind */
    if(randomize_kind)
    {
        /* get a fully random value for kind */
        rand = (uint8_t)util_prng_gen() % 0xff;
        *(p_tcp_options+0) = rand;
    }
    else
    {
        /* get a random, but valid kind */
        rand = (uint8_t)util_prng_gen() % TCP_OPTS_NO_VALUES;
        *(p_tcp_options+0) = g_TCP_OPTIONS[rand][TCP_OPTIONS_KIND];
    }

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
    if(length_option == MUT_LENGTH_ZERO)
    {
        *(p_tcp_options+1) = 0x00;
    }

    /* set a random value for the length */
    if(length_option == MUT_LENGTH_INVALID)
    {
        *(p_tcp_options+1) = (uint8_t)util_prng_gen() % 40 + 1;
    }

}

static int
generator_tcp_options(uint8_t *p_tcp_options, uint8_t *p_total_length)
{
    int ret = GENERATOR_CYCLE_NOT_DONE;

    if(!g_cycle)
    {
        print_tcp_state();
    }

    switch(g_tcp_state)
    {
        case TCP_STATE_VALID:
            tcp_cycle_valid(p_tcp_options, p_total_length);
        break;
        case TCP_STATE_VALID_KIND_VALID_LENGTH:
            tcp_cycle_randomize(false, MUT_LENGTH_VALID,
                p_tcp_options, p_total_length);
        break;
        case TCP_STATE_INVALID_KIND_VALID_LENGTH:
            tcp_cycle_randomize(true, MUT_LENGTH_VALID,
                p_tcp_options, p_total_length);
        break;
        case TCP_STATE_VALID_KIND_INVALID_LENGTH:
            tcp_cycle_randomize(false, MUT_LENGTH_INVALID,
                p_tcp_options, p_total_length);
        break;
        case TCP_STATE_INVALID_KIND_INVALID_LENGTH:
            tcp_cycle_randomize(true, MUT_LENGTH_INVALID,
                p_tcp_options, p_total_length);
        break;
        case TCP_STATE_VALID_KIND_ZERO_LENGTH:
            tcp_cycle_randomize(false, MUT_LENGTH_ZERO,
                p_tcp_options, p_total_length);
        break;
        case TCP_STATE_INVALID_KIND_ZERO_LENGTH:
            tcp_cycle_randomize(true, MUT_LENGTH_ZERO,
                p_tcp_options, p_total_length);
        break;
        case TCP_STATE_DONE:
            ret = GENERATOR_CYCLE_DONE;
        break;
        default:
            printf("[GENERATOR] Fatal: Unknown State\n");
            /* if this happens, just exit. */
            exit(1);
        break;
    }
    
    g_cycle++;

    if(g_tcp_state == TCP_STATE_VALID)
    {
        if(g_cycle == TCP_OPTS_NO_VALUES)
        {
            g_tcp_state++;
            g_cycle = 0;
        }
    }
    else
    {
        /* if we are done sending x invalid packets */
        if(g_cycle == TCP_INVALID_COUNT)
        {
            g_tcp_state++;
            g_cycle = 0;
        }
    }

    return ret;
}

static void
ip_cycle_valid(uint8_t *p_ip_options, uint8_t *p_total_length)
{
    int i = 0;
    uint8_t padding = 0;

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

}

static void
ip_cycle_randomize(bool random_type, uint8_t length_option,
    uint8_t *p_ip_options, uint8_t *p_total_length)
{
    int i = 0;
    uint8_t padding = 0;
    uint8_t rand = 0;

    /* first byte is the type, choose at random from
       valid types or choose a completely random byte */
    if(random_type)
    {
        rand = (uint8_t)util_prng_gen() % 0xff;
        *(p_ip_options+0) = rand;
    }
    else
    {
        rand = (uint8_t)util_prng_gen() % IP_OPTS_NO_VALUES;
        *(p_ip_options+0) = g_IP_OPTIONS[rand][IP_OPTION_TYPE];
    }

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

    /* zero length has uncovered vulns in a couple of products */
    if(length_option == MUT_LENGTH_ZERO)
    {
        *(p_ip_options+1) = 0;
    }

    if(length_option == MUT_LENGTH_INVALID)
    {
        *(p_ip_options+1) = (uint8_t)util_prng_gen() % 40 + 1;
    }

}

static int
generator_ip_options(uint8_t *p_ip_options, uint8_t *p_total_length)
{
    int ret = GENERATOR_CYCLE_NOT_DONE;

    if(!g_cycle)
    {
        print_ip_state();
    }

    switch(g_ip_state)
    {
        case IP_STATE_VALID:
            ip_cycle_valid(p_ip_options, p_total_length);
        break;
        case IP_STATE_INVALID:
            ip_cycle_randomize(false, MUT_LENGTH_VALID,
                p_ip_options, p_total_length);
        break;
        case IP_STATE_INVALID_INVALID_LENGTH:
            ip_cycle_randomize(false, MUT_LENGTH_INVALID,
                p_ip_options, p_total_length);
        break;
        case IP_STATE_INVALID_ZERO_LENGTH:
            ip_cycle_randomize(false, MUT_LENGTH_ZERO,
                p_ip_options, p_total_length);
        break;
        case IP_STATE_INVALID_RANDOM_TYPE:
            ip_cycle_randomize(true, MUT_LENGTH_VALID,
                p_ip_options, p_total_length);
        break;
        case IP_STATE_INVALID_RANDOM_TYPE_ZERO_LENGTH:
            ip_cycle_randomize(true, MUT_LENGTH_ZERO,
                p_ip_options, p_total_length);
        break;
        case IP_STATE_INVALID_RANDOM_TYPE_INVALID_LENGTH:
            ip_cycle_randomize(true, MUT_LENGTH_INVALID,
                p_ip_options, p_total_length);
        break;
        case IP_STATE_DONE:
            ret = GENERATOR_CYCLE_DONE;
        break;
        default:
            printf("[GENERATOR] Fatal: Unknown State\n");
            /* if this happens, just exit. */
            exit(1);
        break;
    }

    g_cycle++;

    if(g_ip_state == IP_STATE_VALID)
    {
        if(g_cycle == IP_OPTS_NO_VALUES)
        {
            g_ip_state++;
            g_cycle = 0;
        }
    }
    else
    {
        /* if we are done sending x invalid packets */
        if(g_cycle == IP_INVALID_COUNT)
        {
            g_ip_state++;
            g_cycle = 0;
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

    if(CHECK_NULL(p_tcp_options))
    {
        NULL_PTR_EXCEPTION("generator_run - p_tcp_options");
    }

    if(CHECK_NULL(p_total_length))
    {
        NULL_PTR_EXCEPTION("generator_run - p_total_length");
    }

    if(g_generate == NULL)
    {
        printf("[GENERATOR] null-pointer exception\n");
        return GENERATOR_FAILURE;
    }

    return g_generate(&p_tcp_options[0], p_total_length);
}


/*** end of file ***/
