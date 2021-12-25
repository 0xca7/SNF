/** @file util.c
 * 
 * @brief utility functions
 *
 */


/**
 * Author:  0xca7
 * Desc:    various utility functions
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

#include "util.h"

/***************************************************************************
 * MACROS
 **************************************************************************/
#define UTIL_SUCCESS  0
#define UTIL_FAILURE  -1

#define IP_ANY        "0.0.0.0\0"

/***************************************************************************
 * TYPES / DATA STRUCTURES
 **************************************************************************/

/**
 * @brief a XorShift64 RNG 
 */
typedef struct {
    uint64_t state; /** the current xorshift state */
} xorshift64_t; /* @xorshift */

/***************************************************************************
 * GLOBALS
 **************************************************************************/
/** @brief module global xorshift64 prng instance */
static xorshift64_t g_xorshift = {0}; 

/***************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief seed the XorShift64 PRNG
 * @warning caller must ensure p_xor != NULL
 * @param[in] p_xor pointer to a xorshift64_t see @xorshift
 * @param[in] seed the seed value to set, must not be zero!
 * @return -1 on failure, 0 on success
 */
static int
xorshift64_seed(xorshift64_t *p_xor, uint64_t seed);

/**
 * @brief generate value from the XorShift64 PRNG
 * @warning caller must ensure p_xor != NULL
 * @param[in] p_xor pointer to a xorshift64_t see @xorshift
 * @return a random 64 bit value 
 */
static uint64_t
xorshift64_generate(xorshift64_t *p_xor);

/***************************************************************************
 * PRIVATE FUNCTIONS
 **************************************************************************/

/**
 * Pseudo Random Numbers
 */
static int
xorshift64_seed(xorshift64_t *p_xor, uint64_t seed) 
{
    int ret = UTIL_FAILURE;

    if(seed != 0)
    {
        p_xor->state = seed;
        ret = UTIL_SUCCESS;
    }

    return ret;
}

static uint64_t
xorshift64_generate(xorshift64_t *p_xor) 
{
	p_xor->state ^= p_xor->state << 13;
	p_xor->state ^= p_xor->state >> 7;
	p_xor->state ^= p_xor->state << 17;
	return p_xor->state;
}
/**************************************************************************/

/**
 * Network Interface 
 */


/**************************************************************************/

/***************************************************************************
 * PUBLIC FUNCTIONS
 **************************************************************************/

extern int 
util_prng_init(void) 
{
    int ret = UTIL_FAILURE;
    time_t res = 0;
    
    /* NOTE: function is so short that goto doesn't make
             sense here, so two returns are used */

    res = time(NULL);
    if(res == -1)
    {
        printf("[UTIL] (time) %s\n", strerror(errno));
        return ret;
    }
    return xorshift64_seed(&g_xorshift, (uint64_t)res);
}

extern uint64_t 
util_prng_gen(void)
{
    return xorshift64_generate(&g_xorshift);
}

extern int 
util_get_nic_ip(char *ifname, char *ip)
{
    assert(ifname != NULL);
    assert(ip != NULL);

    int ret = UTIL_FAILURE;
    int fd = -1;
    struct ifreq ifr = {0}; 

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1)
    {
        printf("[UTIL] (socket) %s\n", strerror(errno));
        goto GET_NIC_IP_FAILURE;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);

    /* if the given interface name `ifname` does not exist,
       this will fail with "interface does not exist" */
    ret = ioctl(fd, SIOCGIFADDR, &ifr);
    if(ret == -1)
    {
        printf("[UTIL] (ioctl) %s\n", strerror(errno));
        goto GET_NIC_IP_FAILURE;
    }

    /* and more importantly */
    strncpy(ip, 
        inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 15);

    ret = close(fd);
    if(ret == -1)
    {
        printf("[UTIL] (close) %s\n", strerror(errno));
        goto GET_NIC_IP_FAILURE;
    }

    ret = UTIL_SUCCESS;

GET_NIC_IP_FAILURE:
    return ret;
}

/*** end of file ***/

