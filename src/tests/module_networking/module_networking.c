/** @file module_networking.c
 * 
 * @brief tests for the networking module
 *
 */
#include <unity.h>
#include <networking.h>
#include <packet.h>
#include "../../modules/networking/networking.c"


/**
 * Author:  0xca7
 * Desc:    tests for the networking module, may require
 *          elevated privs
 *
 */

/**
 * Changelog:
 * [dd/mm/yyyy][author]: change
 */

/**********************************************************
 * Initialization 
 *********************************************************/

void 
setUp(void)
{
}

void 
tearDown(void)
{
}

/**********************************************************
 * Test Cases - Private Functions
 *********************************************************/


/**********************************************************
 * Test Cases - Public Functions
 *********************************************************/

/**
 * @brief tests the networking_init and deinit functions
 * - tests success cases
 */
void 
test_networking_init_deinit(void) 
{
    TEST_ASSERT_EQUAL_INT(0,
        networking_init(IPPROTO_TCP));

    TEST_ASSERT_NOT_EQUAL_INT(-1,
        g_sockfd);
    TEST_ASSERT_TRUE(g_initialized);
    
    TEST_ASSERT_EQUAL_INT(0,
        networking_deinit());

    TEST_ASSERT_EQUAL_INT(-1,
        g_sockfd);
    TEST_ASSERT_FALSE(g_initialized);
 
}

/**
 * @brief tests sending a network packet
 */
void
test_networking_send(void)
{
    uint8_t packet[256] = { 0x00 };
    uint8_t options[4] = { 0x02, 0x04, 0xde, 0xad };
    uint8_t options_length = 4;

    TEST_ASSERT_EQUAL_INT(0,
        networking_init(IPPROTO_TCP));

    /* correctness is tested in seperate unit test */
    if(util_prng_init() == -1) 
    {
        printf("[TEST WARNING] building tcp packet failed\n");
    }
    
    /* correctness is tested in seperate unit test */
    if(packet_build_tcp(&packet[0], 256, 
        &options[0], options_length,
        inet_addr("127.0.0.1"), inet_addr("127.0.0.1"), 
        5555) == -1) 
    {
        printf("[TEST WARNING] building tcp packet failed\n");
    }
    
    TEST_ASSERT_EQUAL_INT(0,
        networking_send(&packet[0], 44, inet_addr("127.0.0.1")));

    TEST_ASSERT_EQUAL_INT(0,
        networking_deinit());
}


/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_networking_init_deinit);
    RUN_TEST(test_networking_send);

    return UNITY_END();
}



