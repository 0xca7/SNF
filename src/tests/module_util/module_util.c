/** @file module_util.c
 * 
 * @brief tests for the `util` module
 *
 */
#include <unity.h>
#include <util.h>
#include "../../modules/util/util.c"


/**
 * Author:  0xca7
 * Desc:    this is a template header
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
 * @brief test the function to get an IP from a NIC
 */
void
test_get_nic_ip(void)
{
    char ip_addr[15] = { 0x00 }; 

    TEST_ASSERT_EQUAL_INT(0,
        util_get_nic_ip("lo", &ip_addr[0]));
    TEST_ASSERT_EQUAL_STRING("127.0.0.1", ip_addr);

    TEST_ASSERT_EQUAL_INT(-1,
        util_get_nic_ip("doesnotexist", &ip_addr[0]));
}

/** 
 * @brief test the PRNG
 */
void
test_prng()
{
    /* a non-seeded RNG always returns zero */
    TEST_ASSERT_EQUAL_UINT64(0, util_prng_gen());

    /* set to a known value and test results */
    g_xorshift.state = 0xdeadbeef;
    TEST_ASSERT_EQUAL_UINT64(0x37c59ca7bf06be52, 
        util_prng_gen());
    TEST_ASSERT_EQUAL_UINT64(0x167a05ab294167ae, 
        util_prng_gen());
    TEST_ASSERT_EQUAL_UINT64(0xaae6f93d9e7dcee1, 
        util_prng_gen());

    /* seeding the rng must not fail */
    TEST_ASSERT_EQUAL_INT(0,
        util_prng_init());
}

/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_get_nic_ip);
    RUN_TEST(test_prng);

    return UNITY_END();
}



