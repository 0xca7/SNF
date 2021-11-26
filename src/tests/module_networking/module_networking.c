/** @file module.c
 * 
 * @brief A description of the module’s purpose. 
 *
 */
#include <unity.h>
#include <networking.h>
#include "../../modules/networking/networking.c"


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


/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_networking_init_deinit);

    return UNITY_END();
}



