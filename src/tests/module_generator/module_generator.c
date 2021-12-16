/** @file module_generator.c
 * 
 * @brief tests for the generator module
 *
 */
#include <unity.h>
#include <generator.h>
#include "../../modules/generator/generator.c"


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

/**
 * @brief test the cycle function
 */
void
test_generator_cycle_tcp_options()
{
    int iter = 0;
    uint8_t buffer[256] = { 0x00 };
    
    while(iter != TCP_OPTS_NO_VALUES)
    {
        TEST_ASSERT_EQUAL_INT(GENERATOR_CYCLE_NOT_DONE,
            generator_cycle_tcp_options(&buffer[0]));
        iter++;
    }
    TEST_ASSERT_EQUAL_INT(GENERATOR_CYCLE_DONE,
        generator_cycle_tcp_options(&buffer[0]));
}



/**********************************************************
 * Test Cases - Public Functions
 *********************************************************/

/**
 * @brief test the init function
 */
void
test_generator_init()
{
    generator_init(FUZZ_MODE_IP_OPTIONS);
    TEST_ASSERT_EQUAL_INT(FUZZ_MODE_IP_OPTIONS,
        g_mode);
}

/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_generator_init);
    RUN_TEST(test_generator_cycle_tcp_options);

    return UNITY_END();
}



