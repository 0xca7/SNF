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
    uint8_t buffer_length = 0;
    
    while(iter != TCP_OPTS_NO_VALUES)
    {
        //TEST_ASSERT_EQUAL_INT(1,
        //    generator_tcp_options(&buffer[0], &buffer_length));
        iter++;
    }
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
    TEST_ASSERT_EQUAL_INT(-1,
        generator_init(FUZZ_MODE_IP_OPTIONS));
    TEST_ASSERT_EQUAL_INT(FUZZ_MODE_IP_OPTIONS,
        g_mode);

    TEST_ASSERT_EQUAL_INT(0,
        generator_init(FUZZ_MODE_TCP_OPTIONS));
    TEST_ASSERT_EQUAL_INT(FUZZ_MODE_TCP_OPTIONS,
        g_mode);
}

/**
 * @brief test the run function
 */
void
test_generator_run()
{
    uint8_t options[4] = { 0x00 };
    uint8_t options_length = 0;

    /* not initialized is invalid */
    TEST_ASSERT_EQUAL_INT(1,
        generator_run(&options[0], &options_length));
}

/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();
    
    RUN_TEST(test_generator_init);
    RUN_TEST(test_generator_run);
    RUN_TEST(test_generator_cycle_tcp_options);

    return UNITY_END();
}



