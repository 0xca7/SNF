/** @file module.c
 * 
 * @brief A description of the module’s purpose. 
 *
 */
#include <unity.h>
#include <fuzzer.h>
#include "../../modules/fuzzer/fuzzer.c"


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
void 
test_fuzzer_check_mode(void)
{
    int i = 0;
    
    for(i = 0; i < FUZZ_MODE_INVALID; i++)
    {
        TEST_ASSERT_EQUAL_INT(0,
            fuzzer_check_mode(i));
    }
    
    TEST_ASSERT_EQUAL_INT(-1,
        fuzzer_check_mode(FUZZ_MODE_INVALID));

}


/**********************************************************
 * Test Cases - Public Functions
 *********************************************************/

/**
 * @brief tests the fuzzer_new function
 */
void
test_fuzzer_new(void)
{
    fuzz_config_t *cfg = NULL;
    cfg = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "192.168.1.1",
        7777
    );
    TEST_ASSERT_NOT_NULL(cfg);

    /* test a faulty mode */
    fuzz_config_t *fault = NULL;
    fault = fuzzer_new(
        FUZZ_MODE_INVALID,
        "192.168.1.1",
        7777
    );
    TEST_ASSERT_NULL(fault);
    
    /* test a faulty ip */
    fault = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "abcd",
        7777
    );
    TEST_ASSERT_NULL(fault);
 
    fault = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "10.0.0.1",
        0
    );
    TEST_ASSERT_NULL(fault);
       
}

/**
 * @brief test fuzzer initialization
 * @return void
 */
void 
test_fuzzer_init(void) 
{
    fuzz_config_t cfg = {0};
    TEST_ASSERT_EQUAL_INT(0, fuzzer_init(&cfg));
}

/**
 * @brief test fuzzer de-initialization
 * @return void
 */
void 
test_fuzzer_deinit(void) 
{
    fuzz_config_t *cfg = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "127.0.0.1",
        7777
    );
    TEST_ASSERT_NOT_NULL(cfg);

    TEST_ASSERT_EQUAL_INT(0, fuzzer_deinit(cfg));

}





/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_fuzzer_new);
    RUN_TEST(test_fuzzer_init);
    RUN_TEST(test_fuzzer_deinit);

    RUN_TEST(test_fuzzer_check_mode);

    return UNITY_END();
}



