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

void
test_fuzzer_convert_ip(void) 
{
    struct in_addr ip_addr;
    char ip_str[16] = "127.0.0.1";

    char ip_invalid[16] = "555.555.555.555";

    TEST_ASSERT_EQUAL_INT(0, 
        fuzzer_convert_ip((const char*)&ip_str[0], &ip_addr));

    TEST_ASSERT_EQUAL_HEX32(0x0100007f, ip_addr.s_addr);

    TEST_ASSERT_EQUAL_INT(-1, 
        fuzzer_convert_ip((const char*)&ip_invalid[0], &ip_addr));
}

void
test_fuzzer_mode_to_ascii() 
{
    TEST_ASSERT_EQUAL_STRING(MODE_STRING_IP_OPTIONS,
        fuzzer_mode_to_ascii(FUZZ_MODE_IP_OPTIONS));

    TEST_ASSERT_EQUAL_STRING(MODE_STRING_TCP_OPTIONS,
        fuzzer_mode_to_ascii(FUZZ_MODE_TCP_OPTIONS));

    TEST_ASSERT_EQUAL_STRING(MODE_STRING_INVALID,
        fuzzer_mode_to_ascii(999));
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
    fuzz_config_t *p_cfg = NULL;
    p_cfg = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "lo",
        "192.168.1.1",
        7777
    );

    fuzzer_print_config(p_cfg);

    TEST_ASSERT_NOT_NULL(p_cfg);

    /* test a p_faulty mode */
    fuzz_config_t *p_fault = NULL;
    p_fault = fuzzer_new(
        FUZZ_MODE_INVALID,
        "lo",
        "192.168.1.1",
        7777
    );
    TEST_ASSERT_NULL(p_fault);
    
    /* test a p_faulty ip */
    p_fault = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "lo",
        "abcd",
        7777
    );
    TEST_ASSERT_NULL(p_fault);
 
    p_fault = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "lo",
        "10.0.0.1",
        0
    );
    TEST_ASSERT_NULL(p_fault);

    p_fault = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "abcd",
        "10.0.0.1",
        7777
    );
    TEST_ASSERT_NULL(p_fault);
       
}

/**
 * @brief test fuzzer initialization
 * @return void
 */
void 
test_fuzzer_init(void) 
{
    fuzz_config_t p_cfg = {0};
    TEST_ASSERT_EQUAL_INT(0, fuzzer_init(&p_cfg));
}

/**
 * @brief test fuzzer de-initialization
 * @return void
 */
void 
test_fuzzer_deinit(void) 
{
    fuzz_config_t *p_cfg = fuzzer_new(
        FUZZ_MODE_IP_OPTIONS,
        "lo",
        "127.0.0.1",
        7777
    );
    
    fuzzer_print_config(p_cfg);

    TEST_ASSERT_NOT_NULL(p_cfg);

    TEST_ASSERT_EQUAL_INT(0, fuzzer_deinit(p_cfg));

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
    RUN_TEST(test_fuzzer_convert_ip);
    RUN_TEST(test_fuzzer_mode_to_ascii);

    return UNITY_END();
}



