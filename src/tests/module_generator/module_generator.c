/** @file module_generator.c
 * 
 * @brief tests for the generator module
 *
 */
#include <string.h>

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

void 
test_padding_calculation()
{
    int i = 0;
    int j = 0;
    uint8_t options[4] = { 0x00 };
    uint8_t *ptr_len = &options[1];
    uint8_t padding = 0;

    for(i = 1; i <= 4; i++)
    {
        *ptr_len = i;
        padding = calc_options_padding(&options[0], 0x55);
        /* check if padding was calculated to correct length 
           and if the padding was set correctly. */
        TEST_ASSERT_EQUAL_UINT8(i, 4 - padding);
        printf("padding: %d [%02x %02x %02x %02x]\n", 
            padding, options[0], options[1], options[2], options[3]);
        for(j = padding; j > 4 - padding ; j--) 
        {
            TEST_ASSERT_EQUAL_UINT8(0x55, options[j]);
        }
        memset(options, 0, 4);
    }

}

void
test_tcp_cycle_valid()
{
    int i = 0;
    
    uint8_t buffer[256] = {0x00};
    uint8_t total_length = 0;

    for(i = 0; i < TCP_OPTS_NO_VALUES; i++)
    {
        tcp_cycle_valid(&buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
        TEST_ASSERT_NOT_NULL(buffer);
    }

}


void
test_tcp_cycle_randomize()
{
    int i = 0;
    
    uint8_t buffer[256] = {0x00};
    uint8_t total_length = 0;

    printf("[ (false, MUT_LENGTH_VALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        tcp_cycle_randomize(false, MUT_LENGTH_VALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (true, MUT_LENGTH_VALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        tcp_cycle_randomize(true, MUT_LENGTH_VALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (false, MUT_LENGTH_ZERO) ]\n");
    for(i = 0; i < 256; i++)
    {
        tcp_cycle_randomize(false, MUT_LENGTH_ZERO,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (true, MUT_LENGTH_ZERO) ]\n");
    for(i = 0; i < 256; i++)
    {
        tcp_cycle_randomize(true, MUT_LENGTH_ZERO,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (false, MUT_LENGTH_INVALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        tcp_cycle_randomize(false, MUT_LENGTH_INVALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (true, MUT_LENGTH_INVALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        tcp_cycle_randomize(true, MUT_LENGTH_INVALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

}

void
test_ip_cycle_valid()
{
    int i = 0;
    
    uint8_t buffer[256] = {0x00};
    uint8_t total_length = 0;

    for(i = 0; i < TCP_OPTS_NO_VALUES; i++)
    {
        ip_cycle_valid(&buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
        TEST_ASSERT_NOT_NULL(buffer);
    }

}


void
test_ip_cycle_randomize()
{
    int i = 0;
    
    uint8_t buffer[256] = {0x00};
    uint8_t total_length = 0;

    printf("[ (false, MUT_LENGTH_VALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        ip_cycle_randomize(false, MUT_LENGTH_VALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (true, MUT_LENGTH_VALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        ip_cycle_randomize(true, MUT_LENGTH_VALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (false, MUT_LENGTH_ZERO) ]\n");
    for(i = 0; i < 256; i++)
    {
        ip_cycle_randomize(false, MUT_LENGTH_ZERO,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (true, MUT_LENGTH_ZERO) ]\n");
    for(i = 0; i < 256; i++)
    {
        ip_cycle_randomize(true, MUT_LENGTH_ZERO,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (false, MUT_LENGTH_INVALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        ip_cycle_randomize(false, MUT_LENGTH_INVALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
    }

    printf("[ (true, MUT_LENGTH_INVALID) ]\n");
    for(i = 0; i < 256; i++)
    {
        ip_cycle_randomize(true, MUT_LENGTH_INVALID,
            &buffer[0], &total_length);
        TEST_ASSERT_EQUAL_UINT8(0, (total_length % 4));
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
    TEST_ASSERT_EQUAL_INT(0,
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

    /* if the generator is initialized, it must work */
    generator_init(FUZZ_MODE_TCP_OPTIONS);

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

    RUN_TEST(test_tcp_cycle_valid);
    RUN_TEST(test_tcp_cycle_randomize);

    RUN_TEST(test_ip_cycle_valid);
    RUN_TEST(test_ip_cycle_randomize);

    RUN_TEST(test_padding_calculation);

    return UNITY_END();
}



