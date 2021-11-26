/** @file module.c
 * 
 * @brief A description of the module’s purpose. 
 *
 */
#include <unity.h>
#include <fuzzer.h>


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
 * Test Cases
 *********************************************************/

/**
 * @brief trivial test to confirm correct function
 * @return void
 */
void 
test_trivial(void) 
{
    TEST_FAIL();
}

/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_trivial);

    return UNITY_END();
}



