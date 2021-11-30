/** @file module_packet.c
 * 
 * @brief A description of the packet’s purpose. 
 *
 */
#include <unity.h>
#include <packet.h>
#include "../../modules/packet/packet.c"


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
 * tests the IPv4 checksum calculation function
 */
void
test_ip_calculate_checksum(void)
{
    uint8_t header_bytes[18] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x11, 0xc0, 0xa8,
        0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7
    };

    TEST_ASSERT_EQUAL_INT(0xb861, 
        ip_calculate_checksum(header_bytes, 18));

    TEST_ASSERT_EQUAL_INT(0xb861, 
        ip_calculate_checksum(header_bytes, 18));
    
}


/**********************************************************
 * Test Cases - Public Functions
 *********************************************************/

/**
 * @brief test building a TCP packet
 * - tests success cases
 */
void
test_packet_build_tcp(void) {
    uint8_t buffer[256] = { 0x00 };
    util_prng_init();
    packet_build_tcp(&buffer[0], 256);
}

/**********************************************************
 * Test Main
 *********************************************************/
int 
main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_ip_calculate_checksum);
    RUN_TEST(test_packet_build_tcp);

    return UNITY_END();
}



