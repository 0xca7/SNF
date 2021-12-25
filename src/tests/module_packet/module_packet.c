/** @file module_packet.c
 * 
 * @brief tests for the packet module. there is not a lot
 *        going on here, as tests with wireshark confirm
 *        that packets are built correctly.
 *        Thus, the functions are called and it is checked
 *        if they return the excepted length only.
 *        Everything else is handeled in the generator tests.
 */

#include <unity.h>
#include <packet.h>
#include "../../modules/packet/packet.c"


/**
 * Author:  0xca7
 * Desc:    tests for the packet module
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
    util_prng_init();
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
}


/**********************************************************
 * Test Cases - Public Functions
 *********************************************************/

/**
 * @brief test building a TCP packet
 * - tests success cases
 */
void
test_packet_build_tcp(void) 
{
    uint8_t buffer[256] = { 0x00 };
    uint8_t options[4] = { 0x02, 0x04, 0xde, 0xad };
    uint8_t options_length = 4;

    /* tcp header without options; 20 bytes TCP header and 
       20 bytes IP header */
    const int TCP_PACKET_SIZE = 20 + 20;  

    /* pass valid options and see what we get as a result */
    TEST_ASSERT_EQUAL_INT(TCP_PACKET_SIZE + 4, 
        packet_build_tcp(&buffer[0], 256, 
            &options[0], options_length,
            inet_addr("127.0.0.1"), inet_addr("127.0.0.1"),
            5555));

    /* NULL pointer exceptions are handled, program exits 
       immediately on NULL pointer */

}

/**
 * @brief test building a IP packet
 * - tests success cases
 */
void
test_packet_build_ip(void) {

    uint8_t buffer[256] = { 0x00 };
    uint8_t options[4] = { 0x02, 0x04, 0xde, 0xad };
    uint8_t options_length = 4;

    /* ip header without options; 20 bytes IP header and 
       20 bytes IP header */
    const int IP_PACKET_SIZE = 20 + 20;  

    /* pass valid options and see what we get as a result */
    TEST_ASSERT_EQUAL_INT(IP_PACKET_SIZE + 4, 
        packet_build_ip(&buffer[0], 256, 
            &options[0], options_length,
            inet_addr("127.0.0.1"), inet_addr("127.0.0.1"),
            5555));

    /* NULL pointer exceptions are handled, program exits 
       immediately on NULL pointer */

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
    RUN_TEST(test_packet_build_ip);

    return UNITY_END();
}



