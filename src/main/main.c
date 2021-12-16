/** @file main.c
 * 
 * @brief the main application
 *
 */


/**
 * Author:  0xca7
 * Desc:    the main
 *
 */

/**
 * Changelog:
 * [dd/mm/yyyy][author]: change
 */

/***************************************************************************
 * LIBRARIES
 **************************************************************************/
#include <stdio.h>
#include <string.h>

#include <global_cfg.h>
#include <generator.h>
#include <packet.h>
#include <networking.h>


/***************************************************************************
 * FUNCTION PROTOTYPES
 **************************************************************************/

/**
 * @brief prints a nice banner
 * @param void
 * @return void
 */
static void
banner(void);

/**
 * @brief prints how to use optfuzz and exits
 * @param void
 * @return void
 */
static void
usage(void);

static void 
fuzz(void)
{
    int len = -1;
    uint8_t buffer[256] = { 0x00 };
    uint8_t tcp_options[32] = { 0x00 };

    if(networking_init(IPPROTO_TCP) == -1)
    {
        return;
    }

    if(util_prng_init() == -1)
    {
        return;
    }

    if(generator_init(FUZZ_MODE_TCP_OPTIONS) == -1)
    {
        return;
    }

    while( generator_run(&tcp_options[0]) )
    {
        len = packet_build_tcp(&buffer[0], 256, &tcp_options[0]);
        if(len == -1)
        {
            return;
        }
        else
        {
            printf("sending %d bytes\n", len);
        }
        if(networking_send(&buffer[0], len) == -1) 
        {
            return;
        }   
        memset(buffer, 0, 256);
    }

    if(networking_deinit() == -1)
    {
        return;
    }

}

/***************************************************************************
 * MAIN
 **************************************************************************/
int
main(int argc, char *argv[])
{
    int option_index = 0;
    bool incorrect_option = false;
    char *mode = NULL;
    char *target_ip = NULL;
    char *target_port = NULL;
    char *ifname = NULL;

    long int port = 0;
    char *endptr = NULL;

    banner();

    while (( option_index = getopt(argc, argv, "m:t:p:i:")) != -1)
    {
        if(incorrect_option)
        {
            usage();
        }

        switch (option_index) {
            case 'm':
                mode = optarg;
            break;
            case 't':
                target_ip = optarg;
            break;
            case 'p':
                target_port = optarg;
            break;
            case 'i':
                ifname = optarg;
            break;
            default:
                incorrect_option = true;
            break;
        } 
    } /* while */ 

    if(mode == NULL)
    {
        printf("[!] no mode specified\n");
        usage();
    }

    if(target_ip == NULL)
    {
        printf("[!] no target IP specified\n");
        usage();
    }

    if(target_port == NULL)
    {
        printf("[!] no target port specified\n");
        usage();
    }

    if(ifname == NULL)
    {
        printf("[!] no interface specified\n");
        usage();
    }

    /* convert the port to int and check result */
    port = strtol(target_port, &endptr, 10);
    if(endptr == target_port || errno != 0)
    {
        printf("[!] invalid port\n");
        exit(1);
    }
    
    if(port > 65535 || port < 0)
    {
        printf("[!] invalid port\n");
        exit(1);
    }

    printf("[*] configuration\n");
    printf("[+] target: %s:%s\n", target_ip, target_port);
    printf("[+] ifname: %s\n", ifname);
    printf("[+] mode:   %s\n\n", mode);

    fuzz();

    return EXIT_SUCCESS;
}

/***************************************************************************
 * FUNCTIONS
 **************************************************************************/

static void
banner(void)
{
    printf("\n");
    printf("*** OptFuzz ***\n");
    printf("*** the fuzzer for TCP options\n");
    printf("\n");
}

static void
usage(void)
{
    printf("\n");
    printf("[*] usage\n");
    printf("[+] -t  target IP address\n");
    printf("[+] -p  target port\n");
    printf("[+] -i  network interface\n");
    printf("[+] -m  mode\n");
    printf("        | 0   TCP options\n");
    printf("        | 1   IP options\n");
    printf("\n\n");

    exit(1);
}


