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
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <global_cfg.h>
#include <fuzzer.h>

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

/**
 * @brief get fuzz mode from user input
 * @param mode number entered by user
 * @return the fuzzing mode or FUZZ_MODE_INVALID on failure
 */
static e_fuzz_mode_t 
get_mode(int mode);

/***************************************************************************
 * MAIN
 **************************************************************************/
int
main(int argc, char *argv[])
{
    int ret = -1;
    int i = 0;
    int option_index = 0;
    bool incorrect_option = false;
    char *mode = NULL;
    char *target_ip = NULL;
    char *target_port = NULL;
    char *ifname = NULL;

    long int port = 0;
    long int fuzz_mode = -1;
    char *endptr = NULL;

    struct timespec t_start = {0,0};
    struct timespec t_end = {0,0};
    double t_diff = 0.0;

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

    fuzz_mode = strtol(mode, &endptr, 10);
    if(endptr == mode || errno != 0)
    {
        printf("[!!] invalid port\n");
        exit(1);
    }
    
    if(fuzz_mode > 2 || fuzz_mode < 0)
    {
        printf("[!!] invalid mode\n");
        exit(1);
    }

    fuzz_config_t *config = fuzzer_new(
        get_mode(fuzz_mode), ifname, target_ip, (uint16_t)port
    );

    if(config == NULL)
    {
        printf("[!!] invalid fuzzing config, aborting.\n");
        return EXIT_FAILURE;
    }

    ret = fuzzer_init(config);
    if(ret == -1)
    {
        exit(1);
    }

    fuzzer_print_config(config);
    
    printf("fuzzing in... ");
    for(i = 3; i > 0; i--)
    {
        printf("%d ", i);
        fflush(stdout);
        sleep(1);
    }
    printf("\n\n");
    
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    ret = fuzzer_run(config);
    if(ret == -1)
    {
        printf("[!!] failed to run fuzzer\n");
        /* don't exit, deinit first, to free memory of config */
    }
    clock_gettime(CLOCK_MONOTONIC, &t_end);

    /* get time difference */
    t_diff = ((double)t_end.tv_sec + 1.0e-9*t_end.tv_nsec) - 
        ((double)t_start.tv_sec + 1.0e-9*t_start.tv_nsec);

    printf("... fuzzing took about %.5f seconds\n", t_diff);


    ret = fuzzer_deinit(config);
    if(ret == -1)
    {
        exit(1);
    }

    return EXIT_SUCCESS;
}

/***************************************************************************
 * FUNCTIONS
 **************************************************************************/

static void
banner(void)
{
    printf("\n");
    printf("*** SNF - Simple Network Fuzzer\n");
    printf("*** for TCP and IP options\n");
    printf("*** 0xca7\n");
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
    printf("        | 0   IP options\n");
    printf("        | 1   TCP options\n");
    printf("\n\n");

    exit(1);
}


static e_fuzz_mode_t 
get_mode(int mode)
{
    int fuzz_modes[3] = {
        FUZZ_MODE_IP_OPTIONS,
        FUZZ_MODE_TCP_OPTIONS,
        FUZZ_MODE_INVALID
    };
    
    if(mode >= 0 && mode < 2)
    {
        return fuzz_modes[mode];
    }

    /* invalid */
    return fuzz_modes[2];
}
