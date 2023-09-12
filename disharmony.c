#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include "disharmony_client.h"
#include "disharmony_server.h"

void help(void)
{
    char *help = "Usage for server: ./disharmony [OPTIONS]\n\n" //TODO!!!
                 "Options:\n"
                 "\t -g or --group: print only the effective group ID\n"
                 "\t -G or --groups: print all group IDs\n"
                 "\t -n or --name: print a name instead of a number, for -ugG\n"
                 "\t -r or --real: print the real ID instead of the effective ID, with -ugG\n"
                 "\t -u or --user: print only the effective user ID\n"
                 "\t -h or --help: shows this useful help\n"
                 "\t -v or --version: tells you the version of this program\n\n"

                 "Usage for client: ./disharmony [OPTIONS] HOST\n\n" //TODO!!!
                 "Options:\n"
                 "\t -g or --group: print only the effective group ID\n"
                 "\t -G or --groups: print all group IDs\n"
                 "\t -n or --name: print a name instead of a number, for -ugG\n"
                 "\t -r or --real: print the real ID instead of the effective ID, with -ugG\n"
                 "\t -u or --user: print only the effective user ID\n"
                 "\t -h or --help: shows this useful help\n"
                 "\t -v or --version: tells you the version of this program\n";
    puts(help);
}

static const char optstring[] = "hdqSp:nb:Cu:r:";
struct option longopts[] = {
        { .val = 'h', .name = "help" },
        { .val = 'd', .name = "debug" },
        { .val = 'q', .name = "warn" },
        { .val = 'S', .name = "server" },
        { .val = 'p', .name = "port" },
        { .val = 'n', .name = "foreground" },
        { .val = 'b', .name = "userdb" },
        { .val = 'C', .name = "client" },
        { .val = 'u', .name = "user" },
        { .val = 'r', .name = "room" },
        { 0 },
};

#ifndef STRUCT_OPTIONS
#define STRUCT_OPTIONS
struct options {
    bool debug;
    bool warn;
    bool server;
    char *port;
    bool foreground;
    char *userdb;
    bool client;
    char *user;
    char *room;
};
#endif

long str_to_long(char *str)
{
    errno = 0;
    char *endptr;
    long num = strtol(str, &endptr, 10);
    if (errno != 0 || endptr == str || *endptr != '\0') {
        return -1;
    }
    return num;
}

void parse_args(int *argc, char **argv[], struct options *options)
{
    int opt;

    while ((opt = getopt_long(*argc, *argv, optstring, longopts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                help();
                exit(EXIT_SUCCESS);

            case 'd':
                options->debug = true;
                break;

            case 'q':
                options->warn = true;
                break;

            case 'S':
                options->server = true;
                break;

            case 'p':
                options->port = optarg;
                break;

            case 'n':
                options->foreground = true;
                break;

            case 'b':
                options->userdb = optarg;
                break;

            case 'C':
                options->client = true;
                break;

            case 'u':
                options->user = optarg;
                break;

            case 'r':
                options->room = optarg;
                break;

            default:
                help();
                exit(EXIT_FAILURE);
        }
    }
    *argc -= optind - 1;
    (*argv)[optind - 1] = (*argv)[0];
    *argv = &((*argv)[optind - 1]);
    //last three lines basically remove options by modifying argc and argv
}

bool check_options(struct options options)
{
    if (options.client && options.server) {
        fprintf(stderr, "Can not be server AND client.\n");
        return false;
    }
    if (options.debug && options.warn) {
        fprintf(stderr, "Can not be debug AND warn.\n");
        return false;
    }
    if (options.server && ((options.user != NULL && strcmp(options.user, "") != 0) ||
                           (options.room != NULL && strcmp(options.room, "") != 0 ))) {
        fprintf(stderr, "These options do not make sense with server side.\n");
        return false;
    }
    if (options.client && (options.foreground ||
                          (options.userdb != NULL && strcmp(options.userdb, "") != 0 ))) {
        fprintf(stderr, "These options do not make sense with client side.\n");
        return false;
    }
    /*if (options.port == -1) {
        fprintf(stderr, "Invalid port number.\n");
        return false;
    }*/

    return true;
}

int main(int argc, char *argv[])
{
    struct options options = { 0 };
    parse_args(&argc, &argv, &options);
    if (!check_options(options)) {
        help();
        return EXIT_FAILURE;
    }

    if (options.server) {
        if (options.port == NULL) {
            fprintf(stderr, "You need to specify port!\n");
            help();
            return EXIT_FAILURE;
        }
        if (argc != 1) {
            fprintf(stderr, "Invalid arguments!\n");
            help();
            return EXIT_FAILURE;
        }
        return run_server(options);
    }

    if(options.user == NULL || options.room == NULL) {
        fprintf(stderr, "You need to specify username and room!\n");
        help();
        return EXIT_FAILURE;
    }
    if (argc != 2) {
        fprintf(stderr, "Invalid arguments!\n");
        help();
        return EXIT_FAILURE;
    }
    return run_client(options, argv[1]); //default
}
