//hlavicka

#include <stdbool.h>

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

int run_server(struct options options);
