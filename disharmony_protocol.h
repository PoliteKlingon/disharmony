//hlavicka

#include <stdbool.h>
#include <stdint.h>

#ifndef ENUM_MESSAGE_TYPE
#define ENUM_MESSAGE_TYPE
enum message_type {
    MESSAGE,
    ROOMS,
    EXIT,
    INFO,
    HELP,
    USERS,
    AUDIENCE,
    SWITCH,
    PASSWD,
    UNKNOWN,
    HEARTBEAT,
    LOGIN,
    IMG,
};
#endif

#ifndef STRUCT_MESSAGE
#define STRUCT_MESSAGE
struct message {
    char id[9];
    enum message_type message_type;
    char *user;
    char *room;
    char time[9];
    char *content;
    uint64_t magic_num;
};
#endif

bool send_message(int sockfd, struct message message);
bool recv_message(int sockfd, struct message *message);
