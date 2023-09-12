#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <string.h>

//TODO: NBO vs HBO!!!

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

static bool send_len_str(int sockfd, char *str)
{
    uint64_t str_len = str == NULL ? 0 : strlen(str) + 1;

    if (send(sockfd, &str_len, 4, 0) == -1){
        return false;
    }

    if (str_len == 0) {
        return true;
    }

    if (send(sockfd, str, str_len, 0) == -1){
        return false;
    }
    return true;
}

bool send_message(int sockfd, struct message message)
{
    if (send(sockfd, message.id, 9, 0) == -1){
        //TODO: log? (ve vsech posilanich)
        return false;
    }
    //printf("sent: id: %s\n", message.id);
    if (send(sockfd, &message.message_type, 1, 0) == -1){
        return false;
    }
    //printf("sent: type: %d\n", message.message_type);
    if (!send_len_str(sockfd, message.user)) {
        return false;
    }
    //printf("sent: user: %s\n", message.user);
    if (!send_len_str(sockfd, message.room)) {
        return false;
    }
    //printf("sent: room: %s\n", message.room);
    if (send(sockfd, message.time, 9, 0) == -1){
        return false;
    }
    //printf("sent: time: %s\n", message.time);
    if (!send_len_str(sockfd, message.content)) {
        return false;
    }
    //printf("sent: content: %s\n", message.content);
    if (send(sockfd, &message.magic_num, 4, 0) == -1){
        return false;
    }
    //printf("sent: magic_num: %ld\n", message.magic_num);

    return true;
}

static bool recv_len_str(int sockfd, char **str)
{
    uint64_t str_len = 0;
    if (recv(sockfd, &str_len, 4, MSG_WAITALL) == -1) {
        return false;
    }

    if (str_len == 0) {
        return true;
    }

    *str = malloc(str_len);
    if (*str == NULL) {
        return false;
    }

    if (recv(sockfd, *str, str_len, MSG_WAITALL) == -1) {
        return false;
    }
    return true;
}

bool recv_message(int sockfd, struct message *message)
{
    if (recv(sockfd, &(message->id), 9, MSG_WAITALL) == -1) {
        //TODO: log?
        return false;
    }
    //printf("received: id: %s\n", message->id);
    if (recv(sockfd, &(message->message_type), 1, MSG_WAITALL) == -1){
        return false;
    }
    //printf("received: type: %d\n", message->message_type);
    if (!recv_len_str(sockfd, &(message->user))) {
        return false;
    }
    //printf("received: user: %s\n", message->user);
    if (!recv_len_str(sockfd, &(message->room))) {
        return false;
    }
    //printf("received: room: %s\n", message->room);
    if (recv(sockfd, &(message->time), 9, MSG_WAITALL) == -1){
        return false;
    }
    //printf("received: time: %s\n", message->time);
    if (!recv_len_str(sockfd, &(message->content))) {
        return false;
    }
    //printf("received: content: %s\n", message->content);
    if (recv(sockfd, &(message->magic_num), 4, MSG_WAITALL) == -1){
        return false;
    }
    //printf("received: magic_num: %ld\n", message->magic_num);
    return true;
}
