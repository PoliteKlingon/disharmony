#include "disharmony_server.h"
#include "disharmony_protocol.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>
#include <error.h>
#include <errno.h>
#include <netdb.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#define UNUSED(VAR) ((void) (VAR))

static const unsigned int MAGICNUM = 0xDEADBEEF;

#ifndef ENUM_MESSAGE_TYPE
#define #ifndef ENUM_MESSAGE_TYPE
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

struct user {
    char* name;
    char* password;
    char session_id[9];
    int sockfd;
};

struct room {
    char *name;
    struct user **users;
    int users_no;
    int users_max;
    struct message **messages;
    int messages_no;
    int messages_max;
};

static struct room *create_room (char *name)
{
    struct room *room = calloc(1, sizeof(struct room));
    if (room == NULL) {
        warn("Out of memory!");
        return NULL;
    }
    room->users_no = 0;
    room->users_max = 10;
    room->messages_no = 0;
    room->messages_max = 10;

    room->name = strdup(name);
    if (room->name == NULL) {
        perror("strdup");
        free(room);
        return NULL;
    }

    room->users = calloc(room->users_max, sizeof(struct user *));
    if (room->users== NULL) {
        warn("Not enough memory!");
        free(room->name);
        free(room);
        return NULL;
    }

    room->messages = calloc(room->messages_max, sizeof(struct message *));
    if (room->messages== NULL) {
        warn("Not enough memory!");
        free(room->name);
        free(room->users);
        free(room);
        return NULL;
    }

    return room;
}

static struct room *new_room(char *room_name, struct room ***rooms, int *rooms_no, int *rooms_max)
{   //TODO: tohle je skoro duplikat new_user. jak to udelat aby nebyl?
    struct room *room = create_room(room_name);
    if (room == NULL) {
        return NULL;
    }

    if (*rooms_max <= *rooms_no + 1) {
        *rooms_max = *rooms_max * 2 + 1;
        struct room** newptr = realloc(*rooms, *rooms_max * sizeof(struct room *));
        if (newptr == NULL) {
            warn("Out of memory!\n");
            return NULL;
        }
        *rooms = newptr;
    }

    (*rooms)[*rooms_no] = room;
    (*rooms_no)++;
    return room;
}

static bool new_message(struct message *message, struct room *room)
{
    if (room->messages_max <= room->messages_no + 1) {
        room->messages_max = room->messages_max * 2 + 1;
        struct message** newptr = realloc(room->messages, room->messages_max * sizeof(struct message *));
        if (newptr == NULL) {
            warn("Out of memory!\n");
            return false;
        }
        room->messages = newptr;
    }

    room->messages[room->messages_no] = message;
    (room->messages_no)++;


    return true;
}

static struct user *find_user(char *username, struct user **users, int users_no)
{
    for (int i = 0; i < users_no; i++) {
        if (strcmp(users[i]->name, username) == 0) {
            return users[i];
        }
    }
    return NULL;
}

static struct user *create_user(struct user user_static)
{
    struct user *user = calloc(1, sizeof(struct user));
    if (user == NULL) {
        warn("Out of memory!");
        return NULL;
    }
    user->sockfd = user_static.sockfd;
    strcpy(user->session_id, user_static.session_id);

    user->name = strdup(user_static.name);
    if (user->name == NULL) {
        perror("strdup");
        free(user);
        return NULL;
    }

    user->password = strdup(user_static.password);
    if (user->password == NULL) {
        perror("strdup");
        free(user->name);
        free(user);
        return NULL;
    }

    return user;
}

static struct user *new_user(struct user user_static, struct user ***users, int *users_no, int *users_max)
{
    struct user *user = create_user(user_static);
    if (user == NULL) {
        return NULL;
    }

    if (*users_max <= *users_no + 1) {
        *users_max = *users_max * 2 + 1;
        struct user **newptr = realloc(*users, *users_max * sizeof(struct user *));
        if (newptr == NULL) {
            warn("Out of memory!\n");
            return NULL;
        }
        *users = newptr;
    }

    (*users)[*users_no] = user;
    (*users_no)++;
    return user;
}

static struct room *find_room(char *room, struct room **rooms, int rooms_no)
{
    for (int i = 0; i < rooms_no; i++) {
        if (strcmp(rooms[i]->name, room) == 0) {
            return rooms[i];
        }
    }
    return NULL;
}

static void remove_user(struct user *user, struct room *room)
{
    int index_found = 0;
    while (index_found <= room->users_no) {
        if (room->users[index_found] == user) {
            break;
        }
        index_found++;
    }
    if (room->users[index_found] != user) {
        return;
    }

    room->users[index_found] = room->users_no - 1 == index_found ? NULL : room->users[room->users_no - 1];
    (room->users_no)--;
}

static bool logout_user(char *username, struct user **users, int users_no,
                        char* roomname, struct room **rooms, int rooms_no,
                        struct pollfd **pollfd, int pollfd_no)
{
    struct user *user = find_user(username, users, users_no);
    if (user == NULL) {
        printf("User not found wtf\n");
        //TODO: log asi
        return false;
    }

    struct room *room = find_room(roomname, rooms, rooms_no);
    if (room == NULL) {
        printf("Room not found wtf\n");
        //TODO: log asi
        return false;
    }
    remove_user(user, room);

    for (int i = 0; i < pollfd_no; i++) {
        if (user->sockfd == (*pollfd)[i].fd) {
            (*pollfd)[i].fd = -1;
            close(user->sockfd);
            break;
        }
    }

    user->sockfd = -1;
    return true;
}

static bool assign_user(struct user *user, struct room *room)
{
    if (room->users_max <= room->users_no + 1) {
        room->users_max = room->users_max * 2 + 1;
        struct user** newptr = realloc(room->users, room->users_max * sizeof(struct user *));
        if (newptr == NULL) {
            warn("Out of memory!\n");
            return false;
        }
        room->users = newptr;
    }
    room->users[room->users_no] = user;
    (room->users_no)++;
    return true;
}

static bool delete_user(struct user *user)
{
    return true; //TODO urcite bude potreba? mozna pro uklid
}

static void destroy_message(struct message *message)
{
    free(message->user);
    free(message->content);
    free(message->room);
    free(message);
}

static void destroy_room(struct room room)
{
    for (int i = 0; i < room.messages_no; i++) {
        destroy_message(room.messages[i]);
    }

    free(room.users);
}

static bool send_server_reply(int clientfd, enum message_type message_type, char *content)
{
    struct message reply = {
            .id = "serverid",
            .time = "setvertm",
            .message_type = message_type,
            .content = content,
            .magic_num = MAGICNUM,
    };
    return send_message(clientfd, reply);
}

static void process_message(struct message *message, struct room **rooms, int rooms_no)
{
    struct room *room = find_room(message->room, rooms, rooms_no);
    if (room == NULL) {
        printf("Room not found!\n");
        return;
    }

    if (!new_message(message, room)) {
        return;
    }

    for (int i = 0; i < room->users_no; i++) {
        if(room->users[i]->sockfd != -1) {
            if (!send_message(room->users[i]->sockfd, *message)) {
                warn("Error while sending message\n");
            }
        }
    }
}

static void process_rooms(int clientfd, struct room **rooms, int rooms_no)
{
    int result_len = 0;
    for (int i = 0; i < rooms_no; i++) {
        result_len += 2; // ', '
        result_len += strlen(rooms[i]->name);
    }

    char *result = calloc(result_len, sizeof(char));
    if (result == NULL) {
        printf("Out of memory!");
        return;
    }

    for (int i = 0; i < rooms_no; i++) {
        strcat(result, rooms[i]->name);
        strcat(result, ", ");
    }
    result[result_len - 2] = '\0'; //cut ', ' at the end

    if (!send_server_reply(clientfd, ROOMS, result)) {
        printf("Could not send message\n");
    }
    free(result);
}

static void process_users(int clientfd, struct message *message, struct room **rooms, int rooms_no)
{
    char *result = NULL;
    struct room *room;
    if (message->content != NULL && strlen(message->content) > 0) {
        room = find_room(message->content, rooms, rooms_no);
        if (room == NULL) {
            result = "This room does not exist";
        }
    } else {
        room = find_room(message->room, rooms, rooms_no);
        if (room == NULL) {
            result = "Internal error - your room does not appear to exist";
        }
    }

    if (result != NULL) {
        if (!send_server_reply(clientfd, USERS, result)) {
            printf("Could not send message\n");
        }
        return;
    }

    unsigned long result_len = 0;
    for (int i = 0; i < room->users_no; i++) {
        result_len += strlen(room->users[i]->name);
        result_len += 2; // ', '
    }

    result = calloc(result_len, sizeof(char));
    if (result == NULL) {
        printf("Out of memory!\n");
        return;
    }

    for (int i = 0; i < room->users_no; i++) {
        strcat(result, room->users[i]->name);
        strcat(result, ", ");
    }
    result[result_len - 2] = '\0'; //cut ', ' at the end

    if (!send_server_reply(clientfd, USERS, result)) {
        printf("Could not send message\n");
    }
    free(result);
}

static void process_audience(int clientfd, struct room **rooms, int rooms_no)
{
    unsigned long result_len = 0;

    for (int i = 0; i < rooms_no; i++) {
        result_len += strlen(rooms[i]->name);
        result_len += 2; // ': '
        if (rooms[i]->users_no == 0) {
            result_len += strlen("no active users");
        }
        for (int j = 0; j < rooms[i]->users_no; j++) {
            result_len += strlen(rooms[i]->users[j]->name);
            if (j != rooms[i]->users_no - 1) {
                result_len += 2; // ', '
            }
        }
        if (i != rooms_no - 1) {
            result_len += 1; // '\n
        }
    }

    char *result = calloc(result_len, sizeof(char));
    if (result == NULL) {
        printf("Out of memory!\n");
        return;
    }

    for (int i = 0; i < rooms_no; i++) {
        strcat(result, rooms[i]->name);
        strcat(result, ": ");
        if (rooms[i]->users_no == 0) {
            strcat(result, "no active users");
        }
        for (int j = 0; j < rooms[i]->users_no; j++) {
            strcat(result, rooms[i]->users[j]->name);
            if (j != rooms[i]->users_no - 1) {
                strcat(result, ", ");
            }
        }
        if (i != rooms_no - 1) {
            strcat(result, "\n");
        }
    }

    if (!send_server_reply(clientfd, USERS, result)) {
        printf("Could not send message\n");
    }
    free(result);
}

static void send_recent_messages(int clientfd, struct room room)
{
    int start = room.messages_no > 10 ? room.messages_no - 10 : 0;
    for (int i = start; i < room.messages_no; i++) {
        if (!send_message(clientfd, *room.messages[i])) {
            printf("Could not send message\n");
        }
    }
}

static void process_switch(int sockfd, struct message *message,
                           struct room ***rooms, int *rooms_no, int *rooms_max,
                           struct user **users, int users_no)
{
    struct user *user = find_user(message->user, users, users_no);
    if (user == NULL) {
        printf("User not found\n"); //TODO: asi log idk?
        return;
    }

    struct room *old_room = find_room(message->room, *rooms, *rooms_no);
    if (old_room == NULL) {
        printf("could not find room, that is weird\n");
        return;
    }
    remove_user(user, old_room);

    struct room *wanted_room = find_room(message->content, *rooms, *rooms_no);
    if (wanted_room == NULL) {
        wanted_room = new_room(message->content, rooms, rooms_no, rooms_max);
        if (wanted_room == NULL) {
            printf("Could not create room\n");
            return;
        }
    }
    assign_user(user, wanted_room); //TODO: osetrit fail?
    struct message reply = {
            .message_type = SWITCH,
            .content = message->content,
            .id = "serverid",
            .time = "servertm",
            .magic_num = MAGICNUM,
    };
    if (!send_message(sockfd, reply)) {
        //TODO: asi log?
    }
    send_recent_messages(sockfd, *wanted_room);
}

static void process_passwd(int clientfd, struct message *message, struct user **users, int users_no)
{
    if (message->content[strlen(message->content) - 1] == '\n') {
        message->content[strlen(message->content) - 1] = '\0'; //strip '\n'
    }

    printf("New password is: %skonec\n", message->content);

    struct user *user = find_user(message->user, users, users_no);
    if (user == NULL) {
        if (!send_server_reply(clientfd, PASSWD, "n")) {
            printf("Could not send server reply\n");
        }
        printf("User not found.\n");
        return;
    }

    char *newptr = realloc(user->password, strlen(message->content) + 1);
    if (newptr == NULL) {
        if (!send_server_reply(clientfd, PASSWD, "n")) {
            printf("Could not send server reply\n");
        }
        printf("Out of memory.\n");
        return;
    }

    user->password = newptr;
    strcpy(user->password, message->content);

    if (!send_server_reply(clientfd, PASSWD, "y")) {
        printf("Could not send server reply\n");
    }
    printf("New password set: %skonec\n", user->password);
}

static void process_exit(struct message *message, struct user **users, int users_no,
                         struct room **rooms, int rooms_no,
                         struct pollfd **pollfd, int pollfd_no)
{
    if (!logout_user(message->user, users, users_no, message->room, rooms, rooms_no, pollfd, pollfd_no)) {
        //TODO: log nejspis
    }
}

static void parse_message(int sockfd, struct options options,
                          struct room ***rooms, int *rooms_no, int *rooms_max,
                          struct user **users, int users_no,
                          struct pollfd **pollfd, int pollfd_no)
{
    struct message *message = calloc(1, sizeof(struct message)); //TODO: tento calloc bude chtit nekdy free a nekdy ne
    if (message == NULL) {
        warn("Out of memory!");
        return;
    }

    if (!recv_message(sockfd, message)) {
        warn("Error while receiving message.");
        return;
    }

    if (message->magic_num != MAGICNUM) {
        printf("magicnum is not correct\n");
        return;
    }

    switch (message->message_type) {
        case UNKNOWN:
            break;
        case MESSAGE: case IMG:
            process_message(message, *rooms, *rooms_no);
            return;
        case ROOMS:
            process_rooms(sockfd, *rooms, *rooms_no);
            break;
        case USERS:
            process_users(sockfd, message, *rooms, *rooms_no);
            break;
        case AUDIENCE:
            process_audience(sockfd, *rooms, *rooms_no);
            break;
        case INFO:
            //TODO
            break;
        case SWITCH:
            process_switch(sockfd, message, rooms, rooms_no, rooms_max, users, users_no);
            break;
        case PASSWD:
            process_passwd(sockfd, message, users, users_no);
            break;
        case EXIT:
            process_exit(message, users, users_no, *rooms, *rooms_no, pollfd, pollfd_no);
            break;
        default:
            break;
    }
    destroy_message(message);
}

static
void net_error(int exit_status, int neterrno)
{
    if (neterrno == EAI_SYSTEM) {
        warn("gai error");
    } else {
        warnx("gai error: %s", gai_strerror(neterrno));
    }
    if (exit_status != 0) {
        exit(exit_status);
    }
}

static int setup_connections(struct options options)
{
    int sockfd = -1;

    struct addrinfo *nodes;
    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_flags = AI_PASSIVE,
    };

    int ret;
    if ((ret = getaddrinfo(NULL, options.port, &hints, &nodes)) != 0) {
        net_error(1, ret);
    }

    for (struct addrinfo *node = nodes; sockfd == -1 && node != NULL; node = node->ai_next) {
        sockfd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (bind(sockfd, node->ai_addr, node->ai_addrlen) != 0) {
            net_error(0, ret);
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(nodes);

    if (nodes == NULL) {
        fprintf(stderr, "Could not bind\n");
        return -1;
    }

    listen(sockfd, 1);

    return sockfd;
}

static char random_char(void)
{
    return 'a'; //TODO: randomizovat
}

static void generate_id(char *id)
{
    id[8] = '\0';
    for (int i = 0; i < 8; i++) {
        id[i] = random_char();
    }
}

static void reply_login(int clientfd, char *command)
{
    struct message reply = {.content = command,
            .message_type = LOGIN,
            .magic_num = MAGICNUM,
            .id = "serverid",
            .time = "servertm"};
    if (!send_message(clientfd, reply)) {
        warn("Could not send login reply message.");
    }
}

static bool identify(int clientfd, struct user ***users, int *users_no, int *users_max,
                     struct room ***rooms, int *rooms_no, int *rooms_max)
{
    struct message message = { 0 };
    if (!recv_message(clientfd, &message) || message.message_type != LOGIN) {
        warn("Could not receive client login message.");
        return false;
    }

    if (message.content[strlen(message.content) - 1] == '\n') {
        message.content[strlen(message.content) - 1] = '\0'; //strip '\n'
    }

    struct user *user = find_user(message.user, *users, *users_no);
    if (user != NULL && user->sockfd != -1) {
        reply_login(clientfd, "du");
        return false;
    }

    if (user == NULL) {
        struct user user_static = {.sockfd = clientfd,
                                   .name = message.user,
                                   .password = message.content,
                                   .session_id = ""};
        user = new_user(user_static, users, users_no, users_max);
        if (user == NULL) {
            return false;
        }
    }

    if (strcmp(user->password, message.content) != 0) {
        reply_login(clientfd, "wp");
        return false;
    }

    user->sockfd = clientfd;

    struct room *room = find_room(message.room, *rooms, *rooms_no);
    if (room == NULL) {
        room = new_room(message.room, rooms, rooms_no, rooms_max);
        if (room == NULL) {
            return false;
        }
    }

    assign_user(user, room);

    generate_id(user->session_id);

    free(message.room);
    free(message.user);
    free(message.content);

    struct message reply = {.content = user->session_id,
                            .message_type = LOGIN,
                            .magic_num = MAGICNUM,
                            .id = "serverid",
                            .time = "servertm"};
    if (!send_message(clientfd, reply)) {
        warn("Could not send login reply message.");
        return false;
    }

    send_recent_messages(clientfd, *room);
    return true;
}

static bool new_fd(struct pollfd **pollfd, int *pollfd_no, int *pollfd_max, int clientfd)
{
    if (*pollfd_max <= *pollfd_no + 1) {
        *pollfd_max = *pollfd_max * 2 + 1;
        struct pollfd* newptr = realloc(*pollfd, *pollfd_max * sizeof(struct pollfd));
        if (newptr == NULL) {
            warn("Out of memory!\n");
            return false;
        }
        *pollfd = newptr;
    }

    (*pollfd)[*pollfd_no].fd = clientfd;
    (*pollfd)[*pollfd_no].events = POLLIN;
    (*pollfd)[*pollfd_no].revents = 0;
    (*pollfd_no)++;
    return true;
}

struct pthread_data {
    int sockfd;
    int *pipefd;
    struct user ***users;
    int *users_no;
    int *users_max;
    struct room ***rooms;
    int *rooms_no;
    int *rooms_max;
    struct pollfd **pollfd;
    int *pollfd_no;
    int *pollfd_max;
};

_Noreturn static void *accept_new_users(void * raw_data)
{
    struct pthread_data data = *((struct pthread_data *)raw_data);

    struct sockaddr client_addr = { 0 };
    socklen_t client_addr_len = 0;

    while (true) {
        int clientfd = accept(data.sockfd, &client_addr, &client_addr_len);
        printf("ACCEPTED, clientfd %d.\n", clientfd); //TODO: pak spis log lol

        if (!identify(clientfd, data.users, data.users_no, data.users_max, data.rooms, data.rooms_no, data.rooms_max)) {
            close(clientfd);
            continue;
        }

        if (!new_fd(data.pollfd, data.pollfd_no, data.pollfd_max, clientfd)) {
            //TODO:log asi
        }
        write(data.pipefd[1], "1", 1);
    }
}

/*void alrmhandler(int sig) {
    UNUSED(sig);
    alarm(30);
}*/

int run_server(struct options options) {
    int users_no = 0;
    int users_max = 10;
    struct user **users = calloc(users_max, sizeof(struct user *)); //TODO: FREE!!!
    if (users == NULL) {
        warn("Out of memory!");
        return EXIT_FAILURE;
    }

    int rooms_no = 0;
    int rooms_max = 10;
    struct room **rooms = calloc(rooms_max, sizeof(struct room *)); //TODO: FREE!!!
    if (rooms == NULL) {
        warn("Out of memory!");
        free(users);
        return EXIT_FAILURE;
    }

    int sockfd = setup_connections(options);
    if (sockfd == -1) {
        free(users);
        free(rooms);
        warn("Could not set up a connection.");
        return EXIT_FAILURE;
    }


    int pollfd_no = 0;
    int pollfd_max = 10;
    struct pollfd *pollfd = calloc(pollfd_max, sizeof(struct pollfd));
    if (pollfd == NULL) {
        free(users);
        free(rooms);
        warn("Out of memory.");
        return EXIT_FAILURE;
    }

    int pipefd[2]; //TODO: nekdy by yblo fajn zavrit tuhle rouru
    if (pipe(pipefd) == -1) {
        error(EXIT_FAILURE, errno, "pipe"); //TODO: uklid!
    }

    pollfd[0].fd = pipefd[0];
    pollfd[0].events = POLLIN;
    pollfd[0].revents = 0;
    pollfd_no++;

    /*struct sigaction alrm_action = {
            .sa_handler = alrmhandler,
    };

    if (sigaction(SIGALRM, &alrm_action, NULL) == -1) {
        error(EXIT_FAILURE, errno, "sigaction(SIGALRM)");
        //TODO: uklid?
    }*/
    alarm(5); //TODO: dat na tricet

    sigset_t signals;
    if (sigemptyset(&signals) == -1) {
        error(EXIT_FAILURE, errno, "sigemptyset()"); //TODO: uklid
    }
    if (sigaddset(&signals, SIGALRM) == -1) {
        error(EXIT_FAILURE, errno, "sigaddset()"); //TODO: uklid
    }
    if (sigprocmask(SIG_BLOCK, &signals, NULL) == -1) {
        error(EXIT_FAILURE, errno, "sigprocmask"); //TODO: uklid
    }
    int sigfd = signalfd(-1, &signals, 0);

    pollfd[1].fd = sigfd;
    pollfd[1].events = POLLIN;
    pollfd[1].revents = 0;
    pollfd_no++;

    int pterrno;
    pthread_t thread;
    struct pthread_data data = { sockfd, pipefd,
                                 &users, &users_no, &users_max,
                                 &rooms, &rooms_no, &rooms_max,
                                 &pollfd, &pollfd_no, &pollfd_max };
    if ((pterrno = pthread_create(&thread, NULL, &accept_new_users, &data)) != 0) {
        error(EXIT_FAILURE, pterrno, "pthread_create()"); //TODO: uklid!!
    }

    //TODO: demonizace?


    char tmp;
    int event;
    while ((event = poll(pollfd, pollfd_no, -1)) > 0) {
        if (pollfd[0].revents > 0) {
            read(pollfd[0].fd, &tmp, 1);
            continue;
        }

        if (pollfd[1].revents > 0) {
            for (int i = 0; i < users_no; i++) {
                if (users[i]->sockfd != -1) {
                    send_server_reply(users[i]->sockfd, HEARTBEAT, "");
                }
            }
            read(pollfd[1].fd, NULL, 999999); //TODO: solve this pls

            alarm(5); //TODO: predelat na 30
        }

        for (int i = 2; i < pollfd_no; i++) {
            if (pollfd[i].revents > 0) {
                parse_message(pollfd[i].fd, options, &rooms, &rooms_no, &rooms_max, users, users_no, &pollfd, pollfd_no);
                printf("zprava zpracovana\n");
            }
        }
    }
    if (event == 0) {
        printf("Connection with the server lost.\n");
        close(sockfd);
        return EXIT_FAILURE;
    }
    if (event == -1) {
        close(sockfd);
        error(EXIT_FAILURE, errno, "poll");
    }

    //TODO: nejaky uklid!

    //assert(false); //non-reachable

    //TODO: kazdych 30 sekund vsem pripojenym poslat heartbeat - alarm -> signalfd() -> poll se vsema deskriptorama

    return EXIT_SUCCESS;
}
