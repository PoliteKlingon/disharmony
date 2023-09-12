#include "disharmony_client.h"
#include "disharmony_protocol.h"
#include "encoding.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <poll.h>
#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#define _GNU_SOURCE

static const unsigned int MAGICNUM = 0xDEADBEEF;

void commands(void)
{
    puts("Possible commands:\n"
         "\t/logout or /exit - log out of the server\n"
         "\t/info [USER]     - print info about USER, default: this user\n"
         "\t/switch ROOM     - switch to ROOM, if it does not exit, create ROOM\n"
         "\t/rooms           - print list of rooms on this server\n"
         "\t/users [ROOM]    - print list of users in ROOM, default: this room\n"
         "\t/audience        - print list of rooms and active users in each of them\n"
         "\t/passwd PASSWORD - change your password to PASSWORD\n"
         );
}

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
static void destroy_message(struct message *message)
{
    free(message->user);
    free(message->content);
    free(message->room);
    free(message);
}

enum message_type parse_message_type(char *str)
{
    if (strcmp(str, "/help")     == 0) return HELP;
    if (strcmp(str, "/exit")     == 0 ||
        strcmp(str, "/logout")   == 0) return EXIT;
    if (strcmp(str, "/info")     == 0) return INFO;
    if (strcmp(str, "/users")    == 0) return USERS;
    if (strcmp(str, "/audience") == 0) return AUDIENCE;
    if (strcmp(str, "/switch")   == 0) return SWITCH;
    if (strcmp(str, "/rooms")    == 0) return ROOMS;
    if (strcmp(str, "/passwd")   == 0) return PASSWD;
    if (strcmp(str, "/img")   == 0) return IMG;
    return UNKNOWN;
}

static int wc(char *str)
{
    bool was_space = true;
    int count = 0;
    char ch;
    for (int i = 0; (ch = str[i]) != '\0'; i++) {
        if (!isspace(ch)) {
            if (was_space) {
                was_space = false;
                count++;
            }
        } else {
            was_space = true;
        }
    }
    return count;
}

static size_t get_file_size(char *filename)
{
    struct stat st = { 0 };
    if (stat(filename, &st) == -1) {
        error(0, errno, "stat()");
        return -1;
    }
    return st.st_size;
}

static bool send_image(struct message *message, char *filename)
{
    if (access(filename, F_OK) != 0) {
        printf("This file does not exist!\n");
        return false;
    }

    size_t file_size = get_file_size(filename);
    if (file_size == -1) return false;

    void *data = calloc(file_size, 1);
    if (data == NULL) {
        fprintf(stderr, "Not enough memory!\n");
        return false;
    }

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        error(0, errno, "open");
        free(data);
        return false;
    }

    if (read(fd, data, file_size) == -1) {
        error(0, errno, "read");
        free(data);
        close(fd);
        return false;
    }
    close(fd);

    char *encoded_data = encode(data, file_size);
    if (encoded_data == NULL) {
        free(data);
        return false;
    }
    message->content = encoded_data;
    return true;
}

static bool parse_message(struct message *message, char *str, struct options options, char session_id[9])
{
    if (str == NULL) return false;
    message->user = options.user;
    strcpy(message->id, session_id);
    message->room = options.room;

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(message->time, "%d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

    message->magic_num = MAGICNUM;

    if (str[0] == '/') {
        char *command = wc(str) == 1 ? strtok(str, "\n") : strtok(str, " ");
        message->message_type = parse_message_type(command);
        if (message->message_type == IMG) {
            return send_image(message, strtok(NULL, "\n"));
        }
        message->content = strtok(NULL, "\n");
        return message->message_type != UNKNOWN;
    }
    message->message_type = MESSAGE;
    message->content = str;
    return true;
}

static bool check_message(struct message message)
{
    int words = message.content == NULL ? 0 : wc(message.content);
    switch (message.message_type) {
        case HELP: case EXIT: case AUDIENCE: case ROOMS:
            return words == 0;

        case USERS: case INFO:
            return words == 0 || words == 1;

            case SWITCH: case PASSWD:
            return words == 1;

        default:
            return true;
    }
}

static enum message_type stdin_message(struct options options, int sockfd, char session_id[9])
{
    char *line = NULL;
    size_t size = 0;
    errno = 0;
    if (getline(&line, &size, stdin) == -1) {
        if (errno != 0) {
            error(0, errno, "reading from stdin");
        }
        return UNKNOWN;
    }

    if (size == 0) {
        return UNKNOWN;
    }
    struct message message = { 0 };
    if (!parse_message(&message, line, options, session_id) || !check_message(message)) {
        fprintf(stderr, "Invalid command!\n");
        return UNKNOWN;
    }

    if (message.message_type == PASSWD && strlen(message.content) == 0) {
        fprintf(stderr, "New password cannot be empty!\n");
        return UNKNOWN;
    }

    if (message.message_type == SWITCH && strcmp(message.room, message.content) == 0) {
        printf("You are already in room '%s'.\n", message.content);
        return SWITCH;
    }

    if (message.message_type != HELP) {
        send_message(sockfd, message);
    }

    free(line);
    if (message.message_type == IMG) {
        free(message.content);
    }
    return message.message_type;
}

static void receive_image(struct message *message)
{
    printf("User %s sent an image. Do you want to receive it? (Y/n) ", message->user);
    char *line = NULL;
    size_t size = 0;

    while (true) {
        if (getline(&line, &size, stdin) == -1) {
            error(0, errno, "getline()");
            return;
        }

        if (line != NULL && strlen(line) == 2) {
            if (strcmp(line, "y\n") == 0 || strcmp(line, "Y\n") == 0) {
                free(line);
                break;
            }
            if (strcmp(line, "n\n") == 0 || strcmp(line, "N\n") == 0) {
                printf("Ok, image will not be received.\n");
                free(line);
                return;
            }
        }
        printf("Please confirm receiving the image. Y/n\n");
    }

    printf("Please select a filename for the image: ");
    while (true) {
        if (getline(&line, &size, stdin) == -1) {
            error(0, errno, "getline()");
            return;
        }

        if (line == NULL || strlen(line) == 0 || strcmp(line, "\n") == 0) {
            printf("Please select a valid filename.\n");
            free(line);
            continue;
        }
        if (access(line, F_OK) != 0) {
            break;
        }
        printf("This file already exists, please select another name.\n");
        free(line);
    }

    int image = creat(line, S_IRUSR | S_IWUSR);
    free(line);
    if (image == -1) {
        error(0, errno, "creat()");
        return;
    }
    size_t decoded_data_len = 0;
    void *decoded_data = decode(message->content, &decoded_data_len);
    if (decoded_data == NULL) {
        return;
    }

    if (write(image, decoded_data, decoded_data_len) == -1) {
        free(decoded_data);
        close(image);
        error(0, errno, "write()");
        return;
    }
    close(image);
    free(decoded_data);
    printf("Image received.\n");
}

static void server_message(int sockfd, struct options *options)
{
    struct message *message = calloc(1, sizeof(struct message));
    if (message == NULL) {
        warn("Out of memory!");
        return;
    }

    if (!recv_message(sockfd, message)) {
        warn("Error while receiving message.");
        return;
    }

    if (message->magic_num != MAGICNUM) {
        return;
    }

    switch (message->message_type) {
        case HEARTBEAT:
            printf("heartbeat received.\n");
            break;
        case UNKNOWN:
            printf("Unknown server message received\n");
        case MESSAGE:
            printf("%s|%s: %s", message->time, message->user, message->content);
            break;
        case ROOMS: case AUDIENCE:
            printf("%s\n", message->content);
            break;
        case USERS:
            if (message->content == NULL || strlen(message->content) == 0) {
                printf("There are no users in the selected room.\n");
            } else {
                printf("%s\n", message->content);
            }
            break;
        case INFO:
            if (message->user != NULL) {
                printf("%s:", message->user);
            }
            printf("%s\n", message->content);
            break;
        case SWITCH:
            printf("Successfully switched to '%s'.\n", message->content);
            free(options->room);
            options->room = strdup(message->content);
            if (options->room == NULL) {
                printf("Out of memory!"); //TODO: nejak vylezt?
            }
            return;
        case PASSWD:
            if (strcmp(message->content, "y") == 0) {
                printf("Password successfully changed.\n");
            } else if (strcmp(message->content, "n") == 0) {
                printf("Password could not be changed.\n");
            } else {
                printf("Unknown server message received\n");
            }
            break;
        case EXIT:
            puts("Server closed the connection.\n");
            close(sockfd);
            exit(EXIT_SUCCESS); //TODO: nejak lepe vylezt?
        case IMG:
            receive_image(message);
            break;
        default:
            break;
    }
    destroy_message(message);
}

static
void net_error(int exit_status, int neterrno)
{
    if (neterrno == EAI_SYSTEM)
        warn("gai error");
    else
        warnx("gai error: %s", gai_strerror(neterrno));

    if (exit_status != 0)
        exit(exit_status);
}

static int connect_server(char *server, struct options options)
{
    struct addrinfo *nodes;
    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
    };

    int ret;
    if ((ret = getaddrinfo(server, options.port, &hints, &nodes)) != 0) {
        freeaddrinfo(nodes);
        net_error(1, ret);
        return -1;
    }

    int sockfd = -1;

    for (struct addrinfo *node = nodes; sockfd == -1 && node != NULL;
         node = node->ai_next) {
        sockfd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if ((ret = connect(sockfd, node->ai_addr, node->ai_addrlen)) != 0) {
            net_error(0, ret);
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(nodes);
    return sockfd;
}

static bool identify(struct options options, int sockfd, char *session_id, char *passwd)
{
    struct message message = { .message_type = LOGIN,
                               .user = options.user,
                               .room = options.room,
                               .content = passwd};

    if (!send_message(sockfd, message)) {
        printf("Could not send login message.");
        return false;
    }

    if (!recv_message(sockfd, &message)) {
        printf("Could not receive login message.");
        return false;
    }

    if (message.content == NULL) {
        printf("Failed to identify - unknown error.");
        return false;
    }

    unsigned long mess_len = strlen(message.content);

    if (mess_len == 2) {
        if (strcmp(message.content, "wp") == 0) {
            printf("Wrong password!\n");
        } else if (strcmp(message.content, "du") == 0) {
            printf("This user is already signed in from another place!\n");
        } else {
            printf("Failed to identify - unknown error.");
        }
        return false;
    }

    if (mess_len != 8) {
        printf("Failed to identify - unknown error.");
        return false;
    }

    strncpy(session_id, message.content, 8);
    session_id[8] = '\0';

    printf("Succesfully logged in!\n");
    return true;
}

int run_client(struct options options, char *host) {
    int sockfd = connect_server(host, options);

    options.room = strdup(options.room);
    if (options.room == NULL) {
        error(0, errno, "strdup");
        return EXIT_FAILURE;
    }

    printf("Password: ");
    char *passwd = NULL;
    size_t passwd_len = 0;
    errno = 0;
    if (getline(&passwd, &passwd_len, stdin) == -1) {
        if (errno != 0) {
            error(0, errno, "reading from stdin");
        }
        error(0, errno, "reading from stdin");
        close(sockfd);
        return EXIT_FAILURE;
    }

    if (strlen(passwd) == 0 || strcmp("\n", passwd) == 0) {
        fprintf(stderr, "Password cannot be empty!\n");
        close(sockfd);
        return EXIT_FAILURE;
    }

    char session_id[9] = "";

    if (!identify(options, sockfd, session_id, passwd)) {
        close(sockfd);
        return EXIT_FAILURE;
    }

    free(passwd);

    struct pollfd fds[2] = {
            {
                fileno(stdin), POLLIN, 0
            },
            {
                sockfd, POLLIN, 0
            }
    };

    int event;
    while ((event = poll(fds, 2, 60000)) > 0) {
        if (fds[0].revents > 0) {
            enum message_type type = stdin_message(options, sockfd, session_id);
            if (type == EXIT) {
                printf("Logging out...\n");
                close(sockfd);
                free(options.room);
                return EXIT_SUCCESS;
            } else if (type == HELP) {
                commands();
            }
        }
        if (fds[1].revents > 0) {
            server_message(sockfd, &options);
        }
    }
    free(options.room);
    if (event == 0) {
        printf("Connection with the server lost.\n");
        close(sockfd);
        return EXIT_FAILURE;
    }
    if (event == -1) {
        close(sockfd);
        error(EXIT_FAILURE, errno, "poll");
    }

    assert(false); //non-reachable
}

//TODO: osetrit ctrl+C
