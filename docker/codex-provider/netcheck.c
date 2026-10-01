#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void timeout_handler(int signal_number) {
    (void)signal_number;
    _exit(2);
}

int main(int argc, char **argv) {
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    struct addrinfo *address = NULL;
    int connected = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: ralph-netcheck HOST PORT\n");
        return 2;
    }

    signal(SIGALRM, timeout_handler);
    alarm(5);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(argv[1], argv[2], &hints, &addresses) != 0) {
        return 1;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        int socket_fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }
        if (connect(socket_fd, address->ai_addr, address->ai_addrlen) == 0) {
            connected = 0;
            close(socket_fd);
            break;
        }
        close(socket_fd);
    }
    freeaddrinfo(addresses);
    return connected;
}
