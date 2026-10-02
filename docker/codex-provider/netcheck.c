#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void timeout_handler(int signal_number) {
    (void)signal_number;
    _exit(2);
}

static int denial_errno(int error_number) {
    return error_number == EACCES || error_number == EPERM ||
           error_number == ENETUNREACH || error_number == EHOSTUNREACH ||
           error_number == ENETDOWN || error_number == EAFNOSUPPORT ||
           error_number == EPROTONOSUPPORT;
}

static int prove_socket_denied(int family, int socket_type) {
    int socket_fd = socket(family, socket_type, 0);
    if (socket_fd < 0) {
        return denial_errno(errno) ? 0 : 2;
    }
    if (fcntl(socket_fd, F_SETFL, O_NONBLOCK) < 0) {
        close(socket_fd);
        return 2;
    }
    int result;
    if (family == AF_INET) {
        struct sockaddr_in target = {0};
        target.sin_family = AF_INET;
        target.sin_port = htons(9);
        if (inet_pton(AF_INET, "192.0.2.1", &target.sin_addr) != 1) {
            close(socket_fd);
            return 2;
        }
        result = connect(socket_fd, (struct sockaddr *)&target, sizeof(target));
    } else {
        struct sockaddr_in6 target = {0};
        target.sin6_family = AF_INET6;
        target.sin6_port = htons(9);
        if (inet_pton(AF_INET6, "2001:db8::1", &target.sin6_addr) != 1) {
            close(socket_fd);
            return 2;
        }
        result = connect(socket_fd, (struct sockaddr *)&target, sizeof(target));
    }
    int error_number = errno;
    close(socket_fd);
    if (result == 0 || error_number == EINPROGRESS || error_number == EALREADY ||
        error_number == EWOULDBLOCK) {
        return 1;
    }
    return denial_errno(error_number) ? 0 : 2;
}

int main(int argc, char **argv) {
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    struct addrinfo *address = NULL;
    int connected = 1;

    if (argc == 2 && strcmp(argv[1], "--prove-denied") == 0) {
        const int families[] = {AF_INET, AF_INET6};
        const int socket_types[] = {SOCK_STREAM, SOCK_DGRAM};
        for (size_t family_index = 0; family_index < 2; family_index++) {
            for (size_t type_index = 0; type_index < 2; type_index++) {
                int outcome = prove_socket_denied(
                    families[family_index], socket_types[type_index]
                );
                if (outcome != 0) {
                    return outcome;
                }
            }
        }
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: ralph-netcheck HOST PORT | --prove-denied\n");
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
