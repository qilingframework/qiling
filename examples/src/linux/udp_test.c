#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// reference: https://gist.github.com/saxbophone/f770e86ceff9d488396c0c32d47b757e

#define PORT_DEFAULT  "22033"

static int socket_server(const char *host, const char *port)
{
    int ret, opt, sockfd;
    struct addrinfo hints, *result, *rp;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    ret = getaddrinfo(host, port, &hints, &result);
    if (ret) {
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }
        opt = 1;
        ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
        if (ret == -1) {
            close(sockfd);
            continue;
        }
        ret = bind(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0){
            break;
        }
        /* else close sockfd and continue the loop */
        close(sockfd);
    }
    if (rp == NULL) {
        sockfd = -1;
    }
    freeaddrinfo(result);

    return sockfd;
}

static int socket_client(const char *host, const char *port)
{
    int ret, sockfd;
    struct addrinfo hints, *result, *rp;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    ret = getaddrinfo(host, port, &hints, &result);
    if (ret) {
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }
        ret = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            break;
        }
        /* else close sockfd and continue the loop */
        close(sockfd);
    }
    if (rp == NULL) {
        sockfd = -1;
    }
    freeaddrinfo(result);

    return sockfd;
}

static int process_server(const char *port)
{
    int ret;
    int sockfd;
    int len;
    char buf[256];
    struct sockaddr_storage peer_addr;
    int peer_addr_len;

    for(;;) {
        sockfd = socket_server("127.0.0.1", port);
        if (sockfd == -1) {
            fprintf(stderr, "server port %s error.\n", port);
            return 1;
        }
        for(;;) {
            peer_addr_len = sizeof(struct sockaddr_storage);
            len = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *) &peer_addr, &peer_addr_len);
            fprintf(stderr, "server recvfrom() return %d.\n", len);
            if (len <= 0) {
                fprintf(stderr, "recvfrom %d error.\n", len);
                close(sockfd);
                return 1;
            } else {
                /* echo */
                ret = sendto(sockfd, buf, len, 0, (struct sockaddr *) &peer_addr, peer_addr_len);
                fprintf(stderr, "server sendto() %d return %d.\n", len, ret);
                if (ret != len) {
                    close(sockfd);
                    return 1;
                }
            }
            break;
        }
        close(sockfd);
        break;
    }

    return 0;
}

static int process_client(const char *port)
{
    int ret;
    int sockfd;
    int len;
    char buf[256];

    /* wait server */
    sleep(2);
    for(;;) {
        sockfd = socket_client("127.0.0.1", port);
        if (sockfd == -1) {
            fprintf(stderr, "connect port %s error.\n", port);
            return 1;
        }
        for(;;) {
            ret = write(sockfd, "hello, world.\n", 14);
            if (ret != 14) {
                fprintf(stderr, "--- client write() %d return %d, close %d.\n", 14, ret, sockfd);
                close(sockfd);
                return 1;
            }

            len = read(sockfd, buf, sizeof(buf));
            fprintf(stderr, "client read() return %d.\n", len);
            if (len <= 0) {
                close(sockfd);
                return 1;
            }
            break;
        }
        close(sockfd);
        break;
    }

    return 0;
}



int main(int argc, const char **argv)
{
    pid_t pid;
    const char *port;

    if (argc < 2) {
        port = PORT_DEFAULT;
    } else {
        port = argv[1];
    }
    fprintf(stderr, "port is %s.\n", port);

    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "fork() error.\n");
        exit(1);
    } else if (pid == 0) {
        /* child process */
        process_client(port);
    } else {
        /* parent process */
        process_server(port);
    }

    return 0;
}
