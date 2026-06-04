#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static double now_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: echo_cli HOST PORT TOTAL_BYTES [CHUNK]\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    const char *host = argv[1];
    int port = atoi(argv[2]);
    long total = atol(argv[3]);
    int chunk = (argc > 4) ? atoi(argv[4]) : 262144;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return 1;
    }

    char *sbuf = malloc(chunk);
    char *rbuf = malloc(chunk);
    memset(sbuf, 'x', chunk);

    long to_send = total;
    long recvd = 0;
    double t0 = now_sec();
    int idle = 0;

    while (to_send > 0 || recvd < total) {
        struct pollfd pfd = {.fd = fd, .events = 0};
        if (to_send > 0) pfd.events |= POLLOUT;
        if (recvd < total) pfd.events |= POLLIN;

        int r = poll(&pfd, 1, 5000);
        if (r < 0) { perror("poll"); return 1; }
        if (r == 0) {
            idle++;
            fprintf(stderr, "poll timeout (to_send=%ld recvd=%ld)\n", to_send, recvd);
            if (idle > 10) { fprintf(stderr, "too many idle\n"); return 1; }
            continue;
        }
        idle = 0;

        if (pfd.revents & POLLHUP) { fprintf(stderr, "POLLHUP\n"); }
        if (pfd.revents & POLLERR) { fprintf(stderr, "POLLERR\n"); }
        if (pfd.revents & POLLNVAL) { fprintf(stderr, "POLLNVAL\n"); }

        if ((pfd.revents & POLLOUT) && to_send > 0) {
            int this = (to_send > chunk) ? chunk : (int)to_send;
            int n = write(fd, sbuf, this);
            if (n < 0) { perror("write"); return 1; }
            to_send -= n;
        }

        if ((pfd.revents & POLLIN) && recvd < total) {
            int max_read = (total - recvd > chunk) ? chunk : (int)(total - recvd);
            int n = read(fd, rbuf, max_read);
            fprintf(stderr, "read %d (errno=%d)\n", n, errno);
            if (n <= 0) {
                fprintf(stderr, "short recv at %ld/%ld\n", recvd, total);
                return 1;
            }
            recvd += n;
        }

        if ((pfd.revents & (POLLHUP | POLLERR)) && !(pfd.revents & POLLIN)) {
            if (recvd < total) {
                fprintf(stderr, "err/hup at %ld/%ld\n", recvd, total);
                return 1;
            }
            break;
        }
    }
    double elapsed = now_sec() - t0;

    close(fd);
    free(sbuf);
    free(rbuf);

    double mbps = total / elapsed / 1e6;
    printf("%.2f\n", mbps);
    return 0;
}
