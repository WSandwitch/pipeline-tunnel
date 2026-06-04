#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    int fd;
} conn_t;

static void *echo_thread(void *arg) {
    conn_t *c = (conn_t *)arg;
    int fd = c->fd;
    free(c);
    char buf[65536];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(fd, buf + off, n - off);
            if (w <= 0) goto done;
            off += w;
        }
    }
done:
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: echo_srv PORT\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);

    int port = atoi(argv[1]);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(ls, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(ls, 16) < 0) {
        perror("listen"); return 1;
    }

    while (1) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(ls, (struct sockaddr*)&peer, &plen);
        if (fd < 0) { perror("accept"); continue; }
        conn_t *c = malloc(sizeof(conn_t));
        c->fd = fd;
        pthread_t th;
        pthread_create(&th, NULL, echo_thread, c);
        pthread_detach(th);
    }
    close(ls);
    return 0;
}
