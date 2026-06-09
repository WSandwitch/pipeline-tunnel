#include "listener.h"
#include "common/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

Listener::Listener(const std::string &addr, uint16_t port)
    : addr_(addr), port_(port) {}

Listener::~Listener() {
    if (fd_ >= 0) close(fd_);
}

bool Listener::start() {
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
        log_error("listener socket: %s", strerror(errno));
        return false;
    }

    int opt = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    inet_pton(AF_INET, addr_.c_str(), &addr.sin_addr);

    if (bind(fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("listener bind %s:%d: %s", addr_.c_str(), port_, strerror(errno));
        return false;
    }

    if (listen(fd_, 16) < 0) {
        log_error("listener listen: %s", strerror(errno));
        return false;
    }

    log_info("listener started on %s:%d", addr_.c_str(), port_);
    return true;
}
