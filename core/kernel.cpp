#include "kernel.h"
#include "common/logger.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <cstring>
#include <signal.h>

std::atomic<bool> Kernel::stop_requested_{false};

static void sigint_handler(int) {
    Kernel::request_stop();
}

Kernel::Kernel() {
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        log_error("epoll_create1: %s", strerror(errno));
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

Kernel::~Kernel() {
    stop();
    if (epoll_fd_ >= 0)
        close(epoll_fd_);
}

void Kernel::add_fd_handler(int fd, EventCallback callback, uint32_t events) {
    auto &state = fd_to_handler_[fd];
    if (events & EPOLLIN) state.in_cb = callback;
    if (events & EPOLLOUT) state.out_cb = callback;
    state.events |= events;

    struct epoll_event ev;
    ev.events = state.events;
    ev.data.u64 = (uint64_t)fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        if (errno == EEXIST) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
        } else {
            log_error("epoll_ctl add handler fd=%d: %s", fd, strerror(errno));
        }
    }
}

void Kernel::mod_fd_events(int fd, uint32_t add, uint32_t remove) {
    auto hit = fd_to_handler_.find(fd);
    if (hit == fd_to_handler_.end()) return;
    auto &state = hit->second;
    state.events |= add;
    state.events &= ~remove;
    if (state.events == 0 || (!state.in_cb && !state.out_cb)) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        // Keep the fd entry — RESUME may re-add EPOLLIN later
        return;
    }
    struct epoll_event ev;
    ev.events = state.events;
    ev.data.u64 = (uint64_t)fd;
    epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
}

void Kernel::del_fd(int fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    fd_to_handler_.erase(fd);
}

void Kernel::request_stop() {
    stop_requested_.store(true);
}

void Kernel::start() {
    if (running_.exchange(true)) return;
    event_loop();
}

void Kernel::stop() {
    running_.store(false);
    stop_requested_.store(true);
}

void Kernel::event_loop() {
    const int MAX_EVENTS = 64;
    struct epoll_event events[MAX_EVENTS];

    while (running_.load() && !stop_requested_.load()) {
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 50);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_error("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = (int)events[i].data.u64;

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                log_debug("fd=%d hangup/error", fd);
                auto hit = fd_to_handler_.find(fd);
                if (hit != fd_to_handler_.end()) {
                    try {
                        if (hit->second.in_cb)
                            hit->second.in_cb(fd, EPOLLHUP);
                        else if (hit->second.out_cb)
                            hit->second.out_cb(fd, EPOLLHUP);
                    } catch (const std::exception &e) {
                        log_error("exception in hangup handler for fd=%d: %s", fd, e.what());
                    }
                }
                del_fd(fd);
                continue;
            }

            if (events[i].events & EPOLLIN) {
                auto hit = fd_to_handler_.find(fd);
                if (hit != fd_to_handler_.end() && hit->second.in_cb) {
                    try {
                        auto cb = hit->second.in_cb;
                        cb(fd, EPOLLIN);
                    } catch (const std::exception &e) {
                        log_error("exception in EPOLLIN handler for fd=%d: %s", fd, e.what());
                    }
                }
            }

            if (events[i].events & EPOLLOUT) {
                auto hit = fd_to_handler_.find(fd);
                if (hit != fd_to_handler_.end() && hit->second.out_cb) {
                    try {
                        auto cb = hit->second.out_cb;
                        cb(fd, EPOLLOUT);
                    } catch (const std::exception &e) {
                        log_error("exception in EPOLLOUT handler for fd=%d: %s", fd, e.what());
                    }
                }
            }
        }
    }
    running_.store(false);
}
