#include "kernel.h"
#include "common/logger.h"
#include <sys/epoll.h>
#include <sys/eventfd.h>
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
    wake_fd_ = eventfd(0, EFD_NONBLOCK);
    if (wake_fd_ < 0) {
        log_error("eventfd: %s", strerror(errno));
    } else {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.u64 = (uint64_t)wake_fd_;
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, wake_fd_, &ev) < 0) {
            log_error("epoll_ctl add wake_fd: %s", strerror(errno));
        }
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

Kernel::~Kernel() {
    stop();
    if (wake_fd_ >= 0)
        close(wake_fd_);
    if (epoll_fd_ >= 0)
        close(epoll_fd_);
}

void Kernel::wakeup() {
    if (wake_fd_ >= 0) {
        uint64_t val = 1;
        ::write(wake_fd_, &val, sizeof(val));
    }
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
    bool was_empty = (state.events == 0);
    state.events |= add;
    state.events &= ~remove;
    if (state.events == 0 || (!state.in_cb && !state.out_cb)) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        return;
    }
    struct epoll_event ev;
    ev.events = state.events;
    ev.data.u64 = (uint64_t)fd;
    if (was_empty) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
    } else {
        epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
    }
}

void Kernel::del_fd(int fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    fd_to_handler_.erase(fd);
}

void Kernel::start_workers(size_t count) {
    pool_.start(count);
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
    pool_.stop();
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

        if (tick_cb_) {
            try { tick_cb_(); } catch (const std::exception &e) {
                log_error("exception in tick callback: %s", e.what());
            }
        }


        for (int i = 0; i < nfds; i++) {
            int fd = (int)events[i].data.u64;
            uint32_t e = events[i].events;

            // Consume eventfd wakeup
            if (fd == wake_fd_) {
                uint64_t val;
                while (::read(wake_fd_, &val, sizeof(val)) > 0) {}
                continue;
            }

            // Process EPOLLIN first to drain data before handling hangup
            if (e & EPOLLIN) {
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

            if (e & EPOLLOUT) {
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

            if (e & (EPOLLERR | EPOLLHUP)) {
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
            }
        }
    }
    running_.store(false);
}
