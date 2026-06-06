#ifndef KERNEL_H
#define KERNEL_H

#include <memory>
#include <vector>
#include <functional>
#include <atomic>
#include <unordered_map>
#include <sys/epoll.h>
#include "protocol.h"

class Kernel {
public:
    Kernel();
    ~Kernel();

    using EventCallback = std::function<void(int fd, uint32_t events)>;
    void add_fd_handler(int fd, EventCallback callback, uint32_t events = EPOLLIN);
    void mod_fd_events(int fd, uint32_t add, uint32_t remove);
    void del_fd(int fd);

    void start();
    void stop();

    static void request_stop();

    Protocol &protocol() { return proto_; }

    void set_tick_callback(std::function<void()> cb) { tick_cb_ = std::move(cb); }

private:
    int epoll_fd_ = -1;
    std::atomic<bool> running_{false};
    static std::atomic<bool> stop_requested_;

    Protocol proto_;

    struct FdState {
        EventCallback in_cb;
        EventCallback out_cb;
        uint32_t events = 0;
    };
    std::unordered_map<int, FdState> fd_to_handler_;

    std::function<void()> tick_cb_;

    void event_loop();
};

#endif
