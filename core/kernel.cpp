#include "kernel.h"
#include "common/logger.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <cstring>
#include <execinfo.h>

// Uncomment DEBUG_KERNEL for verbose stderr tracing
////#define DEBUG_KERNEL
#ifdef DEBUG_KERNEL
#define kernel_trace(...) fprintf(stderr, __VA_ARGS__)
#else
#define kernel_trace(...) do {} while(0)
#endif

Kernel::Kernel() {
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        log_error("epoll_create1: %s", strerror(errno));
    }
}

Kernel::~Kernel() {
    stop();
    if (epoll_fd_ >= 0)
        close(epoll_fd_);
}

void Kernel::add_fd(int fd, std::shared_ptr<Chain> chain, int module_idx,
                    uint32_t events) {
    fd_to_chain_.try_emplace(fd, std::move(chain), module_idx, events);

    struct epoll_event ev;
    ev.events = events;
    ev.data.u64 = (uint64_t)fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
        if (errno == EEXIST) {
            epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
        } else {
            log_error("epoll_ctl add fd=%d: %s", fd, strerror(errno));
        }
    }
}

void Kernel::add_fd_handler(int fd, EventCallback callback, uint32_t events) {
    uint32_t new_events;
    {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        auto &state = fd_to_handler_[fd];
        // Store callback per event type — if already registered for other events,
        // merge rather than replace
        if (events & EPOLLIN) {
            state.in_cb = callback;
            kernel_trace( "[KERNEL-REG] fd=%d registered IN_CB\n", fd);
            fflush(stderr);
        }
        if (events & EPOLLOUT) {
            state.out_cb = callback;
            kernel_trace( "[KERNEL-REG] fd=%d registered OUT_CB\n", fd);
            fflush(stderr);
        }
        state.events |= events;
        new_events = state.events;
    }
    struct epoll_event ev;
    ev.events = new_events;
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
    std::lock_guard<std::mutex> lock(handler_mutex_);
    auto hit = fd_to_handler_.find(fd);
    if (hit == fd_to_handler_.end()) return;
    auto &state = hit->second;
    state.events |= add;
    state.events &= ~remove;
    if (!state.in_cb && !state.out_cb) {
        // No callbacks left — clean up entirely
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        fd_to_handler_.erase(hit);
        return;
    }
    if (state.events == 0) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        return;
    }
    struct epoll_event ev;
    ev.events = state.events;
    ev.data.u64 = (uint64_t)fd;
    epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
}

void Kernel::mod_chain_fd_events(int fd, uint32_t add, uint32_t remove) {
    auto it = fd_to_chain_.find(fd);
    if (it == fd_to_chain_.end()) return;
    uint32_t new_events = (it->second.current_events | add) & ~remove;
    it->second.current_events = new_events;
    struct epoll_event ev;
    ev.events = new_events;
    ev.data.u64 = (uint64_t)fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) < 0 && errno == ENOENT) {
        epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
    }
}

void Kernel::del_fd(int fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    {
        std::lock_guard<std::mutex> lock(handler_mutex_);
        fd_to_handler_.erase(fd);
    }
    fd_to_chain_.erase(fd);
}

void Kernel::del_chain_fd(int fd) {
    epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
}

void Kernel::add_chain_fd(int fd) {
    auto it = fd_to_chain_.find(fd);
    if (it == fd_to_chain_.end()) return;
    it->second.pending_in.store(false);
    uint32_t events = it->second.current_events;
    if (events == 0) return;
    struct epoll_event ev;
    ev.events = events;
    ev.data.u64 = (uint64_t)fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0)
        if (errno == EEXIST)
            epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
}

void Kernel::enqueue(Task task) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tasks_.push(std::move(task));
    }
    cv_.notify_one();
}

void Kernel::add_chain(std::shared_ptr<Chain> chain) {
    // Module fds are registered individually by the session via add_fd.
    // Output fds are registered via add_fd_handler.
    log_info("add_chain: chain %llx ready",
             (unsigned long long)chain->session_id());
}

void Kernel::remove_chain(uint64_t session_id) {
    for (auto it = fd_to_chain_.begin(); it != fd_to_chain_.end(); ) {
        if (it->second.chain->session_id() == session_id) {
            del_fd(it->first);
            it = fd_to_chain_.erase(it);
        } else {
            ++it;
        }
    }
}

void Kernel::start(int thread_count) {
    if (running_) return;
    running_ = true;

    stop_pool_ = false;
    for (int i = 0; i < thread_count; i++) {
        workers_.emplace_back([this] { worker_loop(); });
    }

    event_thread_ = std::thread([this] { event_loop(); });

    log_info("kernel started: %d workers", thread_count);
}

void Kernel::stop() {
    if (!running_) return;
    running_ = false;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        stop_pool_ = true;
    }
    cv_.notify_all();

    if (event_thread_.joinable())
        event_thread_.join();

    for (auto &w : workers_)
        if (w.joinable())
            w.join();

    workers_.clear();
    log_info("kernel stopped");
}

void Kernel::worker_loop() {
    while (true) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_.wait(lock, [this] { return stop_pool_ || !tasks_.empty(); });
            if (stop_pool_ && tasks_.empty())
                return;
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        try {
            task();
        } catch (const std::exception &e) {
            log_error("worker task exception: %s", e.what());
            kernel_trace( "[DBG] worker exception: %s\n", e.what());
            kernel_trace( "[DBG] BACKTRACE:\n");
            void *bt[32];
            int n = backtrace(bt, 32);
            char **syms = backtrace_symbols(bt, n);
            for (int i = 0; i < n; i++)
                kernel_trace( "  %s\n", syms[i]);
            free(syms);
            fflush(stderr);
        } catch (...) {
            log_error("worker task unknown exception");
        }
    }
}

void Kernel::event_loop() {
    const int MAX_EVENTS = 64;
    struct epoll_event events[MAX_EVENTS];

    while (running_) {
        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS, 50);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            log_error("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = (int)events[i].data.u64;
            kernel_trace( "[event] fd=%d events=%s%s%s\n", fd,
                    events[i].events & EPOLLIN ? "IN" : "",
                    events[i].events & EPOLLOUT ? "|OUT" : "",
                    events[i].events & EPOLLHUP ? "|HUP" : "");

            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                log_debug("fd=%d hangup/error", fd);
                // Notify handler
                {
                    std::lock_guard<std::mutex> lock(handler_mutex_);
                    auto hit = fd_to_handler_.find(fd);
                    if (hit != fd_to_handler_.end()) {
                        if (hit->second.in_cb)
                            enqueue([cb = hit->second.in_cb, fd] { kernel_trace( "[TASK=HUP_IN] fd=%d\n", fd); fflush(stderr); cb(fd, EPOLLHUP); });
                        else if (hit->second.out_cb)
                            enqueue([cb = hit->second.out_cb, fd] { kernel_trace( "[TASK=HUP_OUT] fd=%d\n", fd); fflush(stderr); cb(fd, EPOLLHUP); });
                    }
                }
                del_fd(fd);
                continue;
            }

            if (events[i].events & EPOLLIN) {
                // Check callback-based handlers first
                EventCallback cb;
                bool is_chain = false;
                int mod_idx = 0;
                std::shared_ptr<Chain> chain;
                {
                    std::lock_guard<std::mutex> lock(handler_mutex_);
                    auto hit = fd_to_handler_.find(fd);
                    if (hit != fd_to_handler_.end()) {
                        bool was_pending = hit->second.pending_in.exchange(true);
                        if (!was_pending) {
                            cb = hit->second.in_cb;
                        }
                        kernel_trace( "[DBG-IN] fd=%d was_pending=%d has_cb=%d\n", fd,
                                was_pending, hit->second.in_cb ? 1 : 0);
                        fflush(stderr);
                    } else {
                        auto it = fd_to_chain_.find(fd);
                        if (it != fd_to_chain_.end()) {
                            if (!it->second.pending_in.exchange(true)) {
                                is_chain = true;
                                chain = it->second.chain;
                                mod_idx = it->second.module_idx;
                            }
                        }
                    }
                }
                if (cb) {
                    enqueue([this, fd, cb] {
                        kernel_trace( "[TASK=IN] fd=%d\n", fd); fflush(stderr);
                        try {
                            cb(fd, EPOLLIN);
                        } catch (const std::exception &e) {
                            kernel_trace( "[DBG] TASK=IN caught: fd=%d %s\n", fd, e.what()); fflush(stderr);
                        } catch (...) {
                            kernel_trace( "[DBG] TASK=IN caught unknown fd=%d\n", fd); fflush(stderr);
                        }
                        std::lock_guard<std::mutex> lock(handler_mutex_);
                        auto it = fd_to_handler_.find(fd);
                        if (it != fd_to_handler_.end())
                            it->second.pending_in.store(false);
                    });
                }
                if (is_chain) {
                    enqueue([this, chain = std::move(chain), fd] {
                        kernel_trace( "[TASK=CHAIN] fd=%d\n", fd); fflush(stderr);
                        try {
                            chain->on_fd_ready(fd);
                        } catch (const std::exception &e) {
                            kernel_trace( "[DBG] TASK=CHAIN caught: fd=%d %s\n", fd, e.what()); fflush(stderr);
                        } catch (...) {
                            kernel_trace( "[DBG] TASK=CHAIN caught unknown fd=%d\n", fd); fflush(stderr);
                        }
                        auto it = fd_to_chain_.find(fd);
                        if (it != fd_to_chain_.end())
                            it->second.pending_in.store(false);
                    });
                }
            }

            if (events[i].events & EPOLLOUT) {
                EventCallback cb;
                bool is_chain_out = false;
                std::shared_ptr<Chain> out_chain;
                {
                    std::lock_guard<std::mutex> lock(handler_mutex_);
                    auto hit = fd_to_handler_.find(fd);
                    if (hit != fd_to_handler_.end()) {
                        if (!hit->second.pending_out.exchange(true)) {
                            cb = hit->second.out_cb;
                        }
                    } else {
                        auto it = fd_to_chain_.find(fd);
                        if (it != fd_to_chain_.end()) {
                            if (!it->second.pending_out.exchange(true)) {
                                is_chain_out = true;
                                out_chain = it->second.chain;
                            }
                        }
                    }
                }
                if (cb) {
                    enqueue([this, fd, cb] {
                        kernel_trace( "[TASK=OUT] fd=%d\n", fd); fflush(stderr);
                        try {
                            cb(fd, EPOLLOUT);
                        } catch (const std::exception &e) {
                            kernel_trace( "[DBG] TASK=OUT caught: fd=%d %s\n", fd, e.what()); fflush(stderr);
                        } catch (...) {
                            kernel_trace( "[DBG] TASK=OUT caught unknown fd=%d\n", fd); fflush(stderr);
                        }
                        std::lock_guard<std::mutex> lock(handler_mutex_);
                        auto it = fd_to_handler_.find(fd);
                        if (it != fd_to_handler_.end())
                            it->second.pending_out.store(false);
                    });
                }
                if (is_chain_out) {
                    enqueue([this, chain = std::move(out_chain), fd] {
                        kernel_trace( "[TASK=CHAIN-OUT] fd=%d\n", fd); fflush(stderr);
                        try {
                            chain->on_fd_write_ready(fd);
                        } catch (const std::exception &e) {
                            kernel_trace( "[DBG] TASK=CHAIN-OUT caught: fd=%d %s\n", fd, e.what()); fflush(stderr);
                        } catch (...) {
                            kernel_trace( "[DBG] TASK=CHAIN-OUT caught unknown fd=%d\n", fd); fflush(stderr);
                        }
                        auto it = fd_to_chain_.find(fd);
                        if (it != fd_to_chain_.end())
                            it->second.pending_out.store(false);
                    });
                }
            }
        }
    }
}
