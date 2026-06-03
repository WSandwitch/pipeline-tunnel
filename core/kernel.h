#ifndef KERNEL_H
#define KERNEL_H

#include <memory>
#include <vector>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <sys/epoll.h>
#include "chain.h"
#include "protocol.h"

struct ChainFdEntry {
    std::shared_ptr<Chain> chain;
    int module_idx;
    std::atomic<bool> pending_in{false};
    std::atomic<bool> pending_out{false};
    std::atomic<uint32_t> current_events{EPOLLIN};

    ChainFdEntry() = default;
    ChainFdEntry(std::shared_ptr<Chain> c, int idx, uint32_t ev = EPOLLIN)
        : chain(std::move(c)), module_idx(idx), current_events(ev) {}
};

class Kernel {
public:
    Kernel();
    ~Kernel();

    // Add a chain to the epoll loop (registers all module in_fds + output fds)
    void add_chain(std::shared_ptr<Chain> chain);

    // Remove chain
    void remove_chain(uint64_t session_id);

    // Register a fd for events (chain-associated, with module index)
    void add_fd(int fd, std::shared_ptr<Chain> chain, int module_idx,
                uint32_t events = EPOLLIN);

    // Register a fd with a callback (non-chain fds like client sockets)
    using EventCallback = std::function<void(int fd, uint32_t events)>;
    void add_fd_handler(int fd, EventCallback callback, uint32_t events = EPOLLIN);

    // Add/remove specific events on a fd without affecting other events
    void mod_fd_events(int fd, uint32_t add, uint32_t remove);

    // Add/remove specific events on a chain fd
    void mod_chain_fd_events(int fd, uint32_t add, uint32_t remove);

    // Remove fd from epoll
    void del_fd(int fd);

    // Temporarily remove/add a chain fd from/to epoll (for module exclusion)
    void del_chain_fd(int fd);
    void add_chain_fd(int fd);

    // Start/stop the event loop
    void start(int thread_count = 4);
    void stop();

    // Queue work for thread pool
    using Task = std::function<void()>;
    void enqueue(Task task);

    // For protocol serialization
    Protocol &protocol() { return proto_; }

private:
    int epoll_fd_ = -1;
    bool running_ = false;

    Protocol proto_;

    // Thread pool
    std::vector<std::thread> workers_;
    std::queue<Task> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    bool stop_pool_ = false;

    // Chain fd lookup (module input fds)
    std::unordered_map<int, ChainFdEntry> fd_to_chain_;

    // Callback-based fd handlers (client sockets, chain output fds, etc.)
    struct FdState {
        EventCallback in_cb;
        EventCallback out_cb;
        uint32_t events = 0;
        std::atomic<bool> pending_in{false};
        std::atomic<bool> pending_out{false};
    };
    std::unordered_map<int, FdState> fd_to_handler_;
    std::mutex handler_mutex_;

    // event loop thread
    std::thread event_thread_;

    void event_loop();
    void worker_loop();
};

#endif
