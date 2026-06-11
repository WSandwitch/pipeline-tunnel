#include "thread_pool.h"
#include <cassert>

ThreadPool::~ThreadPool() {
    stop();
}

void ThreadPool::start(size_t count) {
    if (count == 0) count = 1;
    shutdown_.store(false);
    workers_.reserve(count);
    for (size_t i = 0; i < count; i++) {
        workers_.emplace_back(&ThreadPool::worker_loop, this);
    }
}

void ThreadPool::stop() {
    shutdown_.store(true);
    cv_.notify_all();
    for (auto &w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();
}

size_t ThreadPool::pending() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return queue_.size();
}

void ThreadPool::worker_loop() {
    while (!shutdown_.load()) {
        WorkTask task;
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_.wait(lock, [this] {
                return shutdown_.load() || !queue_.empty();
            });
            if (shutdown_.load()) return;
            task = std::move(queue_.front());
            queue_.pop_front();
            // Transitional lock: order_mutex acquired under queue lock to
            // prevent FIFO reordering; released by fn() after it acquires
            // its own dir_mutex.
            if (task.order_mutex) {
                task.order_mutex->lock();
            }
        }
        if (task.fn) {
            try { task.fn(); } catch (...) {}
        }
        // order_mutex is released by fn() — not here
    }
}
