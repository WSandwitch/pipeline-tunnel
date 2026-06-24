#include "thread_pool.h"
#include "common/utils.h"
#include <cassert>
#include <cstdio>
#include <unistd.h>

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

void ThreadPool::enqueue(WorkTask &&task) {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        queue_.push_back(std::move(task));
        WorkTask &t = queue_.back();
        char buf[256];
        int n = snprintf(buf, sizeof(buf), "[%.6f ENQ POOL dir=%d len=%zu mod=%s]\n",
                         now_sec(), t.task_dir, t.task_len,
                         t.task_mod ? t.task_mod : "?");
        ssize_t r = write(STDERR_FILENO, buf, (size_t)n);
        (void)r;
    }
    cv_.notify_one();
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
            char buf[256];
            int n = snprintf(buf, sizeof(buf), "[%.6f DEQ POOL dir=%d len=%zu mod=%s]\n",
                             now_sec(), task.task_dir, task.task_len,
                             task.task_mod ? task.task_mod : "?");
            ssize_t r = write(STDERR_FILENO, buf, (size_t)n);
            (void)r;
        }
        if (task.fn) {
            try { task.fn(); } catch (...) {}
        }
    }
}
