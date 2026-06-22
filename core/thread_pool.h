#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <functional>
#include <atomic>
#include <vector>
#include <cstddef>
#include <cstdint>

struct WorkTask {
    std::function<void()> fn;
    int task_dir = -1;
    size_t task_len = 0;
    const char *task_mod = nullptr;
    WorkTask() = default;
};

class ThreadPool {
public:
    ThreadPool() = default;
    ~ThreadPool();

    void start(size_t count);
    void stop();

    void enqueue(WorkTask &&task);

    size_t pending() const;

private:
    std::vector<std::thread> workers_;
    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::deque<WorkTask> queue_;
    std::atomic<bool> shutdown_{false};

    void worker_loop();
};

#endif
