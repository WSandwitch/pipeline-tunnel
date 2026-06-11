#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <functional>
#include <atomic>
#include <vector>

struct WorkTask {
    std::function<void()> fn;
    std::mutex *order_mutex = nullptr;
    WorkTask() = default;
    template<typename F> WorkTask(F &&f) : fn(std::forward<F>(f)) {}
};

class ThreadPool {
public:
    ThreadPool() = default;
    ~ThreadPool();

    void start(size_t count);
    void stop();

    template<typename F>
    void enqueue(F &&f) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            queue_.push_back(WorkTask(std::forward<F>(f)));
        }
        cv_.notify_one();
    }

    template<typename F>
    void enqueue(F &&f, std::mutex *order_mutex) {
        WorkTask task(std::forward<F>(f));
        task.order_mutex = order_mutex;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            queue_.push_back(std::move(task));
        }
        cv_.notify_one();
    }

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
