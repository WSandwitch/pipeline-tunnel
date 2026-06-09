#ifndef CHAIN_H
#define CHAIN_H

#include <memory>
#include <vector>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "config.h"
#include "kernel_api.h"
#include "module_instance.h"

class ThreadPool;

class Chain {
public:
    Chain(const ChainConfig &cfg, KernelAPI *kapi,
          ThreadPool *pool, std::shared_ptr<void> owner_guard);
    ~Chain();

    bool valid() const { return !_modules.empty(); }
    bool is_drained() const { return _inflight.load() == 0; }
    void push_packet(const uint8_t *data, size_t len, int src_idx, int dir);
    void wait_drain();
    void cancel() { _cancelled.store(true); }

    static void *get_packet_static(void *chain_ctx, int idx, int *out_size);
    static int   write_packet_static(void *chain_ctx, int dst, const uint8_t *data, size_t len);
    static int   get_node_id_static(void *chain_ctx);

    void *get_packet_impl(Module *mod, int idx, int *out_size);
    int   write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len);

private:
    KernelAPI *_kapi = nullptr;
    std::vector<std::unique_ptr<Module>> _modules;

    ThreadPool *_pool = nullptr;
    std::weak_ptr<void> _owner;
    std::atomic<bool> _cancelled{false};
    std::atomic<int> _inflight{0};
    std::mutex _drain_mtx;
    std::condition_variable _drain_cv;

    void task_done();
};

#endif
