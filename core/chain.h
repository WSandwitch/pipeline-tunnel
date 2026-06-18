#ifndef CHAIN_H
#define CHAIN_H

#include <memory>
#include <vector>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include "config.h"
#include "kernel_api.h"
#include "module_instance.h"

class ThreadPool;

class Chain {
public:
    Chain(const ChainConfig &cfg, KernelAPI *kapi,
          ThreadPool *pool, std::shared_ptr<void> owner_guard);
    ~Chain();

    bool valid() const { return true; }
    bool is_drained() const { return _inflight.load() == 0; }
    bool is_backpressure_paused(int dir) const { return _backpressure_paused[dir].load(); }
    uint64_t get_max_dir_bytes(int dir) const {
        return _inflight_bytes[dir].load();
    }

    // dir=0 (split/encode), dir=1 (merge/decode)
    using PauseCallback = std::function<void(bool paused)>;
    void set_pause_callback(int dir, PauseCallback cb) { _pause_cb[dir] = std::move(cb); }

    void push_packet(const uint8_t *data, size_t len, int src_idx, int dir);
    void wait_drain();
    void cancel() { _cancelled.store(true); }
    int total_extra_outputs() const;

    static void *get_packet_static(void *chain_ctx, int idx, int *out_size);
    static int   write_packet_static(void *chain_ctx, int dst, const uint8_t *data, size_t len);
    static int   get_node_id_static(void *chain_ctx);
    static int   request_outputs_static(void *chain_ctx, int count);
    static int   get_output_fd_static(void *chain_ctx, int idx);
    static int   request_heartbeat_static(void *chain_ctx, int interval_sec);

    void *get_packet_impl(Module *mod, int idx, int *out_size);
    int   write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len);
    int   request_outputs_impl(Module *mod, int count);
    int   request_heartbeat_impl(Module *mod, int interval_sec);

    void check_module_heartbeats(int system_interval_ms);

    static constexpr uint64_t BACKPRESSURE_HIGH = 1048576; // 1MB
    static constexpr uint64_t BACKPRESSURE_LOW  = 262144;  // 256KB

private:
    KernelAPI *_kapi = nullptr;
    std::vector<std::unique_ptr<Module>> _modules;
    ChainConfig _cfg;
    std::atomic<uint64_t> _inflight_bytes[2]{0, 0};

    Module *_entry_ext = nullptr;           // ext-side copy, entry для dir=0
    std::vector<Module *> _wire_entries;    // [conn_id] → wire-side copy для dir=1

    ThreadPool *_pool = nullptr;
    std::weak_ptr<void> _owner;
    std::atomic<bool> _cancelled{false};
    std::atomic<int> _inflight{0};
    std::mutex _drain_mtx;
    std::condition_variable _drain_cv;
    std::unordered_map<Module*, int> _requested_outputs;  // заполняется при init, очищается после построения
    std::mutex nogap_mutex_[2];

    PauseCallback _pause_cb[2];  // pause/resume callbacks per direction
    std::atomic<bool> _backpressure_paused[2] = {false, false};  // track per-direction pause state

    void task_done();
    void enqueue_module(Module *mod, const uint8_t *data, size_t len,
                        int src_idx, int dir);
    void check_backpressure(int dir);
};

#endif
