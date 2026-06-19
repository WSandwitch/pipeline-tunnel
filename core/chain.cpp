#include "chain.h"
#include "thread_pool.h"
#include "common/logger.h"
#include "common/utils.h"
#include <deque>
#include <sys/syscall.h>
#include <unistd.h>
static pid_t my_gettid() { return (pid_t)syscall(SYS_gettid); }

Chain::Chain(const ChainConfig &cfg, KernelAPI *kapi,
             ThreadPool *pool, std::shared_ptr<void> owner_guard)
    : _kapi(kapi), _pool(pool), _owner(owner_guard), _cfg(cfg)
{
    auto create_one = [&](const ModuleSpec &spec, size_t cidx) -> std::unique_ptr<Module> {
        auto base = ModuleBase::find(spec.name);
        if (!base) {
            log_error("chain: module '%s' not found", spec.name.c_str());
            return nullptr;
        }
        auto mod = std::make_unique<Module>();
        mod->base = const_cast<ModuleBase *>(base);
        mod->chain = this;
        mod->id = _kapi->alloc_module_id(_kapi->ctx);
        mod->cfg_idx = cidx;
        mod->near = {nullptr, nullptr};

        mod->api.ctx = mod.get();
        mod->api.request_outputs = &Chain::request_outputs_static;
        mod->api.get_output_fd = &Chain::get_output_fd_static;
        mod->api.get_node_id = &Chain::get_node_id_static;
        mod->api.get_packet = &Chain::get_packet_static;
        mod->api.write_packet = &Chain::write_packet_static;
        mod->api.request_heartbeat = &Chain::request_heartbeat_static;

        mod->ctx = base->init_fn(&mod->api, spec.params.c_str());
        if (!mod->ctx) {
            log_error("chain: module '%s' init failed", spec.name.c_str());
            return nullptr;
        }
        mod->last_activity = std::chrono::steady_clock::now();
        log_debug("chain: module '%s' initialized (id=%d, cfg_idx=%zu)",
                  spec.name.c_str(), mod->id, cidx);
        return mod;
    };

    // Phase 1: main chain (deque for stable pointers during construction)
    std::deque<std::unique_ptr<Module>> build;
    for (size_t i = 0; i < cfg.modules.size(); i++) {
        auto m = create_one(cfg.modules[i], i);
        if (!m) return;
        build.push_back(std::move(m));
    }
    if (build.empty()) return;

    // Link near for main chain
    for (size_t i = 0; i < build.size(); i++) {
        Module *prev = i > 0 ? build[i-1].get() : nullptr;
        Module *next = i + 1 < build.size() ? build[i+1].get() : nullptr;
        build[i]->near = {prev, next};
    }

    // Entry points
    _entry_ext = build[0].get();
    _wire_entries.push_back(nullptr);
    _wire_entries.push_back(build.back().get());
    _entry_ext->wire_dst = 0;
    build.back()->wire_dst = 1;

    // Phase 2: iterative sub-chains
    int next_port = 2;

    while (!_requested_outputs.empty()) {
        auto pending = std::move(_requested_outputs);
        _requested_outputs.clear();

        for (auto &[mod, count] : pending) {
            size_t mc = mod->cfg_idx;
            if (mc == SIZE_MAX || mc + 1 >= cfg.modules.size()) continue;

            mod->near.resize(2 + count);

            for (int k = 1; k <= count; k++) {
                Module *prev_mod = mod;
                Module *first_sub = nullptr;

                for (size_t ri = mc + 1; ri < cfg.modules.size(); ri++) {
                    auto um = create_one(cfg.modules[ri], ri);
                    if (!um) { _modules.clear(); return; }

                    Module *mp = um.get();
                    mp->near[0] = prev_mod;
                    if (prev_mod != mod) prev_mod->near[1] = mp;
                    if (!first_sub) first_sub = mp;
                    prev_mod = mp;
                    build.push_back(std::move(um));
                }

                int port = next_port++;
                prev_mod->wire_dst = port;
                if ((size_t)port >= _wire_entries.size())
                    _wire_entries.resize(port + 1);
                _wire_entries[port] = prev_mod;
                mod->near[1 + k] = first_sub;
            }
        }
    }

    // Phase 3: move to vector
    _modules.reserve(build.size());
    for (auto &m : build)
        _modules.push_back(std::move(m));
}

Chain::~Chain() {
    cancel();
    wait_drain();
}

struct ChainContext {
    const uint8_t *data = nullptr;
    size_t len = 0;
    int src_idx = 0;
    int dir = 0;
};

thread_local ChainContext g_ctx;

void Chain::push_packet(const uint8_t *data, size_t len, int src_idx, int dir) {
    if (_cancelled.load()) {
        free(const_cast<uint8_t*>(data));
        return;
    }
    if (!_entry_ext) {
        if (dir == 0)
            _kapi->wire_write(_kapi->ctx, 1, data, len);
        else
            _kapi->wire_write(_kapi->ctx, 0, data, len);
        return;
    }
    if (!_owner.lock()) {
        free(const_cast<uint8_t*>(data));
        return;
    }

    Module *first;
    if (dir == 0) {
        first = _entry_ext;
    } else {
        if (src_idx < 0 || (size_t)src_idx >= _wire_entries.size()) {
            log_error("chain: src_idx=%d out of range (%zu entries)",
                      src_idx, _wire_entries.size());
            free(const_cast<uint8_t*>(data));
            abort();
        }
        first = _wire_entries[src_idx];
    }
    enqueue_module(first, data, len, src_idx, dir);
}

void Chain::enqueue_module(Module *mod, const uint8_t *data, size_t len,
                           int src_idx, int dir) {
    auto owner = _owner.lock();
    if (!owner) {
        free(const_cast<uint8_t*>(data));
        return;
    }

    _inflight.fetch_add(1);
    _inflight_bytes[dir].fetch_add(len);
    check_backpressure(dir);

    _pool->enqueue([this, data, len, src_idx, dir, mod, owner]() {
        nogap_mutex_[dir].lock();

        if (_cancelled.load()) {
            nogap_mutex_[dir].unlock();
            _inflight_bytes[dir].fetch_sub(len);
            check_backpressure(dir);
            free(const_cast<uint8_t*>(data));
            task_done();
            return;
        }

        g_ctx = ChainContext{data, len, src_idx, dir};

        {
            std::lock_guard<std::mutex> lock(mod->hb_mutex);
            mod->last_activity = std::chrono::steady_clock::now();
        }

        std::lock_guard<std::mutex> lock(mod->dir_mutex[dir]);
        nogap_mutex_[dir].unlock();

        TRACE("CHAIN WRITE_PACKET_IMPL entering dir=%d src=%d len=%zu mod=%s",
              dir, src_idx, len, mod->base ? mod->base->name.c_str() : "?");
        int ret = mod->base->process_fn(mod->ctx, dir, src_idx);
        TRACE("CHAIN WRITE_PACKET_IMPL done dir=%d ret=%d", dir, ret);

        _inflight_bytes[dir].fetch_sub(len);
        check_backpressure(dir);

        if (ret < 0) {
            task_done();
            return;
        }

        task_done();
    });
}

void Chain::task_done() {
    if (_inflight.fetch_sub(1) == 1) {
        std::lock_guard<std::mutex> lock(_drain_mtx);
        _drain_cv.notify_all();
    }
}

void Chain::check_backpressure(int dir) {
    uint64_t bytes = _inflight_bytes[dir].load();

    if (bytes > BACKPRESSURE_HIGH && !_backpressure_paused[dir].load()) {
        _backpressure_paused[dir].store(true);
        TRACE("CHAIN BP PAUSE dir=%d bytes=%zu inflight=%d", dir, (size_t)bytes, _inflight.load());
        if (_pause_cb[dir]) _pause_cb[dir](true);
    }
    if (bytes <= BACKPRESSURE_LOW && _backpressure_paused[dir].load()) {
        _backpressure_paused[dir].store(false);
        TRACE("CHAIN BP RESUME dir=%d bytes=%zu inflight=%d", dir, (size_t)bytes, _inflight.load());
        if (_pause_cb[dir]) _pause_cb[dir](false);
    }
}

void Chain::wait_drain() {
    std::unique_lock<std::mutex> lock(_drain_mtx);
    _drain_cv.wait(lock, [this] { return _inflight.load() == 0; });
}

int Chain::total_extra_outputs() const {
    // _wire_entries[0] = nullptr (unused), [1] = primary wire module, [2+] = extra split outputs
    if (_wire_entries.size() < 2) return 0;
    return (int)(_wire_entries.size() - 2);
}

// --- static API stubs ---

void *Chain::get_packet_static(void *chain_ctx, int idx, int *out_size) {
    auto *mod = (Module *)chain_ctx;
    return mod->chain->get_packet_impl(mod, idx, out_size);
}

int Chain::write_packet_static(void *chain_ctx, int dst, const uint8_t *data, size_t len) {
    auto *mod = (Module *)chain_ctx;
    return mod->chain->write_packet_impl(mod, dst, data, len);
}

int Chain::get_node_id_static(void *chain_ctx) {
    auto *mod = (Module *)chain_ctx;
    return mod->id;
}

int Chain::request_outputs_static(void *chain_ctx, int count) {
    auto *mod = (Module *)chain_ctx;
    return mod->chain->request_outputs_impl(mod, count);
}

int Chain::get_output_fd_static(void *chain_ctx, int idx) {
    (void)chain_ctx;
    return idx;
}

int Chain::request_heartbeat_static(void *chain_ctx, int interval_sec) {
    auto *mod = (Module *)chain_ctx;
    return mod->chain->request_heartbeat_impl(mod, interval_sec);
}

// --- implementation ---

int Chain::request_outputs_impl(Module *mod, int count) {
    if (count < 1) return 0;
    _requested_outputs[mod] = count;
    return count;
}

void *Chain::get_packet_impl(Module *mod, int idx, int *out_size) {
    (void)mod;
    (void)idx;
    *out_size = (int)g_ctx.len;
    const uint8_t *ret_ptr = g_ctx.data;
    return const_cast<uint8_t*>(ret_ptr);
}

int Chain::request_heartbeat_impl(Module *mod, int interval_sec) {
    std::lock_guard<std::mutex> lock(mod->hb_mutex);
    if (interval_sec > 0) {
        mod->heartbeat_interval_sec = interval_sec;
    } else if (interval_sec == 0) {
        mod->heartbeat_interval_sec = -1;
    } else {
        mod->heartbeat_interval_sec = 0;
    }
    return 0;
}

void Chain::check_module_heartbeats(int system_interval_ms) {
    auto now = std::chrono::steady_clock::now();
    for (auto &mod : _modules) {
        int interval_sec = mod->heartbeat_interval_sec;
        if (interval_sec == 0) continue;

        int eff_interval_ms = (interval_sec < 0) ? system_interval_ms
                                                  : interval_sec * 1000;
        if (eff_interval_ms < 1000) eff_interval_ms = 1000;

        bool should_tick = false;
        {
            std::lock_guard<std::mutex> lock(mod->hb_mutex);
            auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - mod->last_activity).count();
            if (idle_ms >= eff_interval_ms) {
                mod->last_activity = now;
                should_tick = true;
            }
        }
        if (should_tick) {
            std::lock_guard<std::mutex> dirlock(mod->dir_mutex[0]);
            mod->base->process_fn(mod->ctx, -1, 0);
        }
    }
}

int Chain::write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len) {
    if (dst >= 0 && (size_t)dst < mod->near.size() && mod->near[dst]) {
        enqueue_module(mod->near[dst], data, len, g_ctx.src_idx, g_ctx.dir);
        return 0;
    }
    // dst=0 always means ext side. dst>=1 uses wire_dst (handles sub-chains).
    return _kapi->wire_write(_kapi->ctx, dst == 0 ? 0 : mod->wire_dst, data, len);
}
