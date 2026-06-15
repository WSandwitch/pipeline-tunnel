#include "chain.h"
#include "thread_pool.h"
#include "common/logger.h"

static Module *find_module_by_idx(std::vector<std::unique_ptr<Module>> &vec, size_t idx) {
    if (idx >= vec.size()) return nullptr;
    return vec[idx].get();
}

Chain::Chain(const ChainConfig &cfg, KernelAPI *kapi,
             ThreadPool *pool, std::shared_ptr<void> owner_guard)
    : _kapi(kapi), _pool(pool), _owner(owner_guard), _cfg(cfg)
{
    for (auto &spec : cfg.modules) {
        auto base = ModuleBase::find(spec.name);
        if (!base) {
            log_error("chain: module '%s' not found", spec.name.c_str());
            return;
        }

        auto mod = std::make_unique<Module>();
        mod->base = const_cast<ModuleBase *>(base);
        mod->chain = this;
        mod->id = _kapi->alloc_module_id(_kapi->ctx);

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
            return;
        }

        mod->last_activity = std::chrono::steady_clock::now();
        log_debug("chain: module '%s' initialized (id=%d)", spec.name.c_str(), mod->id);
        _modules.push_back(std::move(mod));
    }
    // Wire up chain: each module's outputs 0 and 1 point to the next module
    for (size_t i = 0; i + 1 < _modules.size(); i++) {
        _modules[i]->outputs = {_modules[i+1].get(), _modules[i+1].get()};
    }

    // Pre-reserve to avoid pointer invalidation from vector reallocation
    {
        size_t total_clones = 0;
        for (auto &[m, c] : _requested_outputs) {
            size_t mi = 0;
            for (size_t i = 0; i < _modules.size(); i++)
                if (_modules[i].get() == m) { mi = i; break; }
            size_t rem = cfg.modules.size() - (mi + 1);
            total_clones += (size_t)c * rem;
        }
        _clone_modules.reserve(total_clones);
    }

    // Handle request_outputs: clone remaining modules for each extra output
    for (auto &[mod, count] : _requested_outputs) {
        size_t mod_idx = 0;
        for (size_t i = 0; i < _modules.size(); i++) {
            if (_modules[i].get() == mod) { mod_idx = i; break; }
        }
        size_t remaining_start = mod_idx + 1;
        if (remaining_start >= cfg.modules.size()) continue;

        // Ensure outputs[0] exists (points to original next module or nullptr)
        if (mod->outputs.empty() && remaining_start < _modules.size())
            mod->outputs = {_modules[remaining_start].get(), _modules[remaining_start].get()};
        else if (mod->outputs.empty())
            mod->outputs = {nullptr, nullptr};

        mod->outputs.resize((size_t)count + 1);
        if (mod->outputs[0] == nullptr && remaining_start < _modules.size())
            mod->outputs[0] = _modules[remaining_start].get();

        for (int k = 1; k <= count; k++) {
            Module *prev_mod = mod;
            size_t n_cloned = 0;
            for (size_t ri = remaining_start; ri < _modules.size(); ri++) {
                auto &spec = cfg.modules[ri];
                auto base = ModuleBase::find(spec.name);
                if (!base) break;

                auto clone = std::make_unique<Module>();
                clone->base = const_cast<ModuleBase *>(base);
                clone->chain = this;
                clone->id = _kapi->alloc_module_id(_kapi->ctx);
                clone->api.ctx = clone.get();
                clone->api.request_outputs = nullptr;
                clone->api.get_output_fd = nullptr;
                clone->api.get_node_id = &Chain::get_node_id_static;
                clone->api.get_packet = &Chain::get_packet_static;
                clone->api.write_packet = &Chain::write_packet_static;
                clone->api.request_heartbeat = &Chain::request_heartbeat_static;
                clone->ctx = base->init_fn(&clone->api, spec.params.c_str());
                clone->last_activity = std::chrono::steady_clock::now();

                if (n_cloned == 0)
                    prev_mod->outputs[k] = clone.get();
                else
                    prev_mod->outputs = {clone.get(), clone.get()};

                prev_mod = clone.get();
                n_cloned++;

                // Wire clone to next original module for last clone (will be overwritten if more clones follow)
                if (ri + 1 >= _modules.size())
                    clone->outputs = {};
                else
                    clone->outputs = {nullptr, nullptr};

                _clone_modules.push_back(std::move(clone));
            }
            // Wire last clone's outputs to the original remaining module's outputs (empty = wire)
            if (n_cloned > 0 && prev_mod != mod) {
                prev_mod->outputs = {};
            }
        }
    }
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
    int output_port = -1;
    Module *next_mod = nullptr;
};

thread_local ChainContext g_ctx;

void Chain::push_packet(const uint8_t *data, size_t len, int src_idx, int dir) {
    if (_cancelled.load()) {
        free(const_cast<uint8_t*>(data));
        return;
    }
    if (_modules.empty()) {
        if (dir == 0) {
            _kapi->wire_write(_kapi->ctx, 1, data, len);
        } else {
            _kapi->wire_write(_kapi->ctx, 0, data, len);
        }
        return;
    }
    if (!_owner.lock()) {
        free(const_cast<uint8_t*>(data));
        return;
    }

    Module *first = dir == 0 ? _modules[0].get() : _modules.back().get();
    enqueue_module(first, data, len, src_idx, dir, -1);
}

void Chain::enqueue_module(Module *mod, const uint8_t *data, size_t len,
                           int src_idx, int dir, int output_port) {
    auto owner = _owner.lock();
    if (!owner) {
        free(const_cast<uint8_t*>(data));
        return;
    }

    mod->pending[dir].fetch_add(1);
    _inflight.fetch_add(1);
    check_backpressure(dir);

    _pool->enqueue([this, data, len, src_idx, dir, output_port, mod, owner,
                   om = &dir_order_mutex_[dir]]() {
        if (_cancelled.load()) {
            mod->pending[dir].fetch_sub(1);
            check_backpressure(dir);
            om->unlock();
            free(const_cast<uint8_t*>(data));
            task_done();
            return;
        }

        g_ctx = ChainContext{data, len, src_idx, dir, output_port, nullptr};

        {
            std::lock_guard<std::mutex> lock(mod->hb_mutex);
            mod->last_activity = std::chrono::steady_clock::now();
        }

        std::lock_guard<std::mutex> lock(mod->dir_mutex[dir]);
        om->unlock();

        int ret = mod->base->process_fn(mod->ctx, dir, src_idx);

        mod->pending[dir].fetch_sub(1);
        check_backpressure(dir);

        if (ret < 0) {
            log_debug("chain: module process_fn returned %d, dropping packet", ret);
            task_done();
            return;
        }

        // Reverse chaining: write_packet(dir=1, dst=0) sets g_ctx.next_mod
        if (g_ctx.next_mod) {
            Module *next = g_ctx.next_mod;
            g_ctx.next_mod = nullptr;
            enqueue_module(next, g_ctx.data, g_ctx.len,
                          g_ctx.src_idx, dir, g_ctx.output_port);
        }

        task_done();
    }, &dir_order_mutex_[dir]);
}

void Chain::task_done() {
    if (_inflight.fetch_sub(1) == 1) {
        std::lock_guard<std::mutex> lock(_drain_mtx);
        _drain_cv.notify_all();
    }
}

void Chain::check_backpressure(int dir) {
    int max_p = 0;
    for (auto &m : _modules)
        if (auto v = m->pending[dir].load(); v > max_p) max_p = v;
    for (auto &m : _clone_modules)
        if (auto v = m->pending[dir].load(); v > max_p) max_p = v;

    log_debug("chain: check_bp dir=%d max_p=%d bp_paused=%d", dir, max_p, (int)_backpressure_paused[dir].load());

    if (max_p > BACKPRESSURE_HIGH && !_backpressure_paused[dir].load()) {
        _backpressure_paused[dir].store(true);
        log_debug("chain: PAUSE dir=%d max_p=%d", dir, max_p);
        if (_pause_cb[dir]) _pause_cb[dir](true);
    }
    if (max_p <= BACKPRESSURE_LOW && _backpressure_paused[dir].load()) {
        _backpressure_paused[dir].store(false);
        log_debug("chain: RESUME dir=%d max_p=%d", dir, max_p);
        if (_pause_cb[dir]) _pause_cb[dir](false);
    }
}

void Chain::wait_drain() {
    std::unique_lock<std::mutex> lock(_drain_mtx);
    _drain_cv.wait(lock, [this] { return _inflight.load() == 0; });
}

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
    auto *mod = (Module *)chain_ctx;
    return mod->chain->get_output_fd_impl(mod, idx);
}

int Chain::total_extra_outputs() const {
    int total = 0;
    for (auto &[mod, count] : _requested_outputs) {
        (void)mod;
        total += count;
    }
    return total;
}

int Chain::request_outputs_impl(Module *mod, int count) {
    if (count < 1) return 0;
    _requested_outputs[mod] = count;
    return count;
}

int Chain::get_output_fd_impl(Module *mod, int idx) {
    (void)mod;
    return idx;
}

void *Chain::get_packet_impl(Module *mod, int idx, int *out_size) {
    (void)mod;
    (void)idx;
    *out_size = (int)g_ctx.len;
    return const_cast<uint8_t*>(g_ctx.data);
}

int Chain::request_heartbeat_static(void *chain_ctx, int interval_sec) {
    auto *mod = (Module *)chain_ctx;
    return mod->chain->request_heartbeat_impl(mod, interval_sec);
}

int Chain::request_heartbeat_impl(Module *mod, int interval_sec) {
    std::lock_guard<std::mutex> lock(mod->hb_mutex);
    if (interval_sec > 0) {
        mod->heartbeat_interval_sec = interval_sec;
    } else if (interval_sec == 0) {
        mod->heartbeat_interval_sec = -1; // use system interval
    } else {
        mod->heartbeat_interval_sec = 0;  // cancel
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

    for (auto &mod : _clone_modules) {
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
    if (_requested_outputs.count(mod)) {
        g_ctx.output_port = dst;
    }
    if (g_ctx.dir == 1 && dst == 0) {
        Module *prev = nullptr;
        for (size_t i = 1; i < _modules.size(); i++) {
            if (_modules[i].get() == mod) {
                prev = _modules[i - 1].get();
                break;
            }
        }
        if (prev) {
            g_ctx.next_mod = prev;
            g_ctx.data = data;
            g_ctx.len = len;
            return 0;
        }
        int ret = _kapi->wire_write(_kapi->ctx, 0, data, len);
        return ret;
    }

    if (dst >= 0 && (size_t)dst < mod->outputs.size()) {
        if (mod->outputs[dst]) {
            Module *m = mod->outputs[dst];
            enqueue_module(m, data, len, g_ctx.src_idx, g_ctx.dir, g_ctx.output_port);
            return 0;
        }
    }
    int wire_dst = (g_ctx.output_port >= 0 && g_ctx.dir == 0) ? (g_ctx.output_port + 1) : dst;
    int ret = _kapi->wire_write(_kapi->ctx, wire_dst, data, len);
    return ret;
}
