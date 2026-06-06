#include "chain.h"
#include "common/logger.h"

Chain::Chain(const ChainConfig &cfg, KernelAPI *kapi)
    : _kapi(kapi)
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
        mod->outputs = 1;

        mod->api.ctx = mod.get();
        mod->api.request_outputs = nullptr;
        mod->api.get_output_fd = nullptr;
        mod->api.get_node_id = &Chain::get_node_id_static;
        mod->api.get_packet = &Chain::get_packet_static;
        mod->api.write_packet = &Chain::write_packet_static;

        mod->ctx = base->init_fn(&mod->api, spec.params.c_str());
        if (!mod->ctx) {
            log_error("chain: module '%s' init failed", spec.name.c_str());
            return;
        }

        log_debug("chain: module '%s' initialized (id=%d)", spec.name.c_str(), mod->id);
        _modules.push_back(std::move(mod));
    }
}

Chain::~Chain() = default;

struct PushContext {
    const uint8_t *data = nullptr;
    size_t len = 0;
    int src_idx = 0;
};

thread_local PushContext g_push_ctx;
thread_local bool g_push_ctx_valid = false;

void Chain::push_packet(const uint8_t *data, size_t len, int src_idx, int dir) {
    if (_modules.empty()) return;
    if (_in_push) {
        log_error("chain: re-entrant push_packet detected, dropping packet");
        return;
    }
    _in_push = true;

    PushContext old_ctx = g_push_ctx;
    bool old_valid = g_push_ctx_valid;
    g_push_ctx = PushContext{data, len, src_idx};
    g_push_ctx_valid = true;

    auto &mod = *_modules[0];
    int ret = mod.base->process_fn(mod.ctx, dir, src_idx);
    if (ret < 0) {
        log_debug("chain: module process_fn returned %d, dropping packet", ret);
    }

    g_push_ctx = old_ctx;
    g_push_ctx_valid = old_valid;
    _in_push = false;
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

void *Chain::get_packet_impl(Module *mod, int idx, int *out_size) {
    (void)mod;
    (void)idx;
    if (!g_push_ctx_valid) {
        *out_size = 0;
        return nullptr;
    }
    *out_size = (int)g_push_ctx.len;
    return const_cast<uint8_t*>(g_push_ctx.data);
}

int Chain::write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len) {
    (void)mod;
    return _kapi->wire_write(_kapi->ctx, dst, data, len);
}