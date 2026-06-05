#include "chain.h"
#include "common/logger.h"
#include <cstring>
#include <cstdlib>

Chain::Chain(const ChainConfig &cfg, KernelAPI *kapi, const ChainRef &ref)
    : _kapi(kapi), _ref(ref)
{
    for (auto &spec : cfg.modules) {
        auto base = ModuleBase::find(spec.name);
        if (!base) {
            log_error("chain: module '%s' not found", spec.name.c_str());
            return; // FIXME: better error handling
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

void Chain::push_packet(const uint8_t *data, size_t len, int src_idx) {
    if (_modules.empty()) return;
    _push_data = data;
    _push_len = len;
    _push_src_idx = src_idx;

    auto &mod = *_modules[0];
    mod.base->process_fn(mod.ctx, 0, src_idx);
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
    if (idx == 0) {
        *out_size = (int)_push_len;
        return const_cast<uint8_t *>(_push_data);
    }
    *out_size = 0;
    return nullptr;
}

int Chain::write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len) {
    (void)mod;
    int fd = -1;
    if (dst == 1 && !_ref.out_fds.empty())
        fd = _ref.out_fds[0];
    else if (dst == 0 && !_ref.in_fds.empty())
        fd = _ref.in_fds[0];

    if (fd < 0) {
        log_error("chain: write_packet no fd for dst=%d", dst);
        free(const_cast<uint8_t *>(data));
        return -1;
    }

    int ret = _kapi->wire_write(_kapi->ctx, fd, data, len);
    free(const_cast<uint8_t *>(data));
    return ret;
}
