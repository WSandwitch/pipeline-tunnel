#ifndef CHAIN_H
#define CHAIN_H

#include <memory>
#include <vector>
#include "config.h"
#include "chain_ref.h"
#include "kernel_api.h"
#include "module_instance.h"

class Chain {
public:
    Chain(const ChainConfig &cfg, KernelAPI *kapi, const ChainRef &ref);
    ~Chain();

    void push_packet(const uint8_t *data, size_t len, int src_idx);

    // ModuleChain callback targets — called with Module* as chain_ctx
    static void *get_packet_static(void *chain_ctx, int idx, int *out_size);
    static int   write_packet_static(void *chain_ctx, int dst, const uint8_t *data, size_t len);
    static int   get_node_id_static(void *chain_ctx);

    void *get_packet_impl(Module *mod, int idx, int *out_size);
    int   write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len);

private:
    KernelAPI *_kapi = nullptr;
    ChainRef _ref;
    std::vector<std::unique_ptr<Module>> _modules;

    const uint8_t *_push_data = nullptr;
    size_t _push_len = 0;
    int _push_src_idx = 0;
};

#endif
