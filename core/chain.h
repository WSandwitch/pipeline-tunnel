#ifndef CHAIN_H
#define CHAIN_H

#include <memory>
#include <vector>
#include <cstdint>
#include "config.h"
#include "kernel_api.h"
#include "module_instance.h"

class Chain {
public:
    Chain(const ChainConfig &cfg, KernelAPI *kapi);
    ~Chain();

    void push_packet(const uint8_t *data, size_t len, int src_idx, int dir);

    // ModuleChain callback targets — called with Module* as chain_ctx
    static void *get_packet_static(void *chain_ctx, int idx, int *out_size);
    static int   write_packet_static(void *chain_ctx, int dst, const uint8_t *data, size_t len);
    static int   get_node_id_static(void *chain_ctx);

    void *get_packet_impl(Module *mod, int idx, int *out_size);
    int   write_packet_impl(Module *mod, int dst, const uint8_t *data, size_t len);

private:
    KernelAPI *_kapi = nullptr;
    std::vector<std::unique_ptr<Module>> _modules;

    // Re-entrancy guard
    bool _in_push = false;
};

#endif