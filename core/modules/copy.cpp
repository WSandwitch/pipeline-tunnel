#include "modules/include/module_api.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

struct builtin_copy_ctx {
    ModuleChain *api;
    int trace;
    int node_id;
    int mode_copy; /* 0 = move (default), 1 = copy */
};

extern "C" void *builtin_copy_init(ModuleChain *api, const char *config) {
    auto *ctx = (builtin_copy_ctx *)malloc(sizeof(builtin_copy_ctx));
    ctx->api = api;
    ctx->trace = 0;
    ctx->mode_copy = 0;
    ctx->node_id = (api && api->get_node_id) ? api->get_node_id(api->ctx) : -1;

    if (config) {
        if (strstr(config, "trace")) ctx->trace = 1;
        const char *m = strstr(config, "m:");
        if (m && (m[2] == 'c' || m[2] == 'm'))
            ctx->mode_copy = (m[2] == 'c');
    }
    return ctx;
}

extern "C" int builtin_copy_process(void *ctx_ptr, int dir, int trigger_idx) {
    (void)dir;
    auto *ctx = (builtin_copy_ctx *)ctx_ptr;

    int sz = 0;
    uint8_t *pkt = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!pkt || sz <= 0) return -1;

    if (ctx->trace) {
        fprintf(stderr, "[copy node=%d sz=%d trigger=%d] ", ctx->node_id, sz, trigger_idx);
        size_t show = (size_t)sz < 64 ? (size_t)sz : 64;
        for (size_t i = 0; i < show; i++) fprintf(stderr, "%02x", pkt[i]);
        if ((size_t)sz > 64) fprintf(stderr, "...");
        fprintf(stderr, "\n");
    }
    int write_dst = (dir == 0) ? 1 : 0;
    if (ctx->mode_copy) {
        uint8_t *cp = (uint8_t *)malloc((size_t)sz);
        if (!cp) { free(pkt); return -1; }
        memcpy(cp, pkt, (size_t)sz);
        free(pkt);
        return ctx->api->write_packet(ctx->api->ctx, write_dst, cp, (size_t)sz);
    } else {
        return ctx->api->write_packet(ctx->api->ctx, write_dst, pkt, (size_t)sz);
    }
}

extern "C" const char *builtin_copy_modulename() {
    return "copy";
}

extern "C" const char *builtin_copy_moduledesc() {
    return "copy data from input to output (move or copy)";
}

extern "C" const char *builtin_copy_modulehelp() {
    return "Copies data from input to output.\n"
           "Config options:\n"
           "  trace   – hex dump to stderr\n"
           "  m:c     – copy mode (alloc+memcpy, free original)\n"
           "  m:m     – move mode (default, pass pointer through)\n"
           "Example: \"trace m:c\"";
}

extern "C" const char *builtin_copy_moduleversion() {
    return "1.0.0";
}
