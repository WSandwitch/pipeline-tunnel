#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct copy_ctx {
    ModuleChain *api;
    int trace;
    int node_id;
    int mode_copy; /* 0 = move (default), 1 = copy */
};

void *init(ModuleChain *api, const char *config) {
    struct copy_ctx *ctx = (struct copy_ctx *)malloc(sizeof(*ctx));
    ctx->api = api;
    ctx->trace = 0;
    ctx->mode_copy = 0; /* default move */
    ctx->node_id = (api && api->get_node_id) ? api->get_node_id(api->ctx) : -1;

    if (config) {
        if (strstr(config, "trace")) ctx->trace = 1;
        const char *m = strstr(config, "m:");
        if (m && (m[2] == 'c' || m[2] == 'm'))
            ctx->mode_copy = (m[2] == 'c');
    }
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_idx) {
    (void)dir;
    struct copy_ctx *ctx = (struct copy_ctx *)ctx_ptr;

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
    int write_dst = (trigger_idx == 0) ? 1 : 0;
    fprintf(stderr, "COPY[%d]: node=%d dir=%d trig=%d sz=%d write_dst=%d\n", ctx->node_id, ctx->node_id, dir, trigger_idx, sz, write_dst);

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

const char *moduleversion(void) {
    return "1.0.0";
}

const char *modulename(void) {
    return "copy";
}

const char *moduledesc(void) {
    return "copy data from input to output (move or copy)";
}

const char *modulehelp(void) {
    return "Copies data from input to output.\n"
           "Config options:\n"
           "  trace   – hex dump to stderr\n"
           "  m:c     – copy mode (alloc+memcpy, free original)\n"
           "  m:m     – move mode (default, pass pointer through)\n"
           "Example: \"trace m:c\"";
}
