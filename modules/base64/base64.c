#include "modules/include/module_api.h"
#include <libbase64.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct b64_ctx {
    ModuleChain *api;
    int trace;
    int node_id;
};

void *init(ModuleChain *api, const char *config) {
    struct b64_ctx *ctx = (struct b64_ctx *)malloc(sizeof(*ctx));
    ctx->api = api;
    ctx->trace = config && strstr(config, "trace") != NULL;
    ctx->node_id = (api && api->get_node_id) ? api->get_node_id(api->ctx) : -1;
    if (ctx->trace)
        fprintf(stderr, "[base64 node=%d init]\n", ctx->node_id);
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_idx) {
    (void)dir;
    struct b64_ctx *ctx = (struct b64_ctx *)ctx_ptr;

    int sz = 0;
    uint8_t *pkt = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!pkt || sz <= 0) return -1;

    int write_dst = (trigger_idx == 0) ? 1 : 0;
    int ret;

    if (trigger_idx == 0) {
        size_t elen = ((size_t)sz + 2) / 3 * 4;
        char *wbuf = (char *)malloc(elen);
        if (!wbuf) { free(pkt); return -1; }

        size_t outlen;
        base64_encode((const char *)pkt, (size_t)sz, wbuf, &outlen, 0);

        if (ctx->trace)
            fprintf(stderr, "[base64 node=%d fw] sz=%d -> out=%zu\n", ctx->node_id, sz, outlen);
        free(pkt);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, (const uint8_t *)wbuf, outlen);
    } else {
        size_t outlen;
        int ok = base64_decode((const char *)pkt, (size_t)sz, (char *)pkt, &outlen, 0);
        if (!ok) { free(pkt); return -1; }

        if (ctx->trace)
            fprintf(stderr, "[base64 node=%d rv] sz=%d -> out=%zu\n", ctx->node_id, sz, outlen);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, pkt, outlen);
    }

    return ret;
}

const char *moduleversion(void) { return "1.0.1"; }
const char *modulename(void)    { return "base64"; }
const char *moduledesc(void)    { return "Base64 encode/decode with SIMD acceleration"; }
const char *modulehelp(void) {
    return "Encodes data from external->wire, decodes from wire->external.\n"
           "Uses aklomp/base64 library with runtime SIMD dispatch.\n"
           "Config: \"trace\" enables debug output.";
}
