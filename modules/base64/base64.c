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

int process(void *ctx_ptr, int dir, int trigger_idx, const uint8_t *data, size_t len) {
    struct b64_ctx *ctx = (struct b64_ctx *)ctx_ptr;

    if (!data || len <= 0) {
        return -1;
    }

    int write_dst = (dir == 0) ? 1 : 0;
    int ret;

    if (dir == 0) {
        size_t elen = (len + 2) / 3 * 4;
        char *wbuf = (char *)ctx->api->malloc(ctx->api->ctx, elen);
        if (!wbuf) return -1;

        size_t outlen;
        base64_encode((const char *)data, len, wbuf, &outlen, 0);

        if (ctx->trace)
            fprintf(stderr, "[base64 node=%d fw] sz=%zu -> out=%zu\n", ctx->node_id, len, outlen);
        ctx->api->free(ctx->api->ctx, (void*)data);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, (const uint8_t *)wbuf, outlen);
    } else {
        size_t outlen;
        uint8_t *buf = (uint8_t *)ctx->api->malloc(ctx->api->ctx, len);
        if (!buf) return -1;
        memcpy(buf, data, len);
        int ok = base64_decode((const char *)buf, len, (char *)buf, &outlen, 0);
        if (!ok) { ctx->api->free(ctx->api->ctx, buf); return -1; }

        if (ctx->trace)
            fprintf(stderr, "[base64 node=%d rv] sz=%zu -> out=%zu\n", ctx->node_id, len, outlen);
        ctx->api->free(ctx->api->ctx, (void*)data);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, buf, outlen);
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
