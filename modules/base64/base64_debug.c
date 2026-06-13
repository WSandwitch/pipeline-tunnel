#include "modules/include/module_api.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libbase64.h>

struct b64_ctx {
    ModuleChain *api;
    int trace;
    int node_id;
    int call_count_fw;
    int call_count_rv;
};

void *init(ModuleChain *api, const char *config) {
    struct b64_ctx *ctx = (struct b64_ctx *)malloc(sizeof(*ctx));
    ctx->api = api;
    ctx->trace = 1;  // always trace
    ctx->node_id = (api && api->get_node_id) ? api->get_node_id(api->ctx) : -1;
    ctx->call_count_fw = 0;
    ctx->call_count_rv = 0;
    fprintf(stderr, "[B64-DEBUG init] node=%d config='%s'\n", ctx->node_id, config ? config : "(null)");
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_idx) {
    struct b64_ctx *ctx = (struct b64_ctx *)ctx_ptr;
    
    int sz = 0;
    uint8_t *pkt = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!pkt || sz <= 0) {
        fprintf(stderr, "[B64-DEBUG node=%d dir=%d trig=%d] NO DATA\n", ctx->node_id, dir, trigger_idx);
        return -1;
    }
    
    fprintf(stderr, "[B64-DEBUG node=%d dir=%d trig=%d] sz=%d data[0]=%02x\n", 
            ctx->node_id, dir, trigger_idx, sz, sz>0?pkt[0]:0);
    
    (void)dir;
    int write_dst = (trigger_idx == 0) ? 1 : 0;
    int ret;
    
    if (trigger_idx == 0) {
        ctx->call_count_fw++;
        size_t elen = ((size_t)sz + 2) / 3 * 4;
        char *wbuf = (char *)malloc(elen);
        if (!wbuf) { free(pkt); return -1; }
        size_t outlen;
        fprintf(stderr, "[B64-DEBUG node=%d ENCODE] sz=%d buf=%p elen=%zu\n", ctx->node_id, sz, (void*)pkt, elen);
        base64_encode((const char *)pkt, (size_t)sz, wbuf, &outlen, 0);
        fprintf(stderr, "[B64-DEBUG node=%d ENCODE-DONE] outlen=%zu\n", ctx->node_id, outlen);
        free(pkt);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, (const uint8_t *)wbuf, outlen);
        fprintf(stderr, "[B64-DEBUG node=%d ENCODE-WROTE] ret=%d dst=%d\n", ctx->node_id, ret, write_dst);
    } else {
        ctx->call_count_rv++;
        size_t outlen;
        fprintf(stderr, "[B64-DEBUG node=%d DECODE] sz=%d buf=%p\n", ctx->node_id, sz, (void*)pkt);
        int ok = base64_decode((const char *)pkt, (size_t)sz, (char *)pkt, &outlen, 0);
        fprintf(stderr, "[B64-DEBUG node=%d DECODE-DONE] ok=%d outlen=%zu\n", ctx->node_id, ok, outlen);
        if (!ok) { free(pkt); return -1; }
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, pkt, outlen);
        fprintf(stderr, "[B64-DEBUG node=%d DECODE-WROTE] ret=%d dst=%d\n", ctx->node_id, ret, write_dst);
    }
    return ret;
}

const char *moduleversion(void) { return "1.0.1-debug"; }
const char *modulename(void)    { return "base64-debug"; }
const char *moduledesc(void)    { return "Debug base64 module"; }
const char *modulehelp(void)    { return "debug"; }
