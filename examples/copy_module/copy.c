#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct copy_ctx {
    int in_fd;
    int out_fd;
    ModuleKernel *kapi;
    int trace;
    int node_id;
};

void *init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config) {
    struct copy_ctx *ctx = (struct copy_ctx *)malloc(sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->kapi = kapi;
    ctx->trace = (config && strstr(config, "trace") != NULL);
    ctx->node_id = (kapi && kapi->get_node_id) ? kapi->get_node_id(kapi->ctx) : -1;
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    (void)dir;
    struct copy_ctx *ctx = (struct copy_ctx *)ctx_ptr;

    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, buf);

    if (ctx->trace) {
        fprintf(stderr, "[copy node=%d sz=%d trigger=%d] ", ctx->node_id, sz, trigger_fd);
        size_t show = (size_t)sz < 64 ? (size_t)sz : 64;
        for (size_t i = 0; i < show; i++) fprintf(stderr, "%02x", buf[i]);
        if ((size_t)sz > 64) fprintf(stderr, "...");
        fprintf(stderr, "\n");
    }

    int write_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;
    int ret = ctx->kapi->write_packet(ctx->kapi->ctx, write_fd, buf, (size_t)sz);
    free(buf);
    return ret;
}

const char *modulename(void) {
    return "copy";
}

const char *moduledesc(void) {
    return "Copy module - copies input data to output, optional trace";
}

const char *modulehelp(void) {
    return "Copies data from input to output unchanged.\n"
           "Config: \"trace\" enables hex dump to stderr.\n"
           "Useful as a pass-through module for testing chains.";
}
