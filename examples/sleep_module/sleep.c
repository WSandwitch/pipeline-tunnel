#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct sleep_ctx {
    int in_fd;
    int out_fd;
    ModuleKernel *kapi;
    int trace;
    int node_id;
    useconds_t delay_us;
};

void *init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config) {
    struct sleep_ctx *ctx = (struct sleep_ctx *)malloc(sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->kapi = kapi;
    ctx->trace = (config && strstr(config, "trace") != NULL);
    ctx->node_id = (kapi && kapi->get_node_id) ? kapi->get_node_id(kapi->ctx) : -1;
    ctx->delay_us = 15000;
    if (config) {
        int val = atoi(config);
        if (val > 0) ctx->delay_us = (useconds_t)val;
    }
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    (void)dir;
    struct sleep_ctx *ctx = (struct sleep_ctx *)ctx_ptr;

    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, buf);

    if (ctx->trace) {
        fprintf(stderr, "[sleep node=%d delay=%u sz=%d trigger=%d] ",
                ctx->node_id, ctx->delay_us, sz, trigger_fd);
        size_t show = (size_t)sz < 64 ? (size_t)sz : 64;
        for (size_t i = 0; i < show; i++) fprintf(stderr, "%02x", buf[i]);
        if ((size_t)sz > 64) fprintf(stderr, "...");
        fprintf(stderr, "\n");
    }

    if (ctx->delay_us > 0)
        usleep(ctx->delay_us);

    int write_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;
    int ret = ctx->kapi->write_packet(ctx->kapi->ctx, write_fd, buf, (size_t)sz);
    free(buf);
    return ret;
}

const char *modulename(void) {
    return "sleep";
}

const char *moduledesc(void) {
    return "Sleep module - introduces configurable delay in data flow";
}

const char *modulehelp(void) {
    return "Introduces a configurable delay (usleep) on each packet.\n"
           "Config: time in microseconds (default 15000 = 15ms).\n"
           "\"trace\" enables debug output.\n"
           "Useful for testing back-pressure and flow control.";
}
