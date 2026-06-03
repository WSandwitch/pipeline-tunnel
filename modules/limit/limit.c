#define _POSIX_C_SOURCE 199309L
#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define DEFAULT_RATE 1048576

struct limit_ctx {
    int in_fd;
    int out_fd;
    ModuleKernel *kapi;
    int trace;
    int node_id;
    uint64_t rate_bps;
    uint64_t tokens;
    uint64_t last_refill_us;
};

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

void *init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config) {
    struct limit_ctx *ctx = (struct limit_ctx *)calloc(1, sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->kapi = kapi;
    ctx->trace = (config && strstr(config, "trace") != NULL);
    ctx->node_id = (kapi && kapi->get_node_id) ? kapi->get_node_id(kapi->ctx) : -1;
    ctx->rate_bps = DEFAULT_RATE;
    ctx->tokens = DEFAULT_RATE;
    ctx->last_refill_us = now_us();

    if (config) {
        int val = atoi(config);
        if (val > 0) ctx->rate_bps = (uint64_t)val;
    }
    if (ctx->rate_bps < 1) ctx->rate_bps = 1;

    if (ctx->trace) {
        fprintf(stderr, "[limit node=%d init] rate=%lu bps\n",
                ctx->node_id, (unsigned long)ctx->rate_bps);
    }

    return ctx;
}

static void refill_tokens(struct limit_ctx *ctx) {
    uint64_t now = now_us();
    uint64_t elapsed = now - ctx->last_refill_us;
    if (elapsed > 0) {
        ctx->tokens += ctx->rate_bps * elapsed / 1000000;
        if (ctx->tokens > ctx->rate_bps)
            ctx->tokens = ctx->rate_bps;
        ctx->last_refill_us = now;
    }
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    (void)dir;
    struct limit_ctx *ctx = (struct limit_ctx *)ctx_ptr;

    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, buf);

    refill_tokens(ctx);
    while (ctx->tokens < (uint64_t)sz) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
        nanosleep(&ts, NULL);
        refill_tokens(ctx);
    }
    ctx->tokens -= (uint64_t)sz;

    int write_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;
    if (ctx->trace) {
        fprintf(stderr, "[limit node=%d dir=%d sz=%d tokens=%lu rate=%lu]\n",
                ctx->node_id, dir, sz, (unsigned long)ctx->tokens, (unsigned long)ctx->rate_bps);
    }

    int ret = ctx->kapi->write_packet(ctx->kapi->ctx, write_fd, buf, (size_t)sz);
    free(buf);
    return ret;
}

const char *modulename(void) {
    return "limit";
}

const char *moduledesc(void) {
    return "Rate limiter module with token bucket pacing";
}

const char *modulehelp(void) {
    return "Limits data throughput using a simple token bucket.\n"
           "Config: bytes per second (default 1048576 = 1MB/s).\n"
           "\"trace\" enables debug output.";
}
