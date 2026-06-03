#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_SEQ_WINDOW 256
#define CHUNK_SIZE 65536

struct chunk {
    uint8_t *data;
    int len;
};

struct seq_entry {
    struct chunk *chunks;
    int count;
    int cap;
    int more;
    int used;
};

struct merge_state {
    unsigned char next_seq;
    struct seq_entry buf[MAX_SEQ_WINDOW];
};

struct split_ctx {
    int in_fd;
    int out_fd;
    ModuleKernel *kapi;
    int *extra_fds;
    int extra_count;
    int num_outputs;
    int rr_idx;
    unsigned char seqnum;
    struct merge_state merge;
    int trace;
    int node_id;
};

void *init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config) {
    struct split_ctx *ctx = (struct split_ctx *)calloc(1, sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->kapi = kapi;
    ctx->extra_fds = NULL;
    ctx->extra_count = 0;
    ctx->rr_idx = 0;
    ctx->seqnum = 0;
    ctx->merge.next_seq = 0;

    int copies = 1;
    if (config && config[0] != '\0') {
        if (strncmp(config, "split:", 6) == 0)
            copies = atoi(config + 6);
        else if (strcmp(config, "split") == 0)
            copies = 1;
    }
    if (copies < 1) copies = 1;

    if (kapi && kapi->request_outputs) {
        int ret = kapi->request_outputs(kapi->ctx, copies);
        if (ret > 0) {
            ctx->extra_fds = (int *)malloc(sizeof(int) * (size_t)ret);
            ctx->extra_count = ret;
            for (int i = 0; i < ret; i++)
                ctx->extra_fds[i] = kapi->get_output_fd(kapi->ctx, i);
        }
    }
    ctx->num_outputs = ctx->extra_count + 1;

    ctx->trace = config && strstr(config, "trace") != NULL;
    ctx->node_id = kapi && kapi->get_node_id ? kapi->get_node_id(kapi->ctx) : -1;
    if (ctx->trace)
        fprintf(stderr, "[split node=%d init] outputs=%d\n",
                ctx->node_id, ctx->num_outputs);

    return ctx;
}

static int output_fd_at(struct split_ctx *ctx, int idx) {
    if (idx == 0) return ctx->out_fd;
    if (idx - 1 < ctx->extra_count) return ctx->extra_fds[idx - 1];
    return ctx->out_fd;
}

static int process_split(struct split_ctx *ctx, int trigger_fd) {
    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *in_buf = (uint8_t *)malloc((size_t)sz);
    if (!in_buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, in_buf);

    int to_output = (trigger_fd == ctx->in_fd);

    int offset = 0;
    int chunks = 0;
    while (offset < sz) {
        int chunk_len = sz - offset;
        if (chunk_len > CHUNK_SIZE) chunk_len = CHUNK_SIZE;
        int more = (offset + chunk_len < sz) ? 1 : 0;

        uint8_t out_buf[CHUNK_SIZE + 2];
        out_buf[0] = ctx->seqnum++;
        out_buf[1] = (uint8_t)more;
        memcpy(out_buf + 2, in_buf + offset, (size_t)chunk_len);

        int fd;
        if (to_output) {
            int out_idx = ctx->rr_idx % ctx->num_outputs;
            ctx->rr_idx++;
            fd = output_fd_at(ctx, out_idx);
        } else {
            fd = ctx->in_fd;
        }

        int ret = ctx->kapi->write_packet(ctx->kapi->ctx, fd, out_buf, (size_t)chunk_len + 2);
        if (ret < 0) { free(in_buf); return ret; }
        offset += chunk_len;
        chunks++;
    }

    if (ctx->trace)
        fprintf(stderr, "[split node=%d fw] chunks=%d sum=%d\n",
                ctx->node_id, chunks, sz);

    free(in_buf);
    return 0;
}

static void merge_flush_packet(struct split_ctx *ctx, unsigned char last_seq, int write_fd) {
    uint8_t *out_buf = NULL;
    int out_len = 0;
    int out_cap = 0;

    for (unsigned char s = ctx->merge.next_seq; s <= last_seq; s++) {
        struct seq_entry *e = &ctx->merge.buf[s];
        for (int i = 0; i < e->count; i++) {
            int needed = out_len + e->chunks[i].len;
            if (needed > out_cap) {
                out_cap = out_cap ? out_cap * 2 : 65536;
                if (out_cap < needed) out_cap = needed;
                uint8_t *tmp = (uint8_t *)realloc(out_buf, (size_t)out_cap);
                if (!tmp) { free(out_buf); return; }
                out_buf = tmp;
            }
            memcpy(out_buf + out_len, e->chunks[i].data, (size_t)e->chunks[i].len);
            out_len += e->chunks[i].len;
        }
        e->used = 0;
        e->more = 0;
        for (int i = 0; i < e->count; i++) free(e->chunks[i].data);
        free(e->chunks);
        e->chunks = NULL;
        e->count = 0;
        e->cap = 0;
    }

    ctx->merge.next_seq = (unsigned char)(last_seq + 1);

    if (out_len > 0 && out_buf) {
        if (ctx->trace)
            fprintf(stderr, "[split node=%d rv] flush seq=%u total=%d\n",
                    ctx->node_id, last_seq, out_len);
        ctx->kapi->write_packet(ctx->kapi->ctx, write_fd, out_buf, (size_t)out_len);
        free(out_buf);
    }
}

static int process_merge(struct split_ctx *ctx, int trigger_fd) {
    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, buf);

    if (sz < 2) { free(buf); return -1; }
    unsigned char seq = buf[0];
    int more = buf[1];
    uint8_t *data = buf + 2;
    int data_len = sz - 2;

    struct seq_entry *e = &ctx->merge.buf[seq];

    if (e->count >= e->cap) {
        int new_cap = e->cap ? e->cap * 2 : 4;
        struct chunk *tmp = (struct chunk *)realloc(e->chunks, sizeof(struct chunk) * (size_t)new_cap);
        if (!tmp) { free(buf); return -1; }
        e->chunks = tmp;
        e->cap = new_cap;
    }
    e->chunks[e->count].data = (uint8_t *)malloc((size_t)data_len);
    memcpy(e->chunks[e->count].data, data, (size_t)data_len);
    e->chunks[e->count].len = data_len;
    e->count++;
    e->used = 1;
    if (more) e->more = 1;
    else e->more = 0;

    free(buf);

    int write_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;

    // Try to flush from next_seq by scanning for a contiguous used sequence
    // ending with a chunk that has more==0 (last chunk of a packet).
    unsigned char scan = ctx->merge.next_seq;
    while (ctx->merge.buf[scan].used) {
        if (!ctx->merge.buf[scan].more) {
            merge_flush_packet(ctx, scan, write_fd);
            break;
        }
        scan++;
    }

    return 0;
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    struct split_ctx *ctx = (struct split_ctx *)ctx_ptr;
    if (dir == 1)
        return process_split(ctx, trigger_fd);
    else
        return process_merge(ctx, trigger_fd);
}

const char *modulename(void) {
    return "split";
}

const char *moduledesc(void) {
    return "Split/merge module for N-way multi-stream";
}

const char *modulehelp(void) {
    return "Splits large packets into chunks (round-robin), merges by seqnum.\n"
           "Config: \"split:N\" for N extra streams.\n"
           "\"trace\" enables debug output.\n"
            "Chunk max size: 65536 bytes, uses more flag for packet boundaries.";
}
