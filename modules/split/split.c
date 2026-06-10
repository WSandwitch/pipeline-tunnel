#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define min(a,b) ((a) < (b) ? (a) : (b))
#define CLAMP(x,lo,hi) ((x) < (lo) ? (lo) : (x) > (hi) ? (hi) : (x))

#define MAX_SEQ_WINDOW 65536
#define DEF_CHUNK_SIZE 16384
#define MIN_CHUNK 64
#define MAX_CHUNK 65536

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
    uint16_t seq;
};

struct merge_state {
    uint16_t next_seq;
    struct seq_entry buf[MAX_SEQ_WINDOW];
};

struct split_ctx {
    ModuleChain *api;
    int num_outputs;
    int rr_idx;
    uint16_t seqnum;
    struct merge_state merge;
    int trace;
    int node_id;
    int chunk_size_min;
    int chunk_size_max;
};

static int parse_size(const char *s, int def) {
    if (!s || !*s) return def;
    long val = atol(s);
    if (val <= 0) return def;
    size_t len = strlen(s);
    if (len > 0 && (s[len-1] == 'K' || s[len-1] == 'k'))
        val *= 1024;
    return CLAMP((int)val, MIN_CHUNK, MAX_CHUNK);
}

void *init(ModuleChain *api, const char *config) {
    struct split_ctx *ctx = (struct split_ctx *)calloc(1, sizeof(*ctx));
    ctx->api = api;
    ctx->rr_idx = 0;
    ctx->seqnum = 0;
    ctx->merge.next_seq = 0;
    ctx->chunk_size_min = DEF_CHUNK_SIZE;
    ctx->chunk_size_max = DEF_CHUNK_SIZE;

    int extra_outputs = 1;
    if (config && config[0] != '\0') {
        const char *sp = strstr(config, "s:");
        if (sp) {
            sp += 2;
            const char *dash = strchr(sp, '-');
            if (dash) {
                char tmp[64];
                size_t len = (size_t)(dash - sp);
                if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
                memcpy(tmp, sp, len); tmp[len] = 0;
                ctx->chunk_size_min = parse_size(tmp, DEF_CHUNK_SIZE);
                ctx->chunk_size_max = parse_size(dash + 1, DEF_CHUNK_SIZE);
            } else {
                ctx->chunk_size_min = parse_size(sp, DEF_CHUNK_SIZE);
                ctx->chunk_size_max = ctx->chunk_size_min;
            }
            if (ctx->chunk_size_min > ctx->chunk_size_max) {
                int t = ctx->chunk_size_min;
                ctx->chunk_size_min = ctx->chunk_size_max;
                ctx->chunk_size_max = t;
            }
        }

        if (strncmp(config, "n:", 2) == 0)
            extra_outputs = atoi(config + 2);
        else if (strncmp(config, "split:", 6) == 0)
            extra_outputs = atoi(config + 6);
        else if (strcmp(config, "split") == 0)
            extra_outputs = 1;
    }
    if (extra_outputs < 1) extra_outputs = 1;

    if (api && api->request_outputs) {
        int ret = api->request_outputs(api->ctx, extra_outputs);
        ctx->num_outputs = ret > 0 ? ret : 1;
    } else {
        ctx->num_outputs = 1;
    }

    ctx->trace = config && strstr(config, "trace") != NULL;
    ctx->node_id = api && api->get_node_id ? api->get_node_id(api->ctx) : -1;

    if (ctx->chunk_size_min < ctx->chunk_size_max)
        srand((unsigned)(time(NULL) ^ (uintptr_t)ctx));

    return ctx;
}

static int next_chunk_size(struct split_ctx *ctx) {
    int lo = ctx->chunk_size_min;
    int hi = ctx->chunk_size_max;
    if (lo >= hi) return lo;
    return lo + (int)((unsigned)rand() % (unsigned)(hi - lo + 1));
}

static int process_split(struct split_ctx *ctx, int trigger_idx) {
    int sz = 0;
    uint8_t *in_buf = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!in_buf || sz <= 0) return -1;

    int offset = 0;
    while (offset < sz) {
        int remain = sz - offset;
        int chunk_len = next_chunk_size(ctx);
        if (chunk_len > remain) chunk_len = remain;
        int more = (chunk_len < remain) ? 1 : 0;

        uint8_t header[3];
        header[0] = (uint8_t)(ctx->seqnum & 0xFF);
        header[1] = (uint8_t)((ctx->seqnum >> 8) & 0xFF);
        header[2] = (uint8_t)more;

        int out_idx = ctx->rr_idx % ctx->num_outputs;
        uint8_t *out_buf = (uint8_t *)malloc((size_t)(chunk_len + 3));
        if (!out_buf) { free(in_buf); return -1; }
        out_buf[0] = header[0];
        out_buf[1] = header[1];
        out_buf[2] = header[2];
        memcpy(out_buf + 3, in_buf + offset, (size_t)chunk_len);

        int ret = ctx->api->write_packet(ctx->api->ctx, out_idx, out_buf, (size_t)chunk_len + 3);
        if (ret < 0) {
            free(out_buf);
            free(in_buf);
            return ret;
        }
        ctx->rr_idx++;
        ctx->seqnum++;
        offset += chunk_len;
    }
    free(in_buf);
    return 0;
}

static void merge_flush_packet(struct split_ctx *ctx, uint16_t last_seq, int write_output) {
    uint8_t *out_buf = NULL;
    int out_len = 0;
    int out_cap = 0;

    int n = (int)(uint16_t)(last_seq - ctx->merge.next_seq) + 1;
    for (int i = 0; i < n; i++) {
        uint16_t s = (uint16_t)(ctx->merge.next_seq + i);
        struct seq_entry *e = &ctx->merge.buf[s % MAX_SEQ_WINDOW];
        for (int j = 0; j < e->count; j++) {
            int needed = out_len + e->chunks[j].len;
            if (needed > out_cap) {
                out_cap = out_cap ? out_cap * 2 : 65536;
                if (out_cap < needed) out_cap = needed;
                uint8_t *tmp = (uint8_t *)realloc(out_buf, (size_t)out_cap);
                if (!tmp) { free(out_buf); return; }
                out_buf = tmp;
            }
            memcpy(out_buf + out_len, e->chunks[j].data, (size_t)e->chunks[j].len);
            out_len += e->chunks[j].len;
        }
        e->used = 0;
        e->more = 0;
        for (int j = 0; j < e->count; j++) free(e->chunks[j].data);
        free(e->chunks);
        e->chunks = NULL;
        e->count = 0;
        e->cap = 0;
    }

    ctx->merge.next_seq = (uint16_t)(last_seq + 1);

            if (out_len > 0 && out_buf) {
        int wr = ctx->api->write_packet(ctx->api->ctx, write_output, out_buf, (size_t)out_len);
        // wire_write takes ownership of out_buf (frees it), so we don't free here
        if (wr < 0)
            fprintf(stderr, "[split ERR] merge write_packet output=%d ret=%d\n", write_output, wr);
    }
}

static int process_merge(struct split_ctx *ctx, int trigger_idx) {
    int sz = 0;
    uint8_t *buf = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!buf || sz <= 0) return -1;

    if (sz < 3) { free(buf); return -1; }
    uint16_t seq = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    int more = buf[2];
    uint8_t *data = buf + 3;
    int data_len = sz - 3;

    size_t slot = seq % MAX_SEQ_WINDOW;
    struct seq_entry *e = &ctx->merge.buf[slot];
    if (e->used && e->seq != seq) {
        e->used = 0;
        e->more = 0;
        for (int i = 0; i < e->count; i++) free(e->chunks[i].data);
        free(e->chunks);
        e->chunks = NULL;
        e->count = 0;
        e->cap = 0;
    }
    e->seq = seq;

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
    e->more = more ? 1 : 0;

    free(buf);

    int write_output = (trigger_idx == 0) ? 1 : 0;

    uint16_t scan = ctx->merge.next_seq;
    int gap_detected = 0;
    while (1) {
        struct seq_entry *se = &ctx->merge.buf[scan % MAX_SEQ_WINDOW];
        if (!se->used || se->seq != scan) {
            if (!gap_detected) {
                fprintf(stderr, "[split dbg] merge gap: next_seq=%u scan=%u used=%d seq=%u ctx_seq=%u\n",
                        ctx->merge.next_seq, scan, se->used, se->seq, seq);
                gap_detected = 1;
            }
            break;
        }
        if (!se->more) {
            merge_flush_packet(ctx, scan, write_output);
            scan = ctx->merge.next_seq;
            continue;
        }
        scan++;
    }

    return 0;
}

int process(void *ctx_ptr, int dir, int trigger_idx) {
    struct split_ctx *ctx = (struct split_ctx *)ctx_ptr;
    if (dir == 0)
        return process_split(ctx, trigger_idx);
    else
        return process_merge(ctx, trigger_idx);
}

const char *moduleversion(void) {
    return "1.0.0";
}

const char *modulename(void) {
    return "split";
}

const char *moduledesc(void) {
    return "Split/merge module for multi-stream data transfer";
}

const char *modulehelp(void) {
    return "Splits large packets into chunks (round-robin), merges by seqnum.\n"
           "Config: \"n:N\" for N extra streams (default 1).\n"
           "        \"s:SIZE\" fixed chunk size, \"s:MIN-MAX\" random range (suffix K).\n"
           "        \"trace\" enables debug output.\n"
           "Default chunk size: 16384, min 64, max 65536. 2-byte seqnum, more flag.";
}
