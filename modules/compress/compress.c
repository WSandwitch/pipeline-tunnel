#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>
#include <zstd.h>

struct compress_ctx {
    int in_fd;
    int out_fd;
    ModuleKernel *kapi;
    int level;
    int use_zstd;
    int trace;
    int node_id;
};

static int gzip_compress(const uint8_t *in, int in_len,
                         uint8_t *out, int out_cap, int level) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (deflateInit2(&strm, level, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;
    strm.next_in = (uint8_t *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = out;
    strm.avail_out = (uInt)out_cap;
    int ret = deflate(&strm, Z_FINISH);
    int out_len = (int)strm.total_out;
    deflateEnd(&strm);
    if (ret != Z_STREAM_END) return -1;
    return out_len;
}

static int gzip_decompress(const uint8_t *in, int in_len,
                           uint8_t **out, int *out_cap) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, 15 | 16) != Z_OK)
        return -1;
    strm.next_in = (uint8_t *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = *out;
    strm.avail_out = (uInt)*out_cap;
    int ret;
    do {
        ret = inflate(&strm, Z_FINISH);
        if ((ret == Z_OK || ret == Z_BUF_ERROR) && strm.avail_out == 0) {
            size_t written = strm.total_out;
            int new_cap = *out_cap * 2;
            uint8_t *new_buf = (uint8_t *)realloc(*out, (size_t)new_cap);
            if (!new_buf) { inflateEnd(&strm); return -1; }
            *out = new_buf;
            *out_cap = new_cap;
            strm.next_out = *out + written;
            strm.avail_out = (uInt)(*out_cap - written);
        } else if (ret != Z_OK && ret != Z_BUF_ERROR) {
            break;
        }
    } while (ret != Z_STREAM_END);
    int out_len = (int)strm.total_out;
    inflateEnd(&strm);
    if (ret != Z_STREAM_END) return -1;
    return out_len;
}

static int zstd_compress(const uint8_t *in, int in_len,
                         uint8_t *out, int out_cap, int level) {
    size_t ret = ZSTD_compress(out, (size_t)out_cap, in, (size_t)in_len, level);
    if (ZSTD_isError(ret)) return -1;
    return (int)ret;
}

static int zstd_decompress(const uint8_t *in, int in_len,
                           uint8_t **out, int *out_cap) {
    size_t ret = ZSTD_decompress(*out, (size_t)*out_cap, in, (size_t)in_len);
    if (ret == 0) return -1;
    if (ZSTD_isError(ret)) {
        size_t needed = ZSTD_getFrameContentSize(in, (size_t)in_len);
        if (needed == ZSTD_CONTENTSIZE_UNKNOWN || needed == ZSTD_CONTENTSIZE_ERROR)
            return -1;
        uint8_t *new_buf = (uint8_t *)realloc(*out, (size_t)needed);
        if (!new_buf) return -1;
        *out = new_buf;
        *out_cap = (int)needed;
        ret = ZSTD_decompress(*out, (size_t)*out_cap, in, (size_t)in_len);
        if (ZSTD_isError(ret)) return -1;
    }
    return (int)ret;
}

void *init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config) {
    struct compress_ctx *ctx = (struct compress_ctx *)malloc(sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->kapi = kapi;
    ctx->level = Z_DEFAULT_COMPRESSION;
    ctx->use_zstd = 0;

    if (config && config[0] != '\0') {
        if (strcmp(config, "gzip") == 0)
            ;
        else if (strncmp(config, "gzip:", 5) == 0)
            ctx->level = atoi(config + 5);
        else if (strcmp(config, "zstd") == 0)
            ctx->use_zstd = 1;
        else if (strncmp(config, "zstd:", 5) == 0) {
            ctx->use_zstd = 1;
            ctx->level = atoi(config + 5);
        } else if (strcmp(config, "trace") != 0)
            fprintf(stderr, "[compress] unknown config '%s'\n", config);
    }
    ctx->trace = config && strstr(config, "trace") != NULL;
    ctx->node_id = kapi && kapi->get_node_id ? kapi->get_node_id(kapi->ctx) : -1;
    if (ctx->trace)
        fprintf(stderr, "[compress node=%d init] %s:%d\n",
                ctx->node_id, ctx->use_zstd ? "zstd" : "gzip", ctx->level);
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    struct compress_ctx *ctx = (struct compress_ctx *)ctx_ptr;

    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *in_buf = (uint8_t *)malloc((size_t)sz);
    if (!in_buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, in_buf);

    uint8_t *out_buf;
    int out_cap;
    if (dir == 1) {
        if (ctx->use_zstd)
            out_cap = (int)ZSTD_compressBound((size_t)sz);
        else
            out_cap = (int)deflateBound(0, (uLong)sz);
    } else {
        out_cap = sz * 10;
    }
    if (out_cap < 65536) out_cap = 65536;
    out_buf = (uint8_t *)malloc((size_t)out_cap);
    if (!out_buf) { free(in_buf); return -1; }
    int out_len;

    if (dir == 1) {
        if (ctx->use_zstd)
            out_len = zstd_compress(in_buf, sz, out_buf, out_cap, ctx->level);
        else
            out_len = gzip_compress(in_buf, sz, out_buf, out_cap, ctx->level);
        free(in_buf);
    } else {
        if (ctx->use_zstd)
            out_len = zstd_decompress(in_buf, sz, &out_buf, &out_cap);
        else
            out_len = gzip_decompress(in_buf, sz, &out_buf, &out_cap);
        free(in_buf);
    }

    if (out_len < 0) {
        free(out_buf);
        fprintf(stderr, "[compress] %s failed\n", dir ? "compress" : "decompress");
        return -1;
    }

    int out_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;
    if (ctx->trace) {
        double ratio = out_len > 0 ? (double)sz / out_len : 0.0;
        fprintf(stderr, "[compress node=%d %s] %s sz=%d → out=%d (%.1fx)\n",
                ctx->node_id, dir ? "fw" : "rv",
                ctx->use_zstd ? "zstd" : "gzip", sz, out_len, ratio);
    }
    int wr = ctx->kapi->write_packet(ctx->kapi->ctx, out_fd, out_buf, (size_t)out_len);
    free(out_buf);
    return wr;
}

const char *modulename(void) {
    return "compress";
}

const char *moduledesc(void) {
    return "Compression module (gzip+zstd)";
}

const char *modulehelp(void) {
    return "dir=1 compress, dir=0 decompress.\n"
           "Config: \"gzip\" (default), \"gzip:N\", \"zstd\", \"zstd:N\".\n"
           "\"trace\" enables debug output.\n"
           "Uses same algorithm for both directions.";
}
