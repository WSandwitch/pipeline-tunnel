#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char b64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_idx(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t b64_enc_len(size_t raw_len) {
    return ((raw_len + 2) / 3) * 4;
}

static size_t b64_dec_len(const char *in, size_t len) {
    (void)in;
    return (len / 4) * 3;
}

static void b64_encode(const unsigned char *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i += 3) {
        unsigned int val = (unsigned int)in[i] << 16;
        if (i + 1 < len) val |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < len) val |= (unsigned int)in[i + 2];
        out[0] = b64_chars[(val >> 18) & 0x3F];
        out[1] = b64_chars[(val >> 12) & 0x3F];
        out[2] = (i + 1 < len) ? b64_chars[(val >> 6) & 0x3F] : '=';
        out[3] = (i + 2 < len) ? b64_chars[val & 0x3F] : '=';
        out += 4;
    }
}

static int b64_decode(const char *in, size_t len, unsigned char *out) {
    if (len % 4 != 0) return -1;
    for (size_t i = 0; i < len; i += 4) {
        int a = b64_idx(in[i]);
        int b = b64_idx(in[i + 1]);
        int c = (in[i + 2] != '=') ? b64_idx(in[i + 2]) : 0;
        int d = (in[i + 3] != '=') ? b64_idx(in[i + 3]) : 0;
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        unsigned int val = ((unsigned int)a << 18) | ((unsigned int)b << 12) |
                           ((unsigned int)c << 6) | (unsigned int)d;
        out[0] = (unsigned char)(val >> 16);
        if (in[i + 2] != '=') out[1] = (unsigned char)(val >> 8);
        if (in[i + 3] != '=') out[2] = (unsigned char)val;
        out += 3;
    }
    return 0;
}

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
        size_t elen = b64_enc_len((size_t)sz);
        char *ebuf = (char *)malloc(elen);
        if (!ebuf) { free(pkt); return -1; }
        b64_encode(pkt, (size_t)sz, ebuf);
        if (ctx->trace)
            fprintf(stderr, "[base64 node=%d fw] sz=%d -> out=%zu\n", ctx->node_id, sz, elen);
        free(pkt);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, (const uint8_t *)ebuf, elen);
        free(ebuf);
    } else {
        size_t mlen = b64_dec_len((char *)pkt, (size_t)sz);
        unsigned char *rbuf = (unsigned char *)malloc(mlen);
        if (!rbuf) { free(pkt); return -1; }
        if (b64_decode((char *)pkt, (size_t)sz, rbuf) < 0) {
            free(rbuf); free(pkt); return -1;
        }
        size_t actual = mlen;
        if ((size_t)sz >= 2 && pkt[sz - 1] == '=') actual--;
        if ((size_t)sz >= 2 && pkt[sz - 2] == '=') actual--;
        if (ctx->trace)
            fprintf(stderr, "[base64 node=%d rv] sz=%d -> out=%zu\n", ctx->node_id, sz, actual);
        free(pkt);
        ret = ctx->api->write_packet(ctx->api->ctx, write_dst, rbuf, actual);
        free(rbuf);
    }

    return ret;
}

const char *moduleversion(void) {
    return "1.0.0";
}

const char *modulename(void) {
    return "base64";
}

const char *moduledesc(void) {
    return "Base64 encode/decode module";
}

const char *modulehelp(void) {
    return "Encodes data from external->wire, decodes from wire->external.\n"
           "Config: \"trace\" enables debug output.";
}
