#include "modules/include/module_api.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

struct crypt_ctx {
    int in_fd;
    int out_fd;
    ModuleChain *chain_api;
    unsigned char key[32];
    int key_set;
    int trace;
    int node_id;
};

void *init(int in_fd, int out_fd, ModuleChain *chain_api, const char *config) {
    struct crypt_ctx *ctx = (struct crypt_ctx *)calloc(1, sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->kapi = kapi;
    ctx->key_set = 0;

    if (config && strlen(config) == 64) {
        for (int i = 0; i < 32; i++) {
            unsigned int byte;
            sscanf(config + i * 2, "%2x", &byte);
            ctx->key[i] = (unsigned char)byte;
        }
    } else {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)(config ? config : ""),
               config ? strlen(config) : 0, hash);
        memcpy(ctx->key, hash, 32);
    }

    ctx->trace = config && strstr(config, "trace") != NULL;
    ctx->node_id = kapi && kapi->get_node_id ? kapi->get_node_id(kapi->ctx) : -1;
    if (ctx->trace) {
        char key_hex[65];
        for (int i = 0; i < 32; i++) sprintf(key_hex + i * 2, "%02x", ctx->key[i]);
        key_hex[64] = '\0';
        fprintf(stderr, "[crypt node=%d init] key=%s\n", ctx->node_id, key_hex);
    }
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    struct crypt_ctx *ctx = (struct crypt_ctx *)ctx_ptr;

    int sz = ctx->kapi->read_packet_size(ctx->kapi->ctx, trigger_fd);
    if (sz <= 0) return -1;
    uint8_t *in_buf = (uint8_t *)malloc((size_t)sz);
    if (!in_buf) return -1;
    ctx->kapi->read_packet(ctx->kapi->ctx, trigger_fd, in_buf);

    int out_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;
    int ret;

    if (dir == 1) {
        unsigned char iv[16];
        do { RAND_bytes(iv, 16); } while (iv[0] == 0xFF);

        EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e_ctx, EVP_aes_256_ctr(), NULL, ctx->key, iv);

        uint8_t *out_buf = (uint8_t *)malloc((size_t)sz + 16);
        if (!out_buf) { free(in_buf); EVP_CIPHER_CTX_free(e_ctx); return -1; }
        int out_len = 0, tmp_len = 0;
        EVP_EncryptUpdate(e_ctx, out_buf, &out_len, in_buf, sz);
        EVP_EncryptFinal_ex(e_ctx, out_buf + out_len, &tmp_len);
        out_len += tmp_len;
        EVP_CIPHER_CTX_free(e_ctx);

        uint8_t *packet = (uint8_t *)malloc((size_t)out_len + 16);
        if (!packet) { free(in_buf); free(out_buf); return -1; }
        memcpy(packet, iv, 16);
        memcpy(packet + 16, out_buf, (size_t)out_len);

        if (ctx->trace) {
            char iv_hex[33];
            for (int i = 0; i < 16; i++) sprintf(iv_hex + i * 2, "%02x", iv[i]);
            iv_hex[32] = '\0';
            fprintf(stderr, "[crypt node=%d fw] iv=%s sz=%d → out=%d\n",
                    ctx->node_id, iv_hex, sz, out_len + 16);
        }

        ret = ctx->kapi->write_packet(ctx->kapi->ctx, out_fd, packet, (size_t)out_len + 16);
        free(packet);
        free(out_buf);
    } else {
        if (sz < 16) {
            fprintf(stderr, "[crypt] decrypt: packet too small (%d)\n", sz);
            free(in_buf); return -1;
        }

        unsigned char *iv = in_buf;
        uint8_t *ciphertext = in_buf + 16;
        int ct_len = sz - 16;

        EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d_ctx, EVP_aes_256_ctr(), NULL, ctx->key, iv);

        uint8_t *out_buf = (uint8_t *)malloc((size_t)ct_len);
        if (!out_buf) { free(in_buf); EVP_CIPHER_CTX_free(d_ctx); return -1; }
        int out_len = 0;
        EVP_DecryptUpdate(d_ctx, out_buf, &out_len, ciphertext, ct_len);
        EVP_CIPHER_CTX_free(d_ctx);

        if (ctx->trace) {
            char iv_hex[33];
            for (int i = 0; i < 16; i++) sprintf(iv_hex + i * 2, "%02x", iv[i]);
            iv_hex[32] = '\0';
            fprintf(stderr, "[crypt node=%d rv] iv=%s sz=%d → out=%d\n",
                    ctx->node_id, iv_hex, sz, out_len);
        }

        ret = ctx->kapi->write_packet(ctx->kapi->ctx, out_fd, out_buf, (size_t)out_len);
        free(out_buf);
    }

    free(in_buf);
    return ret;
}

const char *modulename(void) {
    return "crypt";
}

const char *moduledesc(void) {
    return "AES-256-CTR encrypt/decrypt module";
}

const char *modulehelp(void) {
    return "dir=1 encrypt, dir=0 decrypt.\n"
           "Config: 64-char hex key (or auto-generate if empty).\n"
           "\"trace\" enables debug output.\n"
            "IV prepended to ciphertext (16 bytes). No magic header.";
}
