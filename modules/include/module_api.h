#ifndef MODULE_API_H
#define MODULE_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *ctx;
    int (*request_outputs)(void *chain_ctx, int count);
    int (*get_output_fd)(void *chain_ctx, int idx);
    int (*get_node_id)(void *chain_ctx);
    void *(*get_packet)(void *chain_ctx, int idx, int *out_size);
    int (*write_packet)(void *chain_ctx, int output_id, const uint8_t *data, size_t len);
} ModuleChain;

void *init(ModuleChain *chain_api, const char *config);
int process(void *ctx, int dir, int trigger_idx);
const char *modulename(void);
const char *moduledesc(void);
const char *modulehelp(void);

#ifdef __cplusplus
}
#endif

#endif
