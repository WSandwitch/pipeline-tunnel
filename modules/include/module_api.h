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
    int (*write_packet)(void *chain_ctx, int output_id, const uint8_t *data, size_t len);
    int (*request_heartbeat)(void *chain_ctx, int interval_sec);
    void (*set_src)(void *chain_ctx, int src_idx);
} ModuleChain;

void *init(ModuleChain *chain_api, const char *config);
int process(void *ctx, int dir, int trigger_idx, const uint8_t *data, size_t len);
const char *moduleversion(void);
const char *modulename(void);
const char *moduledesc(void);
const char *modulehelp(void);

#ifdef __cplusplus
}
#endif

#endif
