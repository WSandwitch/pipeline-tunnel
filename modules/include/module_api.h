#ifndef MODULE_API_H
#define MODULE_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *ctx;
    int (*request_outputs)(void *kernel_ctx, int count);
    int (*get_output_fd)(void *kernel_ctx, int idx);
    int (*get_node_id)(void *kernel_ctx);
    int (*read_packet_size)(void *kernel_ctx, int fd);
    int (*read_packet)(void *kernel_ctx, int fd, uint8_t *buf);
    int (*write_packet)(void *kernel_ctx, int fd, const uint8_t *data, size_t len);
} ModuleKernel;

void *init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config);
int process(void *ctx, int dir, int trigger_fd);
const char *modulename(void);
const char *moduledesc(void);
const char *modulehelp(void);

#ifdef __cplusplus
}
#endif

#endif
