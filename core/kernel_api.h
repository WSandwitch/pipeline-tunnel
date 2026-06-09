#ifndef KERNEL_API_H
#define KERNEL_API_H

#include <cstdint>
#include <cstddef>

struct KernelAPI {
    void *ctx;
    int  (*alloc_module_id)(void *ctx);
    int  (*wire_write)(void *ctx, int dst, const uint8_t *data, size_t len);
};

#endif
