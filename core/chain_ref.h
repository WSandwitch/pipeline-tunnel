#ifndef CHAIN_REF_H
#define CHAIN_REF_H

#include <vector>
#include <unordered_map>
#include <cstdint>
#include "common/write_buffer.h"

// ChainRef — data needed by kernel_wire_write for routing.
// Populated by Client/Session as connections are created.
struct ChainRef {
    // Reverse path (dst=0): conn_id → ext/target fd and writer
    std::unordered_map<uint8_t, int> in_fd;
    std::unordered_map<uint8_t, WriteBuffer*> in_writer;
    std::unordered_map<uint8_t, bool> in_paused;

    // Forward path (dst=1): wire fd and its writer
    WriteBuffer *out_writer = nullptr;   // data_connections_[0].writer
    std::vector<int> out_fds;            // [0] = wire fd

    // Pause/resume callbacks (set by Client/Session)
    void *cb_ctx = nullptr;
    void (*send_pause)(void *ctx, uint8_t conn_id) = nullptr;
    void (*send_resume)(void *ctx, uint8_t conn_id) = nullptr;

    // EPOLLOUT registration callbacks (set by Client/Session)
    void (*register_out_epollout)(void *cb_ctx) = nullptr;
    void (*register_in_epollout)(void *cb_ctx, uint8_t conn_id) = nullptr;
};

#endif