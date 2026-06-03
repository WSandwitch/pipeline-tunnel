#ifndef CHAIN_H
#define CHAIN_H

#include <vector>
#include <memory>
#include <string>
#include <functional>
#include <mutex>
#include <atomic>
#include <utility>
#include <unordered_map>
#include "module.h"
#include "config.h"
#include "protocol.h"

class Kernel;

enum FdType { FD_IN = 0, FD_OUT = 1, FD_EXTRA = 2 };

struct FdInfo {
    int module_idx;
    FdType type;
};

struct ChainNode {
    std::unique_ptr<Module> mod;
    int in_fd = -1;
    int out_fd = -1;

    // Module-facing extra output fds (sv[0] from request_outputs socketpairs)
    std::vector<int> extra_out_fds;
    // Peer-facing ends of those socketpairs (sv[1]) — become in_fd of cloned tails
    std::vector<int> extra_peer_fds;

    std::string config_str;
    int pending_packet_size = 0;
    std::unique_ptr<ModuleKernel> kapi;
    void *kapi_ctx = nullptr;
};

class Chain {
public:
    Chain(uint64_t session_id, const ChainConfig &cfg,
          std::function<std::string(const std::string &mod_name)> path_resolver);
    ~Chain();

    void cleanup_kapi();

    uint64_t session_id() const { return session_id_; }

    bool build();

    int input_fd() const { return chain_in_fd_; }

    const std::vector<int> &output_fds() const { return chain_out_fds_; }

    void on_fd_ready(int fd);

    // Called by kernel when EPOLLOUT fires on a chain fd (for flushing buffered writes)
    void on_fd_write_ready(int fd);

    // Retry processing for any fds that have buffered data
    // that couldn't be written (e.g., due to full socket buffer)
    void retry_buffered();

    std::vector<std::pair<int, int>> module_fds() const;

    void set_kernel(Kernel *k) { kernel_ = k; }

    void pause();
    void resume();

    bool valid() const { return valid_; }

private:
    uint64_t session_id_;
    ChainConfig config_;
    std::function<std::string(const std::string &)> path_resolver_;
    bool valid_ = false;

    std::vector<ChainNode> nodes_;
    int chain_in_fd_ = -1;
    std::vector<int> chain_out_fds_;

    std::unique_ptr<std::atomic<bool>[]> busy_flags_;
    size_t busy_count_ = 0;

    std::unordered_map<int, FdInfo> fd_to_info_;

    // Per-fd input buffer for buffered reads (avoids partial-packet processing)
    std::unordered_map<int, std::vector<uint8_t>> fd_bufs_;
    std::unordered_map<int, size_t> fd_cursors_;

    // Per-fd output buffer for buffered writes (avoids partial-write corruption on EAGAIN)
    std::unordered_map<int, std::vector<uint8_t>> fd_pending_writes_;
    std::unordered_map<int, size_t> fd_write_cursors_;

    // Protects all per-fd maps above from concurrent insertion/data-race
    std::mutex fd_data_mutex_;

    int handle_read_packet_size(size_t mod_idx, int fd);
    int handle_read_packet(size_t mod_idx, int fd, uint8_t *buf);
    int handle_write_packet(size_t mod_idx, int fd, const uint8_t *data, size_t len);
    void drain_fd(int fd);

    void register_fd(int fd, size_t mod_idx, FdType type);

    Kernel *kernel_ = nullptr;

    static ModuleKernel make_kernel_api(Chain *chain, size_t mod_idx);
    int handle_request_outputs(size_t mod_idx, int count);
    int handle_get_output_fd(size_t mod_idx, int idx);
    static int read_packet_size_thunk(void *kernel_ctx, int fd);
    static int read_packet_thunk(void *kernel_ctx, int fd, uint8_t *buf);
    static int write_packet_thunk(void *kernel_ctx, int fd, const uint8_t *data, size_t len);
    static int request_outputs_thunk(void *kernel_ctx, int count);
    static int get_output_fd_thunk(void *kernel_ctx, int idx);
    static int get_node_id_thunk(void *kernel_ctx);
};

#endif
