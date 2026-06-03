#include "chain.h"
#include "kernel.h"
#include "common/logger.h"
#include "common/utils.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <fcntl.h>

// Uncomment DEBUG_CHAIN for verbose stderr tracing
// #define DEBUG_CHAIN
#ifdef DEBUG_CHAIN
#define chain_trace(...) fprintf(stderr, __VA_ARGS__)
#else
#define chain_trace(...) do {} while(0)
#endif

static int create_socketpair(int sv[2]) {
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (ret < 0) return ret;
    int bufsz = 1048576; // 1MB buffer for chain data
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    return 0;
}

Chain::Chain(uint64_t session_id, const ChainConfig &cfg,
             std::function<std::string(const std::string &)> path_resolver)
    : session_id_(session_id), config_(cfg),
      path_resolver_(std::move(path_resolver)) {}

void Chain::cleanup_kapi() {
    for (auto &n : nodes_) {
        if (n.kapi && n.kapi->ctx) {
            auto *p = (std::pair<Chain *, size_t> *)n.kapi->ctx;
            delete p;
            n.kapi->ctx = nullptr;
        }
    }
}

Chain::~Chain() {
    cleanup_kapi();
    for (auto &n : nodes_) {
        if (n.in_fd >= 0) close(n.in_fd);
        if (n.out_fd >= 0) close(n.out_fd);
        for (int fd : n.extra_out_fds)
            if (fd >= 0) close(fd);
    }
    if (chain_in_fd_ >= 0) close(chain_in_fd_);
    for (int fd : chain_out_fds_)
        if (fd >= 0) close(fd);
}

// ── fd registration helpers ──

void Chain::register_fd(int fd, size_t mod_idx, FdType type) {
    fd_to_info_[fd] = {(int)mod_idx, type};
}

// ── helper: drain fd into per-fd buffer (non-blocking) ──

void Chain::drain_fd(int fd) {
    // Caller must hold fd_data_mutex_
    std::vector<uint8_t> collected;
    uint8_t tmp[65536];
    ssize_t n;
    do {
        n = read(fd, tmp, sizeof(tmp));
        if (n > 0)
            collected.insert(collected.end(), tmp, tmp + n);
    } while (n > 0);
    if (!collected.empty()) {
        auto &buf = fd_bufs_[fd];
        buf.insert(buf.end(), collected.begin(), collected.end());
    }
}

// ── varint packet I/O (buffered) ──

int Chain::handle_read_packet_size(size_t mod_idx, int fd) {
    (void)mod_idx;
    std::lock_guard<std::mutex> lock(fd_data_mutex_);
    auto &buf = fd_bufs_[fd];
    auto &cursor = fd_cursors_[fd];

    int val = 0;
    int shift = 0;
    size_t start = cursor;

    while (cursor < buf.size()) {
        uint8_t byte = buf[cursor++];
        val |= (int)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) return val;
        shift += 7;
    }

    cursor = start;
    return -1;
}

int Chain::handle_read_packet(size_t mod_idx, int fd, uint8_t *buf) {
    ChainNode &node = nodes_[mod_idx];
    int remaining = node.pending_packet_size;
    node.pending_packet_size = 0;

    std::lock_guard<std::mutex> lock(fd_data_mutex_);
    auto &fdbuf = fd_bufs_[fd];
    auto &cursor = fd_cursors_[fd];

    if (cursor + (size_t)remaining > fdbuf.size())
        return -1;

    memcpy(buf, fdbuf.data() + cursor, (size_t)remaining);
    cursor += (size_t)remaining;
    return 0;
}

int Chain::handle_write_packet(size_t mod_idx, int fd,
                               const uint8_t *data, size_t len) {
    (void)mod_idx;
    std::vector<uint8_t> frame;
    size_t val = len;
    while (val > 0x7F) {
        frame.push_back((uint8_t)((val & 0x7F) | 0x80));
        val >>= 7;
    }
    frame.push_back((uint8_t)(val & 0x7F));
    frame.insert(frame.end(), data, data + len);

    ssize_t w = write(fd, frame.data(), frame.size());
    if (w == (ssize_t)frame.size())
        return 0;

    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::lock_guard<std::mutex> lock(fd_data_mutex_);
            fd_pending_writes_[fd] = std::move(frame);
            fd_write_cursors_[fd] = 0;
            if (kernel_)
                kernel_->mod_chain_fd_events(fd, EPOLLOUT, 0);
            return 0;
        }
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(fd_data_mutex_);
        fd_pending_writes_[fd].assign(frame.begin() + w, frame.end());
        fd_write_cursors_[fd] = 0;
    }
    if (kernel_)
        kernel_->mod_chain_fd_events(fd, EPOLLOUT, 0);
    return 0;
}

// ── thunks ──

int Chain::read_packet_size_thunk(void *kernel_ctx, int fd) {
    auto *data = (std::pair<Chain *, size_t> *)kernel_ctx;
    int sz = data->first->handle_read_packet_size(data->second, fd);
    if (sz >= 0)
        data->first->nodes_[data->second].pending_packet_size = sz;
    return sz;
}

int Chain::read_packet_thunk(void *kernel_ctx, int fd, uint8_t *buf) {
    auto *data = (std::pair<Chain *, size_t> *)kernel_ctx;
    return data->first->handle_read_packet(data->second, fd, buf);
}

int Chain::write_packet_thunk(void *kernel_ctx, int fd,
                              const uint8_t *data, size_t len) {
    auto *p = (std::pair<Chain *, size_t> *)kernel_ctx;
    return p->first->handle_write_packet(p->second, fd, data, len);
}

int Chain::request_outputs_thunk(void *kernel_ctx, int count) {
    auto *data = (std::pair<Chain *, size_t> *)kernel_ctx;
    return data->first->handle_request_outputs(data->second, count);
}

int Chain::get_output_fd_thunk(void *kernel_ctx, int idx) {
    auto *data = (std::pair<Chain *, size_t> *)kernel_ctx;
    return data->first->handle_get_output_fd(data->second, idx);
}

int Chain::get_node_id_thunk(void *kernel_ctx) {
    auto *data = (std::pair<Chain *, size_t> *)kernel_ctx;
    return (int)data->second;
}

ModuleKernel Chain::make_kernel_api(Chain *chain, size_t mod_idx) {
    auto *ctx = new std::pair<Chain *, size_t>(chain, mod_idx);
    ModuleKernel kapi = {};
    kapi.ctx = ctx;
    kapi.request_outputs = request_outputs_thunk;
    kapi.get_output_fd = get_output_fd_thunk;
    kapi.get_node_id = get_node_id_thunk;
    kapi.read_packet_size = read_packet_size_thunk;
    kapi.read_packet = read_packet_thunk;
    kapi.write_packet = write_packet_thunk;
    return kapi;
}

int Chain::handle_request_outputs(size_t mod_idx, int count) {
    ChainNode &node = nodes_[mod_idx];
    node.extra_out_fds.resize(count);
    node.extra_peer_fds.resize(count);

    for (int i = 0; i < count; i++) {
        int sv[2];
        if (create_socketpair(sv) < 0) {
            log_error("request_outputs: socketpair failed");
            return -1;
        }
        set_nonblock(sv[0]);
        set_nonblock(sv[1]);
        node.extra_out_fds[i] = sv[0];
        node.extra_peer_fds[i] = sv[1];
        // Register extra fd for epoll
        register_fd(node.extra_out_fds[i], mod_idx, FD_EXTRA);
    }

    log_debug("request_outputs: mod=%zu count=%d", mod_idx, count);
    return count;
}

int Chain::handle_get_output_fd(size_t mod_idx, int idx) {
    ChainNode &node = nodes_[mod_idx];
    if (idx < (int)node.extra_out_fds.size())
        return node.extra_out_fds[idx];
    return -1;
}

// ── build ──

bool Chain::build() {
    // Phase 1: load all modules
    for (size_t i = 0; i < config_.modules.size(); i++) {
        ChainNode node;

        std::string so_path = path_resolver_(config_.modules[i].name);
        if (so_path.empty())
            so_path = config_.modules[i].name + ".so";
        node.mod = std::make_unique<Module>();
        if (!node.mod->load(so_path)) {
            log_error("chain: failed to load module %s", so_path.c_str());
            return false;
        }

        nodes_.push_back(std::move(node));
    }

    if (nodes_.empty()) {
        // Passthrough: single socketpair chain_in ↔ chain_out
        int sv[2];
        if (create_socketpair(sv) < 0) {
            log_error("chain: passthrough socketpair failed");
            return false;
        }
        set_nonblock(sv[0]);
        set_nonblock(sv[1]);
        chain_in_fd_ = sv[0];
        chain_out_fds_.push_back(sv[1]);
        valid_ = true;
        log_info("chain %llx built: passthrough tunnel (no modules)",
                 (unsigned long long)session_id_);
        return true;
    }

    // Phase 2: chain input socketpair
    {
        int sv[2];
        if (create_socketpair(sv) < 0) {
            log_error("chain: input socketpair failed");
            return false;
        }
        set_nonblock(sv[0]);
        set_nonblock(sv[1]);
        chain_in_fd_ = sv[0];
        nodes_[0].in_fd = sv[1];
        register_fd(nodes_[0].in_fd, 0, FD_IN);
        chain_trace( "[chain sess=%llx] Phase2: chain_in_fd=%d in_fd=%d FD_IN=%d\n",
                (unsigned long long)session_id_, chain_in_fd_, nodes_[0].in_fd, FD_IN);
    }

    // Phase 3: interconnect nodes (one pair of socketpairs per link)
    for (size_t i = 0; i + 1 < nodes_.size(); i++) {
        int sv[2];
        if (create_socketpair(sv) < 0) {
            log_error("chain: interconnect socketpair %zu failed", i);
            return false;
        }
        set_nonblock(sv[0]);
        set_nonblock(sv[1]);
        nodes_[i].out_fd = sv[0];
        nodes_[i + 1].in_fd = sv[1];
        register_fd(nodes_[i].out_fd, i, FD_OUT);
        register_fd(nodes_[i + 1].in_fd, i + 1, FD_IN);
    }

    // Phase 4: last node output → chain_out
    {
        ChainNode &last = nodes_.back();
        if (last.extra_out_fds.empty()) {
            int sv[2];
            if (create_socketpair(sv) < 0) {
                log_error("chain: output socketpair failed");
                return false;
            }
            set_nonblock(sv[0]);
            set_nonblock(sv[1]);
            last.out_fd = sv[0];
            chain_out_fds_.push_back(sv[1]);
            register_fd(last.out_fd, nodes_.size() - 1, FD_OUT);
            chain_trace( "[chain sess=%llx] Phase4: out_fd=%d FD_OUT=%d\n",
                    (unsigned long long)session_id_, last.out_fd, FD_OUT);
        }
    }

    // Phase 5: init all modules
    for (size_t i = 0; i < nodes_.size(); i++) {
        nodes_[i].kapi = std::make_unique<ModuleKernel>(make_kernel_api(this, i));
        nodes_[i].kapi_ctx = nodes_[i].kapi->ctx;
        const char *cfg_str = config_.modules[i].params.c_str();
        nodes_[i].config_str = cfg_str;

        if (!nodes_[i].mod->init(nodes_[i].in_fd, nodes_[i].out_fd, nodes_[i].kapi.get(), cfg_str)) {
            log_error("chain: module %s init failed", nodes_[i].mod->name());
            return false;
        }
    }

    // Phase 5.5: clone tails for forked modules (modules with extra outputs)
    {
        // Collect fork jobs from original nodes
        size_t orig_count = nodes_.size();
        struct ForkJob {
            size_t tail_start_orig;
            size_t tail_len;
            std::vector<int> peer_fds;
        };
        std::vector<ForkJob> jobs;
        for (size_t i = 0; i < orig_count; i++) {
            auto &n = nodes_[i];
            if (n.extra_peer_fds.empty()) continue;
            size_t tail_start = i + 1;
            size_t tail_len = (tail_start < orig_count) ? (orig_count - tail_start) : 0;
            jobs.push_back({tail_start, tail_len, std::move(n.extra_peer_fds)});
            n.extra_peer_fds.clear();
        }

        size_t job_idx = 0;
        while (job_idx < jobs.size()) {
            auto &job = jobs[job_idx];

            for (int peer_fd : job.peer_fds) {
                if (job.tail_len == 0) {
                    chain_out_fds_.push_back(peer_fd);
                    continue;
                }

                // Clone tail_start_orig .. tail_start_orig+tail_len-1
                for (size_t t = 0; t < job.tail_len; t++) {
                    size_t orig_idx = job.tail_start_orig + t;
                    ChainNode &orig = nodes_[orig_idx];

                    ChainNode clone;
                    std::string so_path = path_resolver_(config_.modules[orig_idx].name);
                    if (so_path.empty())
                        so_path = config_.modules[orig_idx].name + ".so";
                    clone.mod = std::make_unique<Module>();
                    if (!clone.mod->load(so_path)) {
                        log_error("chain: failed to load module %s for clone", so_path.c_str());
                        return false;
                    }
                    clone.config_str = orig.config_str;

                    if (t == 0) {
                        clone.in_fd = peer_fd;
                    } else {
                        int sv[2];
                        if (create_socketpair(sv) < 0) {
                            log_error("chain: clone interconnect socketpair failed");
                            return false;
                        }
                        set_nonblock(sv[0]);
                        set_nonblock(sv[1]);
                        // Link previous clone (last in nodes_) to this clone
                        nodes_.back().out_fd = sv[0];
                        clone.in_fd = sv[1];
                    }

                    if (t == job.tail_len - 1) {
                        int sv[2];
                        if (create_socketpair(sv) < 0) {
                            log_error("chain: clone output socketpair failed");
                            return false;
                        }
                        set_nonblock(sv[0]);
                        set_nonblock(sv[1]);
                        clone.out_fd = sv[0];
                        chain_out_fds_.push_back(sv[1]);
                    }

                    // Push before setting kapi/init so make_kernel_api finds it
                    nodes_.push_back(std::move(clone));
                    auto &new_node = nodes_.back();
                    size_t new_idx = nodes_.size() - 1;

                    register_fd(new_node.in_fd, new_idx, FD_IN);
                    if (new_node.out_fd >= 0)
                        register_fd(new_node.out_fd, new_idx, FD_OUT);
                    // Interconnect out (sv[0]) was just set on nodes_[new_idx-1].out_fd
                    if (t > 0)
                        register_fd(nodes_[new_idx - 1].out_fd, new_idx - 1, FD_OUT);

                    new_node.kapi = std::make_unique<ModuleKernel>(make_kernel_api(this, new_idx));
                    new_node.kapi_ctx = new_node.kapi->ctx;

                    if (!new_node.mod->init(new_node.in_fd, new_node.out_fd,
                                            new_node.kapi.get(), new_node.config_str.c_str())) {
                        log_error("chain: cloned module %s init failed", new_node.mod->name());
                        return false;
                    }

                    // If clone also has extra outputs, add a new fork job for remaining tail
                    if (!new_node.extra_peer_fds.empty()) {
                        size_t ct_start = job.tail_start_orig + t + 1;
                        size_t ct_len = (ct_start < orig_count) ? (orig_count - ct_start) : 0;
                        jobs.push_back({ct_start, ct_len,
                                        std::move(new_node.extra_peer_fds)});
                    }
                }
            }

            job_idx++;
        }
    }

    // Phase 6: init busy flags
    busy_count_ = nodes_.size();
    busy_flags_ = std::make_unique<std::atomic<bool>[]>(busy_count_);
    for (size_t i = 0; i < busy_count_; i++)
        busy_flags_[i].store(false);

    log_info("chain %llx built: %zu nodes, %zu out fds",
             (unsigned long long)session_id_, nodes_.size(),
             chain_out_fds_.size());
    for (auto &kv : fd_to_info_)
        chain_trace( "[chain sess=%llx] fd_to_info fd=%d mod=%d type=%d\n",
                (unsigned long long)session_id_, kv.first, kv.second.module_idx, kv.second.type);
    valid_ = true;
    return true;
}

// ── dispatch (buffered) ──

void Chain::on_fd_ready(int fd) {
    auto it = fd_to_info_.find(fd);
    if (it == fd_to_info_.end()) {
        return;
    }

    size_t idx = (size_t)it->second.module_idx;
    if (idx >= busy_count_) return;

    bool expected = false;
    if (!busy_flags_[idx].compare_exchange_strong(expected, true)) {
        return;
    }

    int dir;
    switch (it->second.type) {
        case FD_IN:
            dir = 1;
            break;
        case FD_OUT:
            dir = 0;
            break;
        case FD_EXTRA:
            dir = 0;
            break;
        default:
            dir = 1;
            break;
    }

    {
        std::lock_guard<std::mutex> lock(fd_data_mutex_);
        drain_fd(fd);
    }

    while (true) {
        size_t save;
        {
            std::lock_guard<std::mutex> lock(fd_data_mutex_);
            auto &buf = fd_bufs_[fd];
            auto &cursor = fd_cursors_[fd];

            size_t tmp_pos = cursor;
            size_t pkt_val = 0;
            int shift = 0;
            bool has_varint = false;
            while (tmp_pos < buf.size()) {
                uint8_t byte = buf[tmp_pos++];
                pkt_val |= (size_t)(byte & 0x7F) << shift;
                if (!(byte & 0x80)) { has_varint = true; break; }
                shift += 7;
            }
            size_t varint_bytes = tmp_pos - cursor;
            if (!has_varint || cursor + varint_bytes + pkt_val > buf.size())
                break;
            save = cursor;
        }

        int ret = nodes_[idx].mod->process(dir, fd);
        if (ret < 0) {
            std::lock_guard<std::mutex> lock(fd_data_mutex_);
            fd_cursors_[fd] = save;
            break;
        }

        {
            std::lock_guard<std::mutex> lock(fd_data_mutex_);
            auto &buf = fd_bufs_[fd];
            auto &cursor = fd_cursors_[fd];
            size_t consumed = cursor - save;
            if (consumed > 0) {
                buf.erase(buf.begin(), buf.begin() + consumed);
                cursor = 0;
            }
        }
    }

    busy_flags_[idx].store(false);
}

void Chain::retry_buffered() {
    std::vector<int> to_retry;
    {
        std::lock_guard<std::mutex> lock(fd_data_mutex_);
        for (auto &kv : fd_to_info_) {
            int fd = kv.first;
            auto it = fd_bufs_.find(fd);
            if (it != fd_bufs_.end()) {
                auto cit = fd_cursors_.find(fd);
                if (cit != fd_cursors_.end() && cit->second < it->second.size()) {
                    to_retry.push_back(fd);
                }
            }
        }
    }
    for (int fd : to_retry)
        on_fd_ready(fd);
}

void Chain::on_fd_write_ready(int fd) {
    std::vector<uint8_t> buf;
    size_t cursor = 0;
    {
        std::lock_guard<std::mutex> lock(fd_data_mutex_);
        auto pw = fd_pending_writes_.find(fd);
        if (pw == fd_pending_writes_.end()) return;
        buf = pw->second;
        cursor = fd_write_cursors_[fd];
    }

    size_t remaining = buf.size() - cursor;
    ssize_t w = write(fd, buf.data() + cursor, remaining);

    bool flushed = false;
    {
        std::lock_guard<std::mutex> lock(fd_data_mutex_);
        if (w > 0) {
            fd_write_cursors_[fd] += (size_t)w;
            if (fd_write_cursors_[fd] >= fd_pending_writes_[fd].size()) {
                fd_pending_writes_.erase(fd);
                fd_write_cursors_.erase(fd);
                flushed = true;
                if (kernel_)
                    kernel_->mod_chain_fd_events(fd, 0, EPOLLOUT);
            }
        } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            fd_pending_writes_.erase(fd);
            fd_write_cursors_.erase(fd);
            flushed = true;
            if (kernel_)
                kernel_->mod_chain_fd_events(fd, 0, EPOLLOUT);
        }
    }
    if (flushed)
        retry_buffered();
}

// ── helpers ──

std::vector<std::pair<int, int>> Chain::module_fds() const {
    std::vector<std::pair<int, int>> result;
    for (auto &kv : fd_to_info_) {
        result.emplace_back(kv.first, kv.second.module_idx);
    }
    return result;
}

void Chain::pause() {
    log_debug("chain %llx: paused", (unsigned long long)session_id_);
}

void Chain::resume() {
    log_debug("chain %llx: resumed", (unsigned long long)session_id_);
}
