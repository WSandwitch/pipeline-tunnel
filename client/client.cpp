#include "client.h"
#include "common/logger.h"
#include "common/utils.h"
#include "core/module_base.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <openssl/sha.h>

static std::string hex_sha256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data.data(), data.size(), hash);
    char hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = 0;
    return std::string(hex);
}

static std::string sockaddr_to_str(const struct sockaddr_in &addr) {
    char buf[64];
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return std::string(buf) + ":" + std::to_string(ntohs(addr.sin_port));
}

Client::Client(const std::string &server_host, uint16_t server_port,
               const std::string &password,
               const std::string &listen_addr, uint16_t listen_port,
               const std::string &target_addr,
               const std::vector<ModuleSpec> &modules,
                const std::string &mod_dir,
                int thread_count)
    : server_host_(server_host), server_port_(server_port),
      password_(password),
      listen_addr_(listen_addr), listen_port_(listen_port),
      target_addr_(target_addr),
      modules_(modules),
      mod_dir_(mod_dir) {
    kernel_ = std::make_shared<Kernel>();
    kernel_->start_workers(thread_count);
    chain_config_.modules = modules_;
    last_wire_activity_ = std::chrono::steady_clock::now();
}

Client::~Client() {
    stop();
}

bool Client::connect_to_server() {
    tcp_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd_ < 0) {
        log_error("client socket: %s", strerror(errno));
        return false;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port_);
    inet_pton(AF_INET, server_host_.c_str(), &addr.sin_addr);
    if (connect(tcp_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("client connect %s:%d: %s",
                  server_host_.c_str(), server_port_, strerror(errno));
        close(tcp_fd_); tcp_fd_ = -1;
        return false;
    }
    set_nonblock(tcp_fd_);
    int bufsz = 1048576;
    setsockopt(tcp_fd_, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(tcp_fd_, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    log_info("client connected to %s:%d", server_host_.c_str(), server_port_);
    return true;
}

void Client::send_packet(const Packet &pkt) {
    auto wire = proto_.serialize(pkt);
    if (write(tcp_fd_, wire.data(), wire.size()) < 0)
        log_error("client: write error");
}

void Client::send_control(const Packet &pkt) {
    auto serialized = proto_.serialize(pkt);
    // Wire format: [varint(1+proto_len)][WIRE_CONTROL][proto_data]
    std::vector<uint8_t> framed;
    size_t val = 1 + serialized.size(); // type byte + proto
    while (val > 0x7F) {
        framed.push_back((uint8_t)((val & 0x7F) | 0x80));
        val >>= 7;
    }
    framed.push_back((uint8_t)(val & 0x7F));
    framed.push_back(WIRE_CONTROL);
    framed.insert(framed.end(), serialized.begin(), serialized.end());
    if (data_connections_.empty()) return;
    // Round-robin across all connections
    size_t n = data_connections_.size();
    int start = control_rr_counter_.fetch_add(1) % (int)n;
    for (size_t i = 0; i < n; i++) {
        size_t idx = (size_t)((start + i) % (int)n);
        if (data_connections_[idx].fd < 0) continue;
        auto &dc = data_connections_[idx];
        dc.priority_buf.insert(dc.priority_buf.end(), framed.data(), framed.data() + framed.size());
        if (!dc.writer.registered)
            register_data_conn_epollout(idx, dc.fd);
        return;
    }
}

void Client::register_data_connection_reader(size_t idx) {
    if (idx >= data_connections_.size()) return;
    int fd = data_connections_[idx].fd;
    if (fd < 0) return;
    kernel_->add_fd_handler(fd, [this, idx](int ev_fd, uint32_t events) {
        (void)ev_fd;
        if (events & EPOLLIN) {
            auto &dc = data_connections_[idx];
            size_t old = dc.read_buf.size();
            dc.read_buf.resize(old + MAX_PACKET_SIZE);
            ssize_t n = read(dc.fd, dc.read_buf.data() + old, MAX_PACKET_SIZE);
            if (n > 0) {
                last_wire_activity_ = std::chrono::steady_clock::now();
                heartbeating_ = false;
                dc.read_buf.resize(old + (size_t)n);
                size_t &off = dc.read_offset;
                auto &buf = dc.read_buf;
                while (true) {
                    size_t avail = buf.size() - off;
                    if (avail < 1) break;
                    const uint8_t *ptr = buf.data() + off;
                    size_t pos = 0;
                    size_t val = 0;
                    int shift = 0;
                    while (pos < avail && shift < 56) {
                        uint8_t byte = ptr[pos++];
                        val |= (size_t)(byte & 0x7F) << shift;
                        if (!(byte & 0x80)) break;
                        shift += 7;
                    }
                    if (pos >= 10 || shift >= 56) { buf.clear(); off = 0; break; }
                    if (pos > avail || pos + val > avail || val < 1) break;

                    uint8_t type = ptr[pos];
                    if (type == WIRE_HEARTBEAT_PING || type == WIRE_HEARTBEAT_PONG) {
                        // Heartbeat — reset timer, nothing to dispatch
                        off += pos + val;
                        if (type == WIRE_HEARTBEAT_PING) {
                            // Received ping — send pong
                            uint8_t pkt[2] = {1, WIRE_HEARTBEAT_PONG};
                            dc.writer.write(dc.fd, pkt, 2);
                            if (!dc.writer.registered && dc.writer.size() > 0)
                                register_data_conn_epollout(idx, dc.fd);
                        }
                        continue;
                    }
                    if (type == WIRE_SHUTDOWN_WR_ACK) {
                        if (val < 2) { buf.clear(); off = 0; break; }
                        uint8_t cid = ptr[pos + 1];
                        log_debug("client: SHUTDOWN_WR_ACK conn_id=%u", cid);
                        auto it = conns_.find(cid);
                        if (it != conns_.end()) {
                            it->second.shutting_down_wr = true;
                            // Don't erase conn — ext fd can still receive data (half-close)
                            if (!it->second.writer.empty() && !it->second.writer.registered)
                                register_external_epollout(cid, it->second.fd);
                        }
                        off += pos + val;
                        continue;
                    }
                    if (type == WIRE_SHUTDOWN_WR) {
                        // Unexpected from server — just skip
                        off += pos + val;
                        continue;
                    }
                    if (type == WIRE_CONTROL) {
                        // Control message — parse proto directly, bypass Chain
                        Packet pkt;
                        size_t consumed = proto_.try_parse(ptr + pos + 1, val - 1, pkt);
                        if (consumed > 0) {
                            switch (pkt.type) {
                                case MSG_MODULE_LIST_RES:
                                    handle_module_list_res(pkt);
                                    break;
                                case MSG_CONNECT_OK:
                                    handle_connect_ok(pkt);
                                    break;
                                case MSG_CONNECT_FAIL:
                                    handle_connect_fail(pkt);
                                    break;
                                case MSG_DISCONNECT:
                                    handle_disconnect(pkt);
                                    break;
                                case MSG_CONNECT_PAUSE:
                                    handle_connect_pause(pkt);
                                    break;
                                case MSG_CONNECT_RESUME:
                                    handle_connect_resume(pkt);
                                    break;
                                case MSG_CHAIN_READY:
                                    handle_chain_ready(pkt);
                                    break;
                                case MSG_TRANSMIT_READY:
                                    handle_transmit_ready(pkt);
                                    break;
                                default:
                                    log_debug("client: unexpected control msg %d", (int)pkt.type);
                                    break;
                            }
                        }
                        off += pos + val;
                        continue;
                    }
                    if (type > WIRE_CONTROL) {
                        char hexbuf[256] = {0};
                        size_t dump_sz = buf.size() - off;
                        if (dump_sz > 64) dump_sz = 64;
                        for (size_t i = 0; i < dump_sz && i*3 < 255; i++)
                            snprintf(hexbuf + i*3, 4, "%02x ", (unsigned char)buf.data()[off+i]);
                        log_error("client: wire protocol violation type=%u off=%zu buf_sz=%zu avail=%zu val=%zu pos=%zu hex=%s, disconnecting",
                                  type, off, buf.size(), avail, val, pos, hexbuf);
                        buf.clear(); off = 0;
                        Kernel::request_stop();
                        break;
                    }

                    // type == 0: data — src_idx = idx+1 (1-based output port)
                    if (val < 1) { off += pos + val; continue; }
                    try {
                        dispatch_data_conn_packet(ptr + pos + 1, val - 1, (int)(idx + 1));
                    } catch (const std::exception &e) {
                        log_error("client: dispatch exception: %s (val=%zu, buf_sz=%zu)", e.what(), val, buf.size());
                        buf.clear(); off = 0;
                        break;
                    }
                    off += pos + val;
                }
                if (off > MAX_PACKET_SIZE) {
                    buf.erase(buf.begin(), buf.begin() + off);
                    off = 0;
                }
            }
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            log_debug("client: data connection %zu closed", idx);
        }
    }, EPOLLIN);
}

void Client::dispatch_data_conn_packet(const uint8_t *payload, size_t len, int src_idx) {
    if (len < 1) return;
    if (state_ < RUNNING) {
        std::vector<uint8_t> buf(payload, payload + len);
        pending_data_frames_.emplace_back(std::move(buf), src_idx);
        log_debug("client: data for conn_id=%u before ready, buffered (%zu pending)",
                  payload[0], pending_data_frames_.size());
        return;
    }
    uint8_t *blob = (uint8_t*)malloc(len);
    if (!blob) { log_error("client: dispatch OOM"); return; }
    memcpy(blob, payload, len);
    chain_->push_packet(blob, len, src_idx, 1);
}

void Client::process_wire_buffer(const uint8_t *data, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        size_t val = 0;
        int shift = 0;
        size_t save = pos;
        while (pos < len && shift < 56) {
            uint8_t byte = data[pos++];
            val |= (size_t)(byte & 0x7F) << shift;
            if (!(byte & 0x80)) break;
            shift += 7;
        }
        if (pos >= save + 10 || shift >= 56) break;
        if (pos + val > len || val < 1) break;
        uint8_t type = data[pos];
        if (type == WIRE_CONTROL) {
            Packet pkt;
            size_t consumed = proto_.try_parse(data + pos + 1, val - 1, pkt);
            if (consumed > 0) {
                switch (pkt.type) {
                    case MSG_MODULE_LIST_RES:
                        handle_module_list_res(pkt);
                        break;
                    case MSG_CONNECT_OK:
                        handle_connect_ok(pkt);
                        break;
                    case MSG_CONNECT_FAIL:
                        handle_connect_fail(pkt);
                        break;
                    case MSG_DISCONNECT:
                        handle_disconnect(pkt);
                        break;
                    case MSG_CONNECT_PAUSE:
                        handle_connect_pause(pkt);
                        break;
                    case MSG_CONNECT_RESUME:
                        handle_connect_resume(pkt);
                        break;
                    case MSG_CHAIN_READY:
                        handle_chain_ready(pkt);
                        break;
                    case MSG_TRANSMIT_READY:
                        handle_transmit_ready(pkt);
                        break;
                    default:
                        log_debug("client: unexpected control msg %d", (int)pkt.type);
                        break;
                }
            }
        } else if (type == 0) {
            if (val < 1) { pos += val; continue; }
            dispatch_data_conn_packet(data + pos + 1, val - 1, 1);
        }
        pos += val;
    }
}

void Client::register_data_conn_epollout(size_t idx, int fd) {
    if (idx >= data_connections_.size()) return;
    if (data_connections_[idx].writer.registered) return;
    data_connections_[idx].writer.registered = true;
    kernel_->add_fd_handler(fd, [this, idx](int ev_fd, uint32_t events) {
        (void)ev_fd;
        if (events & EPOLLOUT) {
            if (idx >= data_connections_.size()) return;
            auto &dc = data_connections_[idx];

            // Step 1: loop-flush writer until drained or EAGAIN
            bool drained;
            do {
                size_t old_ro = dc.writer.read_offset;
                drained = dc.writer.flush(dc.fd);
                if (dc.writer.read_offset == old_ro) break;
            } while (!drained);

            // Step 2: flush priority_buf (only if writer fully drained)
            if (drained) {
                while (!dc.priority_buf.empty()) {
                    ssize_t n = ::write(dc.fd, dc.priority_buf.data(), dc.priority_buf.size());
                    if (n > 0) {
                        if ((size_t)n >= dc.priority_buf.size())
                            dc.priority_buf.clear();
                        else
                            dc.priority_buf.erase(dc.priority_buf.begin(),
                                                  dc.priority_buf.begin() + (size_t)n);
                    }
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                }
            }

            // Step 3: one-shot flush writer (data after priority_buf)
            if (dc.priority_buf.empty())
                dc.writer.flush(dc.fd);

            // Step 4: resume paused ext connections if buffer drained below low_water
            if (dc.writer.size() <= dc.writer.low_water) {
                for (auto &[cid, ext] : conns_) {
                    if (ext.paused_by_backpressure) {
                        ext.paused_by_backpressure = false;
                        kernel_->mod_fd_events(ext.fd, EPOLLIN, 0);
                        log_debug("client: BW resume ext conn_id=%u (flush)", cid);
                    }
                }
            }

            // Step 5: deregister EPOLLOUT if everything flushed
            if (dc.writer.empty() && dc.priority_buf.empty()) {
                dc.writer.registered = false;
                kernel_->mod_fd_events(dc.fd, 0, EPOLLOUT);
            }
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            if (idx < data_connections_.size())
                data_connections_[idx].writer.clear();
        }
    }, EPOLLOUT);
}

void Client::stop_listener() {
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
    for (auto &kv : conns_) {
        if (kv.second.fd >= 0) {
            kernel_->del_fd(kv.second.fd);
            shutdown(kv.second.fd, SHUT_RDWR);
            close(kv.second.fd);
        }
    }
    conns_.clear();
}

void Client::stop() {
    stop_listener();
    for (size_t i = 1; i < data_connections_.size(); i++) {
        if (data_connections_[i].fd >= 0) {
            kernel_->del_fd(data_connections_[i].fd);
            close(data_connections_[i].fd);
        }
    }
    data_connections_.clear();
    if (chain_) {
        chain_->cancel();
        chain_->wait_drain();
    }
    if (kernel_)
        kernel_->stop();
    if (tcp_fd_ >= 0) {
        close(tcp_fd_);
        tcp_fd_ = -1;
    }
}

void Client::start_listener() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) { log_error("listener socket: %s", strerror(errno)); return; }
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port_);
    inet_pton(AF_INET, listen_addr_.c_str(), &addr.sin_addr);

    if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("listener bind %s:%d: %s", listen_addr_.c_str(), listen_port_, strerror(errno));
        close(listen_fd_); listen_fd_ = -1; return;
    }
    if (listen(listen_fd_, 16) < 0) {
        log_error("listener listen: %s", strerror(errno));
        close(listen_fd_); listen_fd_ = -1; return;
    }
    log_info("listener started on %s:%d", listen_addr_.c_str(), listen_port_);

    set_nonblock(listen_fd_);

    kernel_->add_fd_handler(listen_fd_, [this](int fd, uint32_t events) {
        if (!(events & EPOLLIN)) return;
        while (true) {
            struct sockaddr_in caddr;
            socklen_t alen = sizeof(caddr);
            int cfd = accept(fd, (struct sockaddr *)&caddr, &alen);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                break;
            }
            on_listener_accept(cfd, caddr);
        }
    }, EPOLLIN);
}

void Client::on_listener_accept(int cfd, const struct sockaddr_in &addr) {
    log_info("client: external connection from %s (pending conn_id)", sockaddr_to_str(addr).c_str());

    set_nonblock(cfd);
    int bufsz = 1048576;
    setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    pending_ext_.push_back({cfd, addr});

    std::vector<uint8_t> payload;
    payload.push_back((uint8_t)target_addr_.size());
    payload.insert(payload.end(), target_addr_.begin(), target_addr_.end());
    Packet pkt = Protocol::make_msg(MSG_CONNECT_REQ, payload);
    send_control(pkt);
}

void Client::on_external_recv(uint8_t conn_id, const uint8_t *data, size_t len) {
    if (state_ < RUNNING) return;
    uint8_t *blob = (uint8_t*)malloc(1 + len);
    if (!blob) { log_error("client: on_external_recv OOM"); return; }
    blob[0] = conn_id;
    memcpy(blob + 1, data, len);
    chain_->push_packet(blob, 1 + len, 0, 0);
}

void Client::on_external_disconnect(uint8_t conn_id) {
    log_info("client: external conn_id=%u disconnected", conn_id);
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    int fd = it->second.fd;
    conns_.erase(it);
    if (fd >= 0) {
        kernel_->del_fd(fd);
        close(fd);
    }
    Packet pkt = Protocol::make_msg(MSG_DISCONNECT, &conn_id, 1);
    send_control(pkt);
}

void Client::finish_disconnect(uint8_t conn_id) {
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    int fd = it->second.fd;
    it->second.writer.flush(fd);
    if (it->second.writer.empty()) {
        it->second.writer.registered = false;
        conns_.erase(it);
        if (fd >= 0) {
            kernel_->del_fd(fd);
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
    }
}

void Client::send_raw_to_external(uint8_t conn_id, const uint8_t *data, size_t len) {
    bool should_pause = false;
    bool should_resume = false;
    bool need_epollout = false;
    int fd = -1;
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    auto &w = it->second.writer;
    fd = it->second.fd;
    if (fd < 0) return;
    int ret = w.write(fd, data, len);
    if (ret > 0 && !w.registered)
        need_epollout = true;
    if (ret > 0 && !it->second.pause_sent) {
        it->second.pause_sent = true;
        should_pause = true;
    }
    if (w.size() < w.low_water && it->second.pause_sent) {
        it->second.pause_sent = false;
        should_resume = true;
    }
    if (need_epollout)
        register_external_epollout(conn_id, fd);
    if (should_pause) {
        log_debug("client: PAUSE sent conn_id=%u (writer=%zu)", conn_id, w.size());
        send_pause(conn_id);
    }
    if (should_resume) {
        log_debug("client: RESUME sent conn_id=%u (writer=%zu)", conn_id, w.size());
        send_resume(conn_id);
    }
}

void Client::on_server_data(const uint8_t *data, size_t len) {
    recv_buf_.insert(recv_buf_.end(), data, data + len);
    while (true) {
        Packet pkt;
        size_t consumed = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), pkt);
        if (consumed == 0) break;
        recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + consumed);

        switch (pkt.type) {
            case MSG_AUTH_CHALLENGE:
                if (state_ == AWAIT_AUTH1_CHALLENGE) handle_auth1_challenge(pkt);
                break;
            case MSG_AUTH_OK:
                if (state_ == AWAIT_AUTH1_OK) handle_auth1_ok(pkt);
                break;
            case MSG_AUTH_RESPONSE:
                if (state_ == AWAIT_AUTH2_OK) handle_auth2_challenge(pkt);
                break;
            case MSG_CONNECT_OK:
                if (state_ == AWAIT_CHAIN_READY || state_ == RUNNING) handle_connect_ok(pkt);
                break;
            case MSG_CONNECT_FAIL:
                if (state_ == AWAIT_CHAIN_READY || state_ == RUNNING) handle_connect_fail(pkt);
                break;
            case MSG_DISCONNECT:
                if (state_ != DISCONNECTED) handle_disconnect(pkt);
                break;
            case MSG_CONNECT_PAUSE:
                if (state_ == RUNNING) handle_connect_pause(pkt);
                break;
            case MSG_CONNECT_RESUME:
                if (state_ == RUNNING) handle_connect_resume(pkt);
                break;
            default:
                break;
        }
        if (chain_) break;
    }
}

void Client::handle_auth1_challenge(const Packet &pkt) {
    challenge1_.assign((const char *)pkt.payload.data(), pkt.payload.size());
    Packet response = Protocol::make_msg(MSG_AUTH_RESPONSE,
        hex_sha256(challenge1_ + password_).data(), 64);
    send_packet(response);
    state_ = AWAIT_AUTH1_OK;
}

void Client::handle_auth1_ok(const Packet &pkt) {
    if (pkt.payload.size() < 1 || pkt.payload[0] != 0x01) {
        log_error("client: auth1 failed");
        state_ = DISCONNECTED;
        Kernel::request_stop();
        return;
    }
    // Extract session_id from payload[1..8]
    if (pkt.payload.size() >= 9) {
        memcpy(&session_id_, &pkt.payload[1], 8);
        log_info("client: auth1 OK, session_id=%llx", (unsigned long long)session_id_);
    } else {
        log_info("client: auth1 OK");
    }
    client_challenge_ = std::to_string(rand()) + std::to_string(time(nullptr));
    Packet chal = Protocol::make_msg(MSG_AUTH_CHALLENGE, client_challenge_.data(), client_challenge_.size());
    send_packet(chal);
    state_ = AWAIT_AUTH2_OK;
}

void Client::handle_auth2_challenge(const Packet &pkt) {
    std::string got((const char *)pkt.payload.data(), pkt.payload.size());
    std::string expected = hex_sha256(client_challenge_ + password_);
    if (got != expected) {
        log_error("client: auth2 failed");
        state_ = DISCONNECTED;
        Kernel::request_stop();
        return;
    }
    log_info("client: mutual auth done");

    // Load modules if not already loaded
    if (!mod_dir_.empty()) {
        ModuleBase::load(mod_dir_);
    }

    // Setup kernel_wire_write lambda
    chain_kapi_.ctx = &chain_ref_;
    chain_kapi_.alloc_module_id = [](void*) -> int { static std::atomic<int> n{0}; return n++; };
    chain_kapi_.wire_write = [](void *ctx, int dst, const uint8_t *data, size_t len) -> int {
        auto *ref = (ChainRef*)ctx;
        auto *self = (Client*)ref->cb_ctx;
        log_debug("client: wire_write dst=%d len=%zu data[0]=%u", dst, len, len>0?data[0]:0);
        if (dst == 0) {
            if (len < 1) {
                free(const_cast<uint8_t*>(data));
                return -1;
            }
            if (data[0] == 255) {
                if (len < 3 || data[1] != CHAIN_CTRL_DISCONNECT) {
                    log_error("client: wire_write dst=0 unknown chain ctrl type=%u",
                              len>=2?data[1]:0);
                    free(const_cast<uint8_t*>(data));
                    return -1;
                }
                uint8_t conn_id = data[2];
                free(const_cast<uint8_t*>(data));
                std::lock_guard<std::mutex> lock(self->data_mtx_);
                self->pending_io_.push_back([self, conn_id]() {
                    log_info("client: chain ctrl disconnect conn_id=%u", conn_id);
                    auto it = self->conns_.find(conn_id);
                    if (it == self->conns_.end()) return;
                    it->second.disconnecting = true;
                    self->chain_ref_.in_fd.erase(conn_id);
                    self->chain_ref_.in_writer.erase(conn_id);
                    self->chain_ref_.in_paused.erase(conn_id);
                    self->pending_disconnect_ids_.push_back(conn_id);
                });
                return 0;
            }
            uint8_t conn_id = data[0];
            std::vector<uint8_t> payload(data + 1, data + len);
            {
                std::lock_guard<std::mutex> lock(self->data_mtx_);
                self->pending_io_.push_back([self, conn_id, payload = std::move(payload)]() {
                    self->send_raw_to_external(conn_id, payload.data(), payload.size());
                });
            }
            free(const_cast<uint8_t*>(data));
            return 0;
        }
        // dst >= 1: forward to correct wire connection with varint+type=0
        if (dst < 1 || (size_t)dst > self->data_connections_.size() ||
            self->data_connections_[dst-1].fd < 0) {
            log_error("client: wire_write dst=%d no data connection", dst);
            return -1;
        }
        int fd = self->data_connections_[dst-1].fd;
        int dc_idx = dst - 1;
        uint8_t varint_buf[10];
        size_t varint_len = 0;
        uint64_t total = 1 + len; // type + data (no sub-stream)
        while (total > 0x7F) {
            varint_buf[varint_len++] = (uint8_t)((total & 0x7F) | 0x80);
            total >>= 7;
        }
        varint_buf[varint_len++] = (uint8_t)(total & 0x7F);
        // Assemble full frame in one buffer to avoid partial-frame flush
        std::vector<uint8_t> frame;
        frame.reserve(varint_len + 1 + len);
        frame.insert(frame.end(), varint_buf, varint_buf + varint_len);
        frame.push_back(0); // type=0 (WIRE_DATA)
        frame.insert(frame.end(), data, data + len);
        int wret = self->data_connections_[dc_idx].writer.write(fd, frame.data(), frame.size());
        {
            std::lock_guard<std::mutex> lock(self->data_mtx_);
            self->pending_io_.push_back([self, dc_idx]() {
                if ((size_t)dc_idx < self->data_connections_.size() &&
                    self->data_connections_[dc_idx].fd >= 0)
                    self->register_data_conn_epollout(dc_idx, self->data_connections_[dc_idx].fd);
            });
        }
        if (wret > 0) {
            std::lock_guard<std::mutex> lock(self->data_mtx_);
            self->pending_io_.push_back([self, dc_idx]() {
                auto &w = self->data_connections_[dc_idx].writer;
                if (w.size() > w.high_water) {
                    for (auto &[cid, ext] : self->conns_) {
                        if (!ext.paused_by_backpressure) {
                            ext.paused_by_backpressure = true;
                            self->kernel_->mod_fd_events(ext.fd, 0, EPOLLIN);
                            log_debug("client: BW pause ext conn_id=%u", cid);
                        }
                    }
                }
            });
        } else {
            std::lock_guard<std::mutex> lock(self->data_mtx_);
            self->pending_io_.push_back([self, dc_idx]() {
                auto &w = self->data_connections_[dc_idx].writer;
                if (w.size() <= w.low_water) {
                    for (auto &[cid, ext] : self->conns_) {
                        if (ext.paused_by_backpressure) {
                            ext.paused_by_backpressure = false;
                            self->kernel_->mod_fd_events(ext.fd, EPOLLIN, 0);
                            log_debug("client: BW resume ext conn_id=%u", cid);
                        }
                    }
                }
            });
        }
        free(const_cast<uint8_t*>(data));
        return 0;
    };

    // Setup pause/resume and epollout callbacks
    chain_ref_.cb_ctx = this;
    chain_ref_.send_pause = [](void *ctx, uint8_t conn_id) {
        auto *self = (Client*)ctx;
        self->send_pause(conn_id);
    };
    chain_ref_.send_resume = [](void *ctx, uint8_t conn_id) {
        auto *self = (Client*)ctx;
        self->send_resume(conn_id);
    };
    chain_ref_.register_out_epollout = [](void *ctx) {
        auto *self = (Client*)ctx;
        int fd = self->chain_ref_.out_fds.empty() ? -1 : self->chain_ref_.out_fds[0];
        if (fd >= 0) self->register_data_conn_epollout(0, fd);
    };
    chain_ref_.register_in_epollout = [](void *ctx, uint8_t conn_id) {
        auto *self = (Client*)ctx;
        auto it = self->conns_.find(conn_id);
        if (it != self->conns_.end())
            self->register_external_epollout(conn_id, it->second.fd);
    };

    // Create Chain
    chain_guard_ = std::make_shared<bool>(true);
    chain_ = std::make_unique<Chain>(chain_config_, &chain_kapi_,
                                     &kernel_->pool(), chain_guard_);
    if (!chain_ || !chain_->valid()) {
        log_error("client: chain creation failed or empty");
        state_ = DISCONNECTED;
        Kernel::request_stop();
        return;
    }

    // Setup data connection on wire fd
    send_packet(Protocol::make_msg(MSG_AUTH_OK, "\x01", 1));
    data_connections_.resize(1);
    data_connections_[0].fd = tcp_fd_;
    chain_ref_.out_fds = {tcp_fd_};
    chain_ref_.out_writer = &data_connections_[0].writer;
    register_data_connection_reader(0);
    // Process any leftover wire-format data that arrived in the same TCP segment
    if (!recv_buf_.empty()) {
        process_wire_buffer(recv_buf_.data(), recv_buf_.size());
        recv_buf_.clear();
    }

    // Set heartbeat tick
    kernel_->set_tick_callback([this]() {
        check_heartbeat();
        process_pending_io();
    });

    // Send MSG_MODULE_LIST_REQ with mids of all loaded modules
    std::vector<uint8_t> mids;
    mids.push_back((uint8_t)modules_.size());
    for (auto &m : modules_) {
        auto *base = ModuleBase::find(m.name);
        if (!base) {
            log_error("client: module '%s' not loaded, cannot send mid", m.name.c_str());
            state_ = DISCONNECTED;
            Kernel::request_stop();
            return;
        }
        // Convert hex mid back to raw 32 bytes
        for (size_t i = 0; i < 64; i += 2) {
            char byte[3] = {base->mid[i], base->mid[i+1], 0};
            mids.push_back((uint8_t)strtol(byte, nullptr, 16));
        }
    }
    Packet mid_req = Protocol::make_msg(MSG_MODULE_LIST_REQ, mids);
    send_control(mid_req);
    state_ = AWAIT_MODULE_LIST_RES;
    log_info("client: MSG_MODULE_LIST_REQ sent, waiting for MSG_MODULE_LIST_RES");
}

void Client::handle_module_list_res(const Packet &pkt) {
    if (pkt.payload.empty()) return;
    if (pkt.payload[0] == 0x01) {
        log_info("client: server verified all modules");
        // Send MSG_CHAIN_CREATE
        std::vector<uint8_t> cfg_bytes;
        auto &mods = modules_;
        cfg_bytes.push_back((uint8_t)mods.size());
        for (auto &m : mods) {
            cfg_bytes.push_back((uint8_t)m.name.size());
            cfg_bytes.insert(cfg_bytes.end(), m.name.begin(), m.name.end());
            uint16_t plen = (uint16_t)m.params.size();
            cfg_bytes.push_back((uint8_t)(plen & 0xFF));
            cfg_bytes.push_back((uint8_t)(plen >> 8));
            cfg_bytes.insert(cfg_bytes.end(), m.params.begin(), m.params.end());
        }
        Packet create_pkt = Protocol::make_msg(MSG_CHAIN_CREATE, cfg_bytes);
        send_control(create_pkt);
        state_ = AWAIT_CHAIN_READY;
        log_info("client: MSG_CHAIN_CREATE sent, waiting for MSG_CHAIN_READY");
    } else {
        log_error("client: server rejected module list");
        // Print missing module names if available
        if (pkt.payload.size() >= 2) {
            size_t pos = 2;
            uint8_t mcount = pkt.payload[1];
            for (uint8_t i = 0; i < mcount; i++) {
                if (pos >= pkt.payload.size()) break;
                uint8_t nlen = pkt.payload[pos++];
                if (pos + nlen > pkt.payload.size()) break;
                std::string name((const char*)pkt.payload.data() + pos, nlen);
                log_error("client: missing module mid");
                pos += nlen;
            }
        }
        state_ = DISCONNECTED;
        Kernel::request_stop();
    }
}

void Client::handle_chain_ready(const Packet &pkt) {
    (void)pkt;
    if (state_ != AWAIT_CHAIN_READY) {
        log_info("client: MSG_CHAIN_READY ignored (state=%d)", (int)state_);
        return;
    }
    log_info("client: MSG_CHAIN_READY received, chain is ready");

    // Calculate total extra outputs from modules
    total_extra_outputs_ = chain_ ? chain_->total_extra_outputs() : 0;

    if (total_extra_outputs_ > 0) {
        state_ = AWAIT_TRANSMIT_READY;
        // Open secondary connections for split outputs
        open_secondary_connections();
    } else {
        // No extra outputs — already ready
        state_ = RUNNING;
        setup_ok_ = true;
        if (listen_port_ > 0) {
            log_info("client: starting listener on %s:%d",
                     listen_addr_.c_str(), listen_port_);
            start_listener();
        }
    }
}

void Client::open_secondary_connections() {
    if (secondary_conns_established_) {
        log_info("client: secondary connections already established, skipping");
        return;
    }
    log_info("client: opening %d secondary connections", total_extra_outputs_);
    secondary_conns_established_ = 1;
    for (int i = 1; i <= total_extra_outputs_; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            log_error("client: secondary socket %d: %s", i, strerror(errno));
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port_);
        inet_pton(AF_INET, server_host_.c_str(), &addr.sin_addr);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("client: secondary connect %d: %s", i, strerror(errno));
            close(fd);
            continue;
        }
        set_nonblock(fd);
        int bufsz = 1048576;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));

        // Send 9-byte handshake: [session_id:8][output_idx:1]
        uint8_t handshake[9];
        memcpy(handshake, &session_id_, 8);
        handshake[8] = (uint8_t)i;
        ssize_t nw = write(fd, handshake, 9);
        if (nw != 9) {
            log_error("client: secondary %d handshake write failed", i);
            close(fd);
            continue;
        }

        // Add to data_connections_
        if ((size_t)(i) >= data_connections_.size())
            data_connections_.resize(i + 1);
        data_connections_[i].fd = fd;
        register_data_connection_reader(i);
        log_info("client: secondary connection %d established (fd=%d)", i, fd);
    }
}

void Client::handle_transmit_ready(const Packet &pkt) {
    (void)pkt;
    log_info("client: MSG_TRANSMIT_READY received, all connections ready");

    if (state_ == AWAIT_TRANSMIT_READY) {
        state_ = RUNNING;
        setup_ok_ = true;

        // Drain any data frames buffered before RUNNING
        if (!pending_data_frames_.empty()) {
            log_info("client: processing %zu buffered data frame(s)",
                     pending_data_frames_.size());
            for (auto &frame : pending_data_frames_) {
                auto &buf = frame.first;
                int src_idx = frame.second;
                uint8_t *blob = (uint8_t*)malloc(buf.size());
                if (blob) {
                    memcpy(blob, buf.data(), buf.size());
                    chain_->push_packet(blob, buf.size(), src_idx, 1);
                }
            }
            pending_data_frames_.clear();
        }

        if (listen_port_ > 0) {
            log_info("client: starting listener on %s:%d",
                     listen_addr_.c_str(), listen_port_);
            start_listener();
        }
    } else {
        log_info("client: already running (listener started earlier)");
    }
}

void Client::register_external_epollout(uint8_t conn_id, int fd) {
    auto it = conns_.find(conn_id);
    if (it == conns_.end() || it->second.writer.registered) return;
    it->second.writer.registered = true;
    kernel_->add_fd_handler(fd, [this, conn_id](int, uint32_t events) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            conns_.erase(conn_id);
            return;
        }
        if (events & EPOLLOUT) {
            bool need_close = false;
            bool need_resume = false;
            int close_fd = -1;
            uint8_t resume_cid = 0;
            auto it2 = conns_.find(conn_id);
            if (it2 == conns_.end()) return;
            bool drained;
            do {
                size_t old_ro = it2->second.writer.read_offset;
                drained = it2->second.writer.flush(it2->second.fd);
                if (it2->second.writer.read_offset == old_ro) break;
            } while (!drained);
            if (it2->second.writer.empty()) {
                it2->second.writer.registered = false;
                kernel_->mod_fd_events(it2->second.fd, 0, EPOLLOUT);
                if (it2->second.disconnecting) {
                    need_close = true;
                    close_fd = it2->second.fd;
                    conns_.erase(it2);
                } else if (it2->second.pause_sent) {
                    it2->second.pause_sent = false;
                    need_resume = true;
                    resume_cid = conn_id;
                }
                // shutting_down_wr: half-close — keep conn alive for receiving data
            }
            if (need_close && close_fd >= 0) {
                kernel_->del_fd(close_fd);
                shutdown(close_fd, SHUT_RDWR);
                close(close_fd);
            }
            if (need_resume) {
                log_debug("client: RESUME sent conn_id=%u (writer drained)", resume_cid);
                send_resume(resume_cid);
            }
        }
    }, EPOLLOUT);
}

void Client::send_pause(uint8_t conn_id) {
    Packet pkt = Protocol::make_msg(MSG_CONNECT_PAUSE, &conn_id, 1);
    send_control(pkt);
}

void Client::send_resume(uint8_t conn_id) {
    Packet pkt = Protocol::make_msg(MSG_CONNECT_RESUME, &conn_id, 1);
    send_control(pkt);
}

void Client::resume_paused_dcfds() {
    for (size_t i = 0; i < data_connections_.size(); i++) {
        auto &dc = data_connections_[i];
        if (dc.paused) {
            dc.paused = false;
            kernel_->mod_fd_events(dc.fd, EPOLLIN, 0);
        }
    }
}

void Client::handle_connect_pause(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    it->second.paused = true;
    log_debug("client: PAUSE conn_id=%u (external %s)", conn_id, it->second.fd >= 0 ? "paused" : "nofd");
    if (it->second.fd >= 0)
        kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
}

void Client::handle_connect_resume(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    it->second.paused = false;
    log_debug("client: RESUME conn_id=%u", conn_id);
    if (it->second.fd >= 0)
        kernel_->mod_fd_events(it->second.fd, EPOLLIN, 0);
}

void Client::handle_connect_ok(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    log_info("client: MSG_CONNECT_OK conn_id=%u", conn_id);

    if (pending_ext_.empty()) {
        log_error("client: MSG_CONNECT_OK with no pending external fd");
        Packet pkt2 = Protocol::make_msg(MSG_DISCONNECT, &conn_id, 1);
        send_control(pkt2);
        return;
    }

    auto pc = pending_ext_.front();
    pending_ext_.pop_front();
    int cfd = pc.fd;

    conns_.emplace(conn_id, ExternalConn{cfd, pc.addr, true});
    chain_ref_.in_fd[conn_id] = cfd;
    chain_ref_.in_writer[conn_id] = &conns_[conn_id].writer;
    chain_ref_.in_paused[conn_id] = false;

    // EPOLLIN handler for external fd
    kernel_->add_fd_handler(cfd, [this, conn_id](int fd, uint32_t events) {
        if (events & EPOLLIN) {
            uint8_t *buf = (uint8_t*)malloc(MAX_PACKET_SIZE);
            if (!buf) { log_error("client: OOM in ext handler"); return; }
            ssize_t n = read(fd, buf + 1, MAX_PACKET_SIZE - 1);
            if (n > 0) {
                buf[0] = conn_id;
                chain_->push_packet(buf, (size_t)n + 1, 0, 0);
            } else {
                free(buf);
            }
            if (n == 0) {
                auto it = conns_.find(conn_id);
                if (it != conns_.end())
                    it->second.shutting_down_wr = true;
                if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
                    uint8_t pkt[3] = {2, WIRE_SHUTDOWN_WR, conn_id};
                    data_connections_[0].writer.write(data_connections_[0].fd, pkt, 3);
                    if (data_connections_[0].writer.size() > 0 && !data_connections_[0].writer.registered)
                        register_data_conn_epollout(0, data_connections_[0].fd);
                }
            }
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            auto it = conns_.find(conn_id);
            if (it != conns_.end() && it->second.shutting_down_wr) {
                if (it->second.fd >= 0) {
                    kernel_->del_fd(it->second.fd);
                    close(it->second.fd);
                }
                conns_.erase(it);
            } else {
                on_external_disconnect(conn_id);
            }
        }
    }, EPOLLIN);
}

void Client::handle_connect_fail(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    log_error("client: MSG_CONNECT_FAIL conn_id=%u", conn_id);
    // Cleanup pending fd
    for (auto &pc : pending_ext_) {
        close(pc.fd);
    }
    pending_ext_.clear();
}

void Client::handle_disconnect(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    log_info("client: server disconnected conn_id=%u", conn_id);
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    it->second.disconnecting = true;
    chain_ref_.in_fd.erase(conn_id);
    chain_ref_.in_writer.erase(conn_id);
    chain_ref_.in_paused.erase(conn_id);
    // Defer actual close — let chain workers finish first
    pending_disconnect_ids_.push_back(conn_id);
}

void Client::check_heartbeat() {
    if (state_ != RUNNING) return;
    auto now = std::chrono::steady_clock::now();
    auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_wire_activity_).count();

    if (idle_ms > 60000) {
        // 60 seconds without any data — wire dead
        log_error("client: heartbeat timeout, reconnecting");
        Kernel::request_stop();
        return;
    }

    if (idle_ms > 30000 && !heartbeating_) {
        // 30 seconds idle — send heartbeat on all connections
        heartbeating_ = true;
        uint8_t hb[2] = {1, WIRE_HEARTBEAT_PING}; // varint(1), type=WIRE_HEARTBEAT_PING
        for (size_t i = 0; i < data_connections_.size(); i++) {
            if (data_connections_[i].fd < 0) continue;
            data_connections_[i].writer.write(data_connections_[i].fd, hb, 2);
            if (!data_connections_[i].writer.registered && data_connections_[i].writer.size() > 0)
                register_data_conn_epollout(i, data_connections_[i].fd);
        }
    }
}

void Client::process_pending_io() {
    std::vector<std::function<void()>> batch;
    {
        std::lock_guard<std::mutex> lock(data_mtx_);
        batch.swap(pending_io_);
    }
    for (auto &fn : batch)
        fn();

    // Clean up disconnected connections once chain is drained
    if (!pending_disconnect_ids_.empty()) {
        if (!chain_ || chain_->is_drained()) {
            for (auto it = pending_disconnect_ids_.begin(); it != pending_disconnect_ids_.end(); ) {
                uint8_t cid = *it;
                auto cit = conns_.find(cid);
                if (cit == conns_.end()) {
                    it = pending_disconnect_ids_.erase(it);
                    continue;
                }
                cit->second.writer.flush(cit->second.fd);
                if (cit->second.writer.empty()) {
                    int fd = cit->second.fd;
                    conns_.erase(cit);
                    if (fd >= 0) {
                        kernel_->del_fd(fd);
                        shutdown(fd, SHUT_RDWR);
                        close(fd);
                    }
                    it = pending_disconnect_ids_.erase(it);
                } else {
                    // Need epollout to finish draining
                    if (!cit->second.writer.registered) {
                        cit->second.writer.registered = true;
                        int fd = cit->second.fd;
                        kernel_->add_fd_handler(fd,
                            [this, cid](int, uint32_t events) {
                                if (events & EPOLLOUT) {
                                    auto it2 = conns_.find(cid);
                                    if (it2 == conns_.end()) return;
                                    it2->second.writer.flush(it2->second.fd);
                                    if (it2->second.writer.empty()) {
                                        it2->second.writer.registered = false;
                                        kernel_->mod_fd_events(it2->second.fd, 0, EPOLLOUT);
                                    }
                                }
                                if (events & (EPOLLERR | EPOLLHUP))
                                    conns_.erase(cid);
                            }, EPOLLOUT);
                    }
                    ++it;
                }
            }
        }
    }
}

bool Client::start() {
    if (modules_.empty()) {
        log_info("client: no modules — tunnel-only mode");
    }
    if (!connect_to_server()) return false;
    state_ = AWAIT_AUTH1_CHALLENGE;

    kernel_->add_fd_handler(tcp_fd_, [this](int fd, uint32_t events) {
        if (events & EPOLLIN) {
            uint8_t buf[4096];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                on_server_data(buf, (size_t)n);
            } else if (n == 0) {
                log_info("client: server disconnected");
                state_ = DISCONNECTED;
                Kernel::request_stop();
            } else if (n < 0 && errno != EAGAIN) {
                log_info("client: server read error");
                state_ = DISCONNECTED;
                Kernel::request_stop();
            }
        }
    }, EPOLLIN);

    kernel_->start();
    if (chain_) {
        chain_->cancel();
        chain_->wait_drain();
    }
    return setup_ok_;
}
