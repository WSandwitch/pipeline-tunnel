#include "session.h"
#include "common/logger.h"
#include "common/utils.h"
#include "core/module_base.h"
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <unordered_map>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <openssl/sha.h>

extern std::unordered_map<uint64_t, std::weak_ptr<Session>> g_session_registry;
extern std::unordered_map<uint64_t, std::shared_ptr<Session>> g_paused_sessions;

static uint64_t generate_id() {
    static uint64_t counter = 0;
    return ++counter + ((uint64_t)time(nullptr) << 32);
}

Session::Session(int client_fd, const std::string &password,
                 std::shared_ptr<Kernel> kernel,
                 int heartbeat_interval_ms)
    : client_fd_(client_fd), password_(password),
      kernel_(std::move(kernel)), session_id_(generate_id()),
      heartbeat_interval_ms_(heartbeat_interval_ms) {
    last_wire_activity_ = std::chrono::steady_clock::now();
}

Session::~Session() {
    if (chain_) {
        chain_->cancel();
        chain_->wait_drain();
    }
    g_session_registry.erase(session_id_);
    g_paused_sessions.erase(session_id_);
    close_all_targets();
    for (auto &dc : data_connections_)
        if (dc.fd >= 0) {
            kernel_->del_fd(dc.fd);
            close(dc.fd);
        }
    data_connections_.clear();
    if (client_fd_ >= 0) {
        kernel_->del_fd(client_fd_);
        close(client_fd_);
    }
}

void Session::send_packet(const Packet &pkt) {
    auto wire = proto_.serialize(pkt);
    ssize_t n = write(client_fd_, wire.data(), wire.size());
    if (n < 0 && errno != EAGAIN)
        log_error("session %llx: send_packet write error: %s",
                  (unsigned long long)session_id_, strerror(errno));
}

static std::string hex_sha256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data.data(), data.size(), hash);
    char hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = 0;
    return std::string(hex);
}

void Session::on_data(const uint8_t *data, size_t len) {
    std::lock_guard<std::mutex> lock(io_mutex_);
    if (state_ < AUTH_DONE) {
        // Auth phase — parse Protocol serialized format
        recv_buf_.insert(recv_buf_.end(), data, data + len);
        while (true) {
            Packet pkt;
            size_t consumed = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), pkt);
            if (consumed == 0) break;
            recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + consumed);
            switch (pkt.type) {
                case MSG_AUTH_RESPONSE:
                    if (state_ == AWAIT_AUTH1_CHALLENGE_RESP)
                        handle_auth_challenge_response(pkt);
                    else if (state_ == AWAIT_AUTH2_RESPONSE)
                        handle_auth2_response(pkt);
                    break;
                case MSG_AUTH_OK:
                    if (state_ == AWAIT_AUTH2_RESPONSE)
                        handle_auth2_response(pkt);
                    break;
                case MSG_AUTH_CHALLENGE:
                    if (state_ == AWAIT_AUTH1_OK)
                        handle_auth2_challenge(pkt);
                    break;
                case MSG_RECONNECT:
                    if (state_ == AWAIT_AUTH1_CHALLENGE_RESP || state_ == AWAIT_CONNECT_REQ || state_ == AWAIT_CHAIN_CREATE)
                        handle_reconnect(pkt);
                    break;
                default:
                    break;
            }
            if (state_ >= AUTH_DONE) break;
        }
        return;
    }

    // Post-auth: wire format data
    if (client_fd_ < 0) return;
    recv_buf_.insert(recv_buf_.end(), data, data + len);
    while (true) {
        Packet pkt;
        size_t consumed = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), pkt);
        if (consumed == 0) break;
        recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + consumed);

        switch (pkt.type) {
            case MSG_AUTH_RESPONSE:
                if (state_ == AWAIT_AUTH2_RESPONSE)
                    handle_auth2_response(pkt);
                break;
            case MSG_AUTH_OK:
                if (state_ == AWAIT_AUTH2_RESPONSE)
                    handle_auth2_response(pkt);
                break;
            case MSG_AUTH_CHALLENGE:
                if (state_ == AWAIT_AUTH1_OK)
                    handle_auth2_challenge(pkt);
                break;
            case MSG_RECONNECT:
                if (state_ == AWAIT_CONNECT_REQ || state_ == AWAIT_CHAIN_CREATE)
                    handle_reconnect(pkt);
                break;
            case MSG_CONNECT_REQ:
                if (state_ == AWAIT_CHAIN_CREATE || state_ == RUNNING)
                    handle_connect_req(pkt);
                break;
            case MSG_CHAIN_CREATE:
                if (state_ == AWAIT_CHAIN_CREATE)
                    handle_chain_create(pkt);
                break;
            case MSG_DISCONNECT:
                if (state_ == RUNNING || state_ == AWAIT_CHAIN_CREATE)
                    handle_disconnect(pkt);
                break;
            case MSG_CONNECT_PAUSE:
                if (state_ == RUNNING || state_ == AWAIT_CHAIN_CREATE) {
                    if (pkt.payload.size() >= 1) {
                        uint8_t cid = pkt.payload[0];
                        auto it = targets_.find(cid);
                        if (it != targets_.end()) {
                            it->second.paused_by_client = true;
                            kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
                        }
                    }
                }
                break;
            case MSG_CONNECT_RESUME:
                if (state_ == RUNNING || state_ == AWAIT_CHAIN_CREATE) {
                    if (pkt.payload.size() >= 1) {
                        uint8_t cid = pkt.payload[0];
                        auto it = targets_.find(cid);
                        if (it != targets_.end()) {
                            it->second.paused_by_client = false;
                            kernel_->mod_fd_events(it->second.fd, EPOLLIN, 0);
                        }
                    }
                }
                break;
            default:
                log_debug("session %llx: unexpected msg %d",
                          (unsigned long long)session_id_, (int)pkt.type);
                break;
        }
    }
}

void Session::handle_auth_challenge_response(const Packet &pkt) {
    std::string expected = hex_sha256(challenge1_ + password_);
    std::string got((const char *)pkt.payload.data(), pkt.payload.size());
    if (got != expected) {
        log_error("session %llx: auth1 failed", (unsigned long long)session_id_);
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        state_ = DISCONNECTED;
        return;
    }
    log_info("session %llx: auth1 OK", (unsigned long long)session_id_);
    // Include session_id in AUTH_OK: [0x01][session_id:8]
    std::vector<uint8_t> ok_payload(9, 0);
    ok_payload[0] = 0x01;
    memcpy(&ok_payload[1], &session_id_, 8);
    Packet ok = Protocol::make_msg(MSG_AUTH_OK, ok_payload.data(), ok_payload.size());
    send_packet(ok);
    state_ = AWAIT_AUTH1_OK;
}

void Session::handle_auth2_challenge(const Packet &pkt) {
    std::string challenge((const char *)pkt.payload.data(), pkt.payload.size());
    std::string resp = hex_sha256(challenge + password_);
    Packet response = Protocol::make_msg(MSG_AUTH_RESPONSE, resp.data(), resp.size());
    send_packet(response);
    state_ = AWAIT_AUTH2_RESPONSE;
}

void Session::handle_auth2_response(const Packet &pkt) {
    if (pkt.payload.size() >= 1 && pkt.payload[0] == 0x01) {
        log_info("session %llx: mutual auth done", (unsigned long long)session_id_);

        // Setup kernel_wire_write lambda
        chain_kapi_.ctx = this;
        chain_kapi_.alloc_module_id = [](void*) -> int { static std::atomic<int> n{0}; return n++; };
        chain_kapi_.wire_write = [](void *ctx, int dst, const uint8_t *data, size_t len) -> int {
            auto *self = (Session*)ctx;
            auto *ref = &self->chain_ref_;
            log_debug("session %llx: wire_write dst=%d len=%zu data[0]=%u",
                      (unsigned long long)self->session_id_, dst, len, len>0?data[0]:0);
            if (dst == 0) {
                if (len < 1 || data[0] == 255) {
                    if (len >= 1)
                        log_error("session %llx: wire_write dst=0 conn_id=255 invalid",
                                  (unsigned long long)self->session_id_);
                    free(const_cast<uint8_t*>(data));
                    return -1;
                }
                uint8_t conn_id = data[0];
                int ret = 0;
                bool need_epollout = false;
                bool need_pause = false;
                {
                    std::lock_guard<std::mutex> lock(self->targets_mtx_);
                    auto tit = self->targets_.find(conn_id);
                    if (tit == self->targets_.end()) { free(const_cast<uint8_t*>(data)); return -1; }
                    ret = tit->second.writer.write(tit->second.fd, data + 1, len - 1);
                    if (ret > 0) need_epollout = true;
                    if (ret > 0 && !ref->in_paused[conn_id]) {
                        need_pause = true;
                        ref->in_paused[conn_id] = true;
                    }
                }
                if (need_epollout) {
                    std::lock_guard<std::mutex> lock(self->data_mtx_);
                    self->pending_io_.push_back([self, conn_id]() {
                        auto it = self->targets_.find(conn_id);
                        if (it != self->targets_.end() && self->chain_ref_.register_in_epollout)
                            self->chain_ref_.register_in_epollout(self->chain_ref_.cb_ctx, conn_id);
                    });
                }
                if (need_pause) {
                    std::lock_guard<std::mutex> lock(self->data_mtx_);
                    self->pending_io_.push_back([self, conn_id]() {
                        auto it = self->targets_.find(conn_id);
                        if (it != self->targets_.end() && !it->second.pause_sent) {
                            it->second.pause_sent = true;
                            self->send_pause(conn_id);
                        }
                    });
                }
                free(const_cast<uint8_t*>(data));
                return ret;
            }
            if (dst < 1 || (size_t)dst > self->data_connections_.size() ||
                self->data_connections_[dst-1].fd < 0) {
                log_error("session %llx: wire_write dst=%zu no data connection",
                          (unsigned long long)self->session_id_, (size_t)dst);
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
            int ret = self->data_connections_[dc_idx].writer.write(fd, frame.data(), frame.size());
            if (ret > 0) {
                std::lock_guard<std::mutex> lock(self->data_mtx_);
                self->pending_io_.push_back([self, dc_idx, fd]() {
                    if ((size_t)dc_idx < self->data_connections_.size() &&
                        self->data_connections_[dc_idx].fd >= 0)
                        self->register_data_conn_epollout(dc_idx, fd);
                });
            }
            if (ret > 0) {
                std::lock_guard<std::mutex> lock(self->data_mtx_);
                self->pending_io_.push_back([self]() {
                    for (auto &[cid, tgt] : self->targets_) {
                        if (!tgt.paused_by_backpressure) {
                            tgt.paused_by_backpressure = true;
                            self->kernel_->mod_fd_events(tgt.fd, 0, EPOLLIN);
                            log_debug("session %llx: BW pause target conn_id=%u",
                                      (unsigned long long)self->session_id_, cid);
                        }
                    }
                });
            } else {
                bool all_below = true;
                for (auto &check_dc : self->data_connections_) {
                    if (check_dc.fd >= 0 && check_dc.writer.size() > check_dc.writer.low_water) {
                        all_below = false;
                        break;
                    }
                }
                if (all_below) {
                    std::lock_guard<std::mutex> lock(self->data_mtx_);
                    self->pending_io_.push_back([self]() {
                        for (auto &[cid, tgt] : self->targets_) {
                            if (tgt.paused_by_backpressure) {
                                tgt.paused_by_backpressure = false;
                                self->kernel_->mod_fd_events(tgt.fd, EPOLLIN, 0);
                                log_debug("session %llx: BW resume target conn_id=%u",
                                          (unsigned long long)self->session_id_, cid);
                            }
                        }
                    });
                }
            }
            free(const_cast<uint8_t*>(data));
            return ret;
        };

        // Setup pause/resume and epollout callbacks
        chain_ref_.cb_ctx = this;
        chain_ref_.send_pause = [](void *ctx, uint8_t conn_id) {
            auto *self = (Session*)ctx;
            self->send_pause(conn_id);
        };
        chain_ref_.send_resume = [](void *ctx, uint8_t conn_id) {
            auto *self = (Session*)ctx;
            self->send_resume(conn_id);
        };
        chain_ref_.register_out_epollout = [](void *ctx) {
            auto *self = (Session*)ctx;
            for (size_t i = 0; i < self->data_connections_.size(); i++) {
                if (self->data_connections_[i].fd < 0) continue;
                if (!self->data_connections_[i].writer.registered &&
                    self->data_connections_[i].writer.size() > 0)
                    self->register_data_conn_epollout(i, self->data_connections_[i].fd);
            }
        };
        chain_ref_.register_in_epollout = [](void *ctx, uint8_t conn_id) {
            auto *self = (Session*)ctx;
            auto it = self->targets_.find(conn_id);
            if (it != self->targets_.end())
                self->register_target_epollout(conn_id, it->second.fd);
        };

        // Switch to wire format reader
        data_connections_.resize(1);
        data_connections_[0].fd = client_fd_;
        chain_ref_.out_fds = {client_fd_};
        chain_ref_.out_writer = &data_connections_[0].writer;
        register_data_connection_reader(0);
        // Process any leftover wire-format data that arrived in the same TCP segment
        if (!recv_buf_.empty()) {
            process_wire_buffer(recv_buf_.data(), recv_buf_.size());
            recv_buf_.clear();
        }
        state_ = AWAIT_CHAIN_CREATE;
    } else {
        log_error("session %llx: auth2 failed", (unsigned long long)session_id_);
        state_ = DISCONNECTED;
    }
}

void Session::handle_module_list_req(const Packet &pkt) {
    log_debug("session %llx: MSG_MODULE_LIST_REQ received (payload_size=%zu)",
              (unsigned long long)session_id_, pkt.payload.size());
    // Parse: [count:u8][mid_32bytes]...
    size_t pos = 0;
    if (pkt.payload.size() < 1) return;
    uint8_t count = pkt.payload[pos++];
    if (pos + (size_t)count * 32 > pkt.payload.size()) return;

    std::vector<std::string> missing;
    for (uint8_t i = 0; i < count; i++) {
        // Convert raw 32-byte mid to hex for comparison
        char hex[65];
        for (int j = 0; j < 32; j++)
            sprintf(hex + j * 2, "%02x", pkt.payload[pos + j]);
        hex[64] = 0;
        std::string mid_hex(hex);
        pos += 32;

        // Check if any loaded module matches this mid
        bool found = false;
        for (auto &[name, base] : ModuleBase::bases) {
            (void)name;
            if (base.mid == mid_hex) {
                found = true;
                break;
            }
        }
        if (!found) {
            log_error("session %llx: missing module mid=%s",
                      (unsigned long long)session_id_, mid_hex.c_str());
            missing.push_back(mid_hex);
        }
    }

    if (missing.empty()) {
        Packet ok = Protocol::make_msg(MSG_MODULE_LIST_RES, "\x01", 1);
        log_info("session %llx: all %u modules verified", (unsigned long long)session_id_, count);
        send_control(ok);
    } else {
        // Build FAIL response: [\x00][count:u8][name_len:u8][name...]...
        std::vector<uint8_t> resp;
        resp.push_back(0x00);
        resp.push_back((uint8_t)missing.size());
        for (auto &m : missing) {
            resp.push_back((uint8_t)m.size());
            resp.insert(resp.end(), m.begin(), m.end());
        }
        Packet fail = Protocol::make_msg(MSG_MODULE_LIST_RES, resp);
        send_control(fail);
        log_error("session %llx: %zu module(s) missing, disconnecting",
                  (unsigned long long)session_id_, missing.size());
        state_ = DISCONNECTED;
    }
}

void Session::handle_chain_create(const Packet &pkt) {
    // Deserialize: [count:u8][name_len:u8][name...][params_len:u16][params...]...
    std::vector<ModuleSpec> mods;
    size_t pos = 0;
    if (pkt.payload.size() < 1) {
        log_error("session %llx: MSG_CHAIN_CREATE too short", (unsigned long long)session_id_);
        return;
    }
    uint8_t count = pkt.payload[pos++];
    for (uint8_t i = 0; i < count; i++) {
        if (pos + 1 > pkt.payload.size()) break;
        uint8_t name_len = pkt.payload[pos++];
        if (pos + name_len > pkt.payload.size()) break;
        std::string name((const char*)pkt.payload.data() + pos, name_len);
        pos += name_len;
        if (pos + 2 > pkt.payload.size()) break;
        uint16_t plen = (uint16_t)pkt.payload[pos] | ((uint16_t)pkt.payload[pos+1] << 8);
        pos += 2;
        if (pos + plen > pkt.payload.size()) break;
        std::string params((const char*)pkt.payload.data() + pos, plen);
        pos += plen;
        mods.push_back({name, params});
    }

    chain_config_.modules = mods;
    chain_ = std::make_unique<Chain>(chain_config_, &chain_kapi_,
                                     &kernel_->pool(), shared_from_this());
    if (!chain_ || !chain_->valid()) {
        log_error("session %llx: chain creation failed or empty, disconnecting",
                  (unsigned long long)session_id_);
        state_ = DISCONNECTED;
        return;
    }
    log_info("session %llx: chain created with %zu module(s)",
             (unsigned long long)session_id_, mods.size());

    // Register backpressure callbacks (raw this is safe: chain's wait_drain in ~Session
    // ensures no callback fires after Session is destroyed)
    chain_->set_pause_callback(0, [this](bool pause) {
        std::lock_guard<std::mutex> lock(data_mtx_);
        pending_io_.push_back([this, pause]() {
            std::lock_guard<std::mutex> tlock(targets_mtx_);
            for (auto &[id, tgt] : targets_) {
                (void)id;
                if (tgt.fd >= 0) {
                    if (pause)
                        kernel_->mod_fd_events(tgt.fd, 0, EPOLLIN);
                    else
                        kernel_->mod_fd_events(tgt.fd, EPOLLIN, 0);
                }
            }
        });
    });
    chain_->set_pause_callback(1, [this](bool pause) {
        std::lock_guard<std::mutex> lock(data_mtx_);
        pending_io_.push_back([this, pause]() {
            if (client_fd_ >= 0) {
                if (pause)
                    kernel_->mod_fd_events(client_fd_, 0, EPOLLIN);
                else
                    kernel_->mod_fd_events(client_fd_, EPOLLIN, 0);
            }
        });
    });

    state_ = RUNNING;

    // Resize data_connections_ for split outputs
    total_extra_outputs_ = chain_->total_extra_outputs();
    if ((size_t)(1 + total_extra_outputs_) > data_connections_.size()) {
        // Reserve before resize: data_connection_reader callback (running on
        // the same stack) holds a reference into data_connections_; resize
        // would reallocate and invalidate it, corrupting wire parsing.
        data_connections_.reserve(1 + total_extra_outputs_);
        data_connections_.resize(1 + total_extra_outputs_);
        log_info("session %llx: data_connections resized to %zu",
                 (unsigned long long)session_id_, data_connections_.size());
    }

    // Process any pending data connections that arrived before chain create
    process_pending_data_conns();

    // If pending connections made all data connections ready, send TRANSMIT_READY
    if (total_extra_outputs_ > 0) {
        bool all_ready = true;
        for (auto &dc : data_connections_) {
            if (dc.fd < 0) { all_ready = false; break; }
        }
        if (all_ready && state_ == RUNNING) {
            process_pending_reconnect_targets();
            Packet trefdy = Protocol::make_msg(MSG_TRANSMIT_READY);
            send_control(trefdy);
            log_info("session %llx: MSG_TRANSMIT_READY sent (from pending data conns)",
                     (unsigned long long)session_id_);
        }
    }

    // Send MSG_CHAIN_READY (includes session_id for reconnect support)
    std::vector<uint8_t> ready_payload(9, 0x01);  // status + session_id
    memcpy(&ready_payload[1], &session_id_, 8);
    Packet ready = Protocol::make_msg(MSG_CHAIN_READY, ready_payload.data(), 9);
    send_control(ready);
    log_info("session %llx: MSG_CHAIN_READY sent", (unsigned long long)session_id_);

    // If no extra outputs, send TRANSMIT_READY immediately
    if (total_extra_outputs_ == 0) {
        process_pending_reconnect_targets();
        Packet trefdy = Protocol::make_msg(MSG_TRANSMIT_READY);
        send_control(trefdy);
        log_info("session %llx: MSG_TRANSMIT_READY sent (no extra outputs)",
                 (unsigned long long)session_id_);
    }
}

void Session::handle_reconnect(const Packet &pkt) {
    // Payload: 8 bytes SID + 64 bytes hex(SHA256(challenge + password))
    if (pkt.payload.size() != 72) {
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }
    uint64_t sid;
    memcpy(&sid, pkt.payload.data(), 8);
    std::string hash((const char *)pkt.payload.data() + 8, 64);
    std::string expected = hex_sha256(challenge1_ + password_);
    if (hash != expected) {
        log_error("session %llx: reconnect auth failed", (unsigned long long)session_id_);
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        state_ = DISCONNECTED;
        return;
    }
    auto it = g_session_registry.find(sid);
    if (it == g_session_registry.end() || it->second.expired()) {
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }
    auto old_session = it->second.lock();
    if (!old_session->reconnect(client_fd_)) {
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }
    log_info("session %llx: reconnected to session %llx",
             (unsigned long long)session_id_, (unsigned long long)sid);
    Packet ok = Protocol::make_msg(MSG_AUTH_OK, "\x01", 1);
    send_packet(ok);
    client_fd_ = -1;
    state_ = DISCONNECTED;
}

uint8_t Session::alloc_conn_id() {
    static uint8_t next = 0;
    return next++;
}

void Session::handle_connect_req(const Packet &pkt) {
    // MSG_CONNECT_REQ: [addr_len:u8][addr...]
    if (pkt.payload.size() < 1) {
        log_error("session %llx: MSG_CONNECT_REQ too short", (unsigned long long)session_id_);
        return;
    }
    uint8_t addr_len = pkt.payload[0];
    if (1 + addr_len > pkt.payload.size()) {
        log_error("session %llx: MSG_CONNECT_REQ addr length mismatch", (unsigned long long)session_id_);
        return;
    }
    std::string target_addr((const char *)pkt.payload.data() + 1, addr_len);

    uint8_t conn_id = alloc_conn_id();
    log_info("session %llx: MSG_CONNECT_REQ target='%s' allocated conn_id=%u",
             (unsigned long long)session_id_, target_addr.c_str(), conn_id);

    if (!setup_tunnel_target(target_addr, conn_id)) {
        Packet fail = Protocol::make_msg(MSG_CONNECT_FAIL, &conn_id, 1);
        send_control(fail);
        return;
    }

    // Register in chain_ref
    chain_ref_.in_fd[conn_id] = targets_[conn_id].fd;
    chain_ref_.in_writer[conn_id] = &targets_[conn_id].writer;
    chain_ref_.in_paused[conn_id] = false;

    // Send OK with conn_id
    Packet ok = Protocol::make_msg(MSG_CONNECT_OK, &conn_id, 1);
    send_control(ok);

    // Register target read handler
    int tfd = targets_[conn_id].fd;
    auto self = shared_from_this();
    kernel_->add_fd_handler(tfd, [this, self, conn_id](int fd, uint32_t events) {
        try {
            if (events & EPOLLIN) {
                {
                    uint8_t *rbuf = (uint8_t*)malloc(MAX_PACKET_SIZE);
                    if (!rbuf) return;
                    ssize_t n = read(fd, rbuf + 1, MAX_PACKET_SIZE - 1);
                    if (n > 0) {
                        if (chain_ && state_ == RUNNING) {
                             rbuf[0] = conn_id;
                             chain_->push_packet(rbuf, 1 + (size_t)n, 0, 0);
                         } else {
                             free(rbuf);
                         }
                     } else {
                         free(rbuf);
                         if (n == 0) {
                             handle_target_eof(conn_id);
                         } else {
                             if (errno != EAGAIN && errno != EWOULDBLOCK)
                                 handle_target_eof(conn_id);
                         }
                     }
                 }
             }
            if (events & (EPOLLERR | EPOLLHUP)) {
                // Drain remaining data then detect EOF
                while (true) {
                      uint8_t *tmp = (uint8_t*)malloc(MAX_PACKET_SIZE);
                      if (!tmp) return;
                      ssize_t n = read(fd, tmp + 1, MAX_PACKET_SIZE - 1);
                      if (n > 0) {
                          if (chain_ && state_ == RUNNING) {
                              tmp[0] = conn_id;
                              chain_->push_packet(tmp, 1 + (size_t)n, 0, 0);
                          } else {
                              free(tmp);
                          }
                     } else {
                          free(tmp);
                        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                            handle_target_eof(conn_id);
                        }
                        break;
                    }
                }
            }
        } catch (const std::exception &e) {
            log_error("session %llx: exception in target handler fd=%d: %s",
                      (unsigned long long)session_id_, fd, e.what());
        } catch (...) {
            log_error("session %llx: exception in target handler fd=%d (unknown)",
                      (unsigned long long)session_id_, fd);
        }
    });
}

void Session::handle_disconnect(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    log_debug("session %llx: handle_disconnect conn_id=%u",
              (unsigned long long)session_id_, conn_id);
    chain_ref_.in_fd.erase(conn_id);
    chain_ref_.in_writer.erase(conn_id);
    chain_ref_.in_paused.erase(conn_id);
    // Defer close — let chain workers finish writing first
    pending_disconnect_targets_.push_back(conn_id);
}

void Session::add_data_connection(uint8_t output_idx, int fd) {
    if (output_idx >= data_connections_.size()) {
        // Not resized yet — buffer for later processing
        pending_data_conns_.push_back({output_idx, fd});
        log_info("session %llx: data connection %u buffered (fd=%d, size=%zu)",
                 (unsigned long long)session_id_, output_idx, fd, data_connections_.size());
        return;
    }
    // Replace existing fd (handles reconnect)
    if (data_connections_[output_idx].fd >= 0) {
        kernel_->del_fd(data_connections_[output_idx].fd);
        close(data_connections_[output_idx].fd);
        data_connections_[output_idx] = DataConnection{};
    }
    data_connections_[output_idx].fd = fd;
    register_data_connection_reader(output_idx);
    log_info("session %llx: data connection %u added (fd=%d)",
             (unsigned long long)session_id_, output_idx, fd);

    // Check if all connections are ready
    bool all_ready = true;
    for (auto &dc : data_connections_) {
        if (dc.fd < 0) { all_ready = false; break; }
    }
    if (all_ready && state_ == RUNNING) {
        process_pending_reconnect_targets();
        Packet ready = Protocol::make_msg(MSG_TRANSMIT_READY);
        send_control(ready);
        log_info("session %llx: MSG_TRANSMIT_READY sent", (unsigned long long)session_id_);
    }
}

void Session::process_pending_data_conns() {
    for (auto &[output_idx, fd] : pending_data_conns_) {
        if (output_idx < data_connections_.size() && data_connections_[output_idx].fd < 0) {
            data_connections_[output_idx].fd = fd;
            register_data_connection_reader(output_idx);
            log_info("session %llx: pending data connection %u added (fd=%d)",
                     (unsigned long long)session_id_, output_idx, fd);
        } else {
            close(fd);
        }
    }
    pending_data_conns_.clear();

    // Check if all ready
    bool all_ready = true;
    for (auto &dc : data_connections_) {
        if (dc.fd < 0) { all_ready = false; break; }
    }
    if (all_ready && state_ == RUNNING) {
        process_pending_reconnect_targets();
        Packet ready = Protocol::make_msg(MSG_TRANSMIT_READY);
        send_control(ready);
        log_info("session %llx: MSG_TRANSMIT_READY sent", (unsigned long long)session_id_);
    }
}

void Session::send_control(const Packet &pkt) {
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
        // Write control message to regular writer buffer (not priority_buf)
        // to ensure ordering with data — control messages go after data on the wire
        dc.writer.write(dc.fd, framed.data(), framed.size());
        if (!dc.writer.registered)
            register_data_conn_epollout(idx, dc.fd);
        return;
    }
}

void Session::process_wire_buffer(const uint8_t *data, size_t len) {
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
        if (pos >= save + 10 || shift >= 56) {
            log_debug("session %llx: process_wire_buffer varint overflow at pos=%zu",
                      (unsigned long long)session_id_, save);
            break;
        }
        if (pos + val > len || val < 1) {
            log_debug("session %llx: process_wire_buffer val=%zu > len=%zu at pos=%zu",
                      (unsigned long long)session_id_, val, len, save);
            break;
        }
        uint8_t type = data[pos];
        log_debug("session %llx: process_wire_buffer type=%u val=%zu at pos=%zu",
                  (unsigned long long)session_id_, type, val, save);
        if (type == WIRE_CONTROL) {
            Packet pkt;
            size_t consumed = proto_.try_parse(data + pos + 1, val - 1, pkt);
            if (consumed > 0) {
                switch (pkt.type) {
                    case MSG_CONNECT_REQ:
                        handle_connect_req(pkt);
                        break;
                    case MSG_DISCONNECT:
                        handle_disconnect(pkt);
                        break;
                    case MSG_MODULE_LIST_REQ:
                        handle_module_list_req(pkt);
                        break;
                    case MSG_CHAIN_CREATE:
                        handle_chain_create(pkt);
                        break;
                    case MSG_CONNECT_PAUSE:
                    case MSG_CONNECT_RESUME: {
                        uint8_t cid = pkt.payload.empty() ? 0 : pkt.payload[0];
                        if (pkt.type == MSG_CONNECT_PAUSE) {
                            log_debug("session %llx: PAUSE conn_id=%u",
                                      (unsigned long long)session_id_, cid);
                            auto it = targets_.find(cid);
                            if (it != targets_.end()) {
                                it->second.paused_by_client = true;
                                kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
                            }
                        } else {
                            log_debug("session %llx: RESUME conn_id=%u",
                                      (unsigned long long)session_id_, cid);
                            auto it = targets_.find(cid);
                            if (it != targets_.end()) {
                                it->second.paused_by_client = false;
                                kernel_->mod_fd_events(it->second.fd, EPOLLIN, 0);
                            }
                        }
                        break;
                    }
                    default:
                        log_debug("session %llx: unexpected control msg %d",
                                  (unsigned long long)session_id_, (int)pkt.type);
                        break;
                }
            }
        } else if (type == WIRE_SHUTDOWN_WR) {
            if (val >= 2) {
                uint8_t cid = data[pos + 1];
                auto it = targets_.find(cid);
                if (it != targets_.end()) {
                    it->second.shutdown_wr = true;
                    if (it->second.writer.empty() ||
                        it->second.writer.flush(it->second.fd)) {
                        shutdown(it->second.fd, SHUT_WR);
                        it->second.shutdown_wr_sent = true;
                    }
                    if (!it->second.shutdown_wr_sent && !it->second.writer.registered)
                        register_target_epollout(cid, it->second.fd);
                }
            }
        } else if (type == 0) {
            if (val < 1) { pos += val; continue; }
            dispatch_data_conn_packet(data + pos + 1, val - 1, 1);
        }
        pos += val;
    }
}

void Session::dispatch_data_conn_packet(const uint8_t *payload, size_t len, int src_idx) {
    if (len < 1) return;
    if (chain_ && state_ == RUNNING) {
        uint8_t *blob = (uint8_t*)malloc(len);
        if (!blob) return;
        memcpy(blob, payload, len);
        chain_->push_packet(blob, len, src_idx, 1);
    }
}

void Session::register_data_connection_reader(size_t idx) {
    if (idx >= data_connections_.size()) return;
    int fd = data_connections_[idx].fd;
    if (fd < 0) return;
    auto self = shared_from_this();
    kernel_->add_fd_handler(fd, [this, self, idx](int ev_fd, uint32_t events) {
        (void)ev_fd;
        try {
        if (events & EPOLLIN) {
            auto &dc = data_connections_[idx];
            size_t old = dc.read_buf.size();
            dc.read_buf.resize(old + MAX_PACKET_SIZE);
            ssize_t n = read(dc.fd, dc.read_buf.data() + old, MAX_PACKET_SIZE);
            if (n == 0) {
                kernel_->del_fd(dc.fd);
                dc.read_buf.clear();
                dc.read_offset = 0;
                dc.fd = -1;
                on_disconnect();
                g_paused_sessions[session_id_] = self;
                return;
            }
            if (n < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    kernel_->del_fd(dc.fd);
                    dc.read_buf.clear();
                    dc.read_offset = 0;
                    dc.fd = -1;
                    on_disconnect();
                    g_paused_sessions[session_id_] = self;
                }
                dc.read_buf.resize(old);
                return;
            }
            if (n > 0) {
                last_wire_activity_ = std::chrono::steady_clock::now();
                heartbeating_ = false;
                dc.read_buf.resize(old + (size_t)n);
                while (true) {
                    auto &dc = data_connections_[idx];
                    size_t &off = dc.read_offset;
                    auto &buf = dc.read_buf;

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
                        off += pos + val;
                        if (type == WIRE_HEARTBEAT_PING) {
                            uint8_t pkt[2] = {1, WIRE_HEARTBEAT_PONG};
                            dc.writer.write(dc.fd, pkt, 2);
                            if (!dc.writer.registered && dc.writer.size() > 0)
                                register_data_conn_epollout(idx, dc.fd);
                        }
                        continue;
                    }
                    if (type == WIRE_SHUTDOWN_WR) {
                        if (val < 2) { buf.clear(); off = 0; break; }
                        uint8_t cid = ptr[pos + 1];
                        log_debug("session %llx: SHUTDOWN_WR conn_id=%u",
                                  (unsigned long long)session_id_, cid);
                        auto it = targets_.find(cid);
                        if (it != targets_.end()) {
                            it->second.shutdown_wr = true;
                            // Flush any buffered data to target before shutdown
                            if (it->second.writer.empty() ||
                                it->second.writer.flush(it->second.fd)) {
                                shutdown(it->second.fd, SHUT_WR);
                                it->second.shutdown_wr_sent = true;
                            }
                            if (!it->second.shutdown_wr_sent && !it->second.writer.registered)
                                register_target_epollout(cid, it->second.fd);
                        }
                        off += pos + val;
                        continue;
                    }
                    if (type == WIRE_SHUTDOWN_WR_ACK) {
                        // Unexpected from client — just skip
                        off += pos + val;
                        continue;
                    }
                    if (type == WIRE_CONTROL) {
                        // Control message — parse proto directly, bypass Chain
                        Packet pkt;
                        size_t consumed = proto_.try_parse(ptr + pos + 1, val - 1, pkt);
                        if (consumed > 0) {
                            switch (pkt.type) {
                                case MSG_CONNECT_REQ:
                                    handle_connect_req(pkt);
                                    break;
                                case MSG_DISCONNECT:
                                    handle_disconnect(pkt);
                                    break;
                                case MSG_MODULE_LIST_REQ:
                                    handle_module_list_req(pkt);
                                    break;
                                case MSG_CHAIN_CREATE:
                                    handle_chain_create(pkt);
                                    break;
                                case MSG_CONNECT_PAUSE:
                                case MSG_CONNECT_RESUME: {
                                    uint8_t cid = pkt.payload.empty() ? 0 : pkt.payload[0];
                                    if (pkt.type == MSG_CONNECT_PAUSE) {
                                        log_debug("session %llx: PAUSE conn_id=%u",
                                                  (unsigned long long)session_id_, cid);
                                        auto it = targets_.find(cid);
                                        if (it != targets_.end()) {
                                            it->second.paused_by_client = true;
                                            kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
                                        }
                                    } else {
                                        log_debug("session %llx: RESUME conn_id=%u",
                                                  (unsigned long long)session_id_, cid);
                                        auto it = targets_.find(cid);
                                        if (it != targets_.end()) {
                                            it->second.paused_by_client = false;
                                            kernel_->mod_fd_events(it->second.fd, EPOLLIN, 0);
                                        }
                                    }
                                    break;
                                }
                                default:
                                    log_debug("session %llx: unexpected control msg %d",
                                              (unsigned long long)session_id_, (int)pkt.type);
                                    break;
                            }
                        }
                        {
                            auto &dc = data_connections_[idx];
                            dc.read_offset += pos + val;
                        }
                        continue;
                    }
                    if (type > WIRE_CONTROL) {
                        char hexbuf[256] = {0};
                        {
                            auto &dc = data_connections_[idx];
                            size_t dump_sz = dc.read_buf.size() - dc.read_offset;
                            if (dump_sz > 64) dump_sz = 64;
                            for (size_t i = 0; i < dump_sz && i*3 < 255; i++)
                                snprintf(hexbuf + i*3, 4, "%02x ", (unsigned char)dc.read_buf.data()[dc.read_offset+i]);
                        }
                        log_error("session %llx: wire protocol violation type=%u off=%zu buf_sz=%zu avail=%zu val=%zu pos=%zu hex=%s",
                                  (unsigned long long)session_id_, type, dc.read_offset, dc.read_buf.size(), avail, val, pos, hexbuf);
                        dc.read_buf.clear(); dc.read_offset = 0;
                        break;
                    }

                    // type == 0: data — src_idx = idx+1 (1-based output port)
                    if (val < 1) { off += pos + val; continue; }
                    dispatch_data_conn_packet(ptr + pos + 1, val - 1, (int)(idx + 1));
                    off += pos + val;
                }
                {
                    auto &dc = data_connections_[idx];
                    if (dc.read_offset > MAX_PACKET_SIZE) {
                        dc.read_buf.erase(dc.read_buf.begin(), dc.read_buf.begin() + dc.read_offset);
                        dc.read_offset = 0;
                    }
                }
            }
        }
        } catch (const std::exception &e) {
            log_error("session %llx: exception in data connection reader: %s",
                      (unsigned long long)session_id_, e.what());
        } catch (...) {
            log_error("session %llx: unknown exception in data connection reader",
                      (unsigned long long)session_id_);
        }
        if (events & (EPOLLERR | EPOLLHUP))
            log_debug("session %llx: data connection %zu closed",
                      (unsigned long long)session_id_, idx);
    }, EPOLLIN);
}

void Session::register_data_conn_epollout(size_t idx, int fd) {
    if (idx >= data_connections_.size()) return;
    if (data_connections_[idx].writer.registered) return;
    data_connections_[idx].writer.registered = true;
    auto self = shared_from_this();
    kernel_->add_fd_handler(fd, [this, self, idx](int ev_fd, uint32_t events) {
        (void)ev_fd;
            if (events & EPOLLOUT) {
                if (idx >= data_connections_.size()) return;
                auto &dc = data_connections_[idx];

                // Step 1: loop-flush writer (tail + pending frames) until drained or EAGAIN
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

                // Step 3: one-shot flush writer (data that might follow priority_buf)
                if (dc.priority_buf.empty())
                    dc.writer.flush(dc.fd);

                // Step 4: resume paused targets if ALL dc buffers drained below low_water
                if (dc.writer.size() <= dc.writer.low_water) {
                    bool all_below = true;
                    for (auto &check_dc : data_connections_) {
                        if (check_dc.fd >= 0 && check_dc.writer.size() > check_dc.writer.low_water) {
                            all_below = false;
                            break;
                        }
                    }
                    if (all_below) {
                        for (auto &[cid, tgt] : targets_) {
                            if (tgt.paused_by_backpressure) {
                                tgt.paused_by_backpressure = false;
                                kernel_->mod_fd_events(tgt.fd, EPOLLIN, 0);
                                log_debug("session %llx: BW resume target conn_id=%u (flush)",
                                          (unsigned long long)session_id_, cid);
                            }
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

bool Session::setup_tunnel_target(const std::string &target_addr, uint8_t conn_id) {
    size_t colon = target_addr.find(':');
    if (colon == std::string::npos) {
        log_error("session %llx: invalid target address '%s' (need host:port)",
                  (unsigned long long)session_id_, target_addr.c_str());
        return false;
    }

    std::string host = target_addr.substr(0, colon);
    std::string port = target_addr.substr(colon + 1);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (err != 0) {
        log_error("session %llx: getaddrinfo '%s:%s' failed: %s",
                  (unsigned long long)session_id_, host.c_str(), port.c_str(),
                  gai_strerror(err));
        return false;
    }

    int fd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        log_error("session %llx: connect to %s:%s failed",
                  (unsigned long long)session_id_, host.c_str(), port.c_str());
        return false;
    }

    int bufsz = 1048576;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    targets_[conn_id] = {fd, target_addr};
    log_info("session %llx: connected to target %s:%s (fd=%d, conn_id=%u)",
             (unsigned long long)session_id_, host.c_str(), port.c_str(), fd, conn_id);
    return true;
}

void Session::send_disconnect_now(uint8_t conn_id) {
    auto it = targets_.find(conn_id);
    if (it == targets_.end()) return;
    // Flush response data to wire before sending disconnect
    if (!data_connections_.empty() && data_connections_[0].fd >= 0)
        data_connections_[0].writer.flush(data_connections_[0].fd);
    if (it->second.shutdown_wr_sent) {
        if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
            uint8_t ack[3] = {2, WIRE_SHUTDOWN_WR_ACK, conn_id};
            data_connections_[0].writer.write(data_connections_[0].fd, ack, 3);
            if (data_connections_[0].writer.size() > 0 && !data_connections_[0].writer.registered)
                register_data_conn_epollout(0, data_connections_[0].fd);
        }
        close_target(conn_id);
    } else {
        close_target(conn_id);
        if (chain_) {
            // Send disconnect as in-band chain control frame
            // guaranteeing ordering with data via seqnum in split/merge
            uint8_t *ctrl = (uint8_t*)malloc(3);
            ctrl[0] = 255;
            ctrl[1] = CHAIN_CTRL_DISCONNECT;
            ctrl[2] = conn_id;
            chain_->push_packet(ctrl, 3, 0, 0);
        } else {
            std::vector<uint8_t> p = {conn_id};
            Packet d = Protocol::make_msg(MSG_DISCONNECT, p);
            send_control(d);
        }
    }
}

void Session::send_pending_disconnects() {
    if (disconnect_ids_.empty()) return;
    for (uint8_t cid : disconnect_ids_)
        send_disconnect_now(cid);
    disconnect_ids_.clear();
    disconnect_pending_ = false;
}

void Session::handle_target_eof(uint8_t conn_id) {
    auto it = targets_.find(conn_id);
    if (it == targets_.end()) return;
    if (chain_ && !chain_->is_drained()) {
        disconnect_pending_ = true;
        disconnect_ids_.push_back(conn_id);
        return;
    }
    send_disconnect_now(conn_id);
}

void Session::close_target(uint8_t conn_id) {
    auto it = targets_.find(conn_id);
    if (it == targets_.end()) return;
    kernel_->del_fd(it->second.fd);
    close(it->second.fd);
    targets_.erase(it);
    log_debug("session %llx: target conn_id=%u disconnected",
              (unsigned long long)session_id_, conn_id);
}

void Session::close_all_targets() {
    while (!targets_.empty())
        close_target(targets_.begin()->first);
}

void Session::on_disconnect() {
    if (paused_.exchange(true)) return;
    if (state_ != RUNNING) {
        paused_ = false;
        return;
    }
    log_info("session %llx: client disconnected", (unsigned long long)session_id_);

    saved_targets_.clear();
    for (auto &kv : targets_)
        saved_targets_.emplace_back(kv.first, kv.second.addr);

    close_all_targets();

    for (size_t i = 0; i < data_connections_.size(); i++) {
        if (data_connections_[i].fd >= 0) {
            kernel_->del_fd(data_connections_[i].fd);
            if ((int)i != 0)
                close(data_connections_[i].fd);
            data_connections_[i].fd = -1;
            data_connections_[i].writer.clear();
            data_connections_[i].read_buf.clear();
        }
    }

    paused_ = true;
    log_debug("session %llx: paused, waiting for reconnect",
              (unsigned long long)session_id_);
}

bool Session::reconnect(int new_client_fd) {
    if (!paused_) {
        log_error("session %llx: reconnect failed — not paused",
                  (unsigned long long)session_id_);
        return false;
    }

    log_info("session %llx: client reconnected", (unsigned long long)session_id_);

    if (client_fd_ >= 0 && client_fd_ != new_client_fd) {
        kernel_->del_fd(client_fd_);
        close(client_fd_);
    }
    client_fd_ = new_client_fd;

    auto self = shared_from_this();
    g_paused_sessions.erase(session_id_);

    data_connections_[0].writer.clear();
    data_connections_[0].read_buf.clear();
    data_connections_[0].read_offset = 0;
    data_connections_[0].fd = client_fd_;
    chain_ref_.out_fds = {client_fd_};
    chain_ref_.out_writer = &data_connections_[0].writer;
    register_data_connection_reader(0);

    // Defer target reconnect until all data connections are ready
    // (secondary connections must be re-established first)
    pending_reconnect_targets_ = std::move(saved_targets_);
    process_pending_reconnect_targets();
    paused_ = false;

    log_info("session %llx: resumed after reconnect", (unsigned long long)session_id_);
    return true;
}

void Session::process_pending_reconnect_targets() {
    if (pending_reconnect_targets_.empty()) return;
    log_info("session %llx: reconnecting %zu pending target(s)",
             (unsigned long long)session_id_, pending_reconnect_targets_.size());
    auto targets = std::move(pending_reconnect_targets_);
    auto self = shared_from_this();
    for (auto &saved : targets) {
        uint8_t conn_id = saved.first;
        std::string addr = saved.second;
        if (targets_.count(conn_id)) {
            log_debug("session %llx: target conn_id=%u already exists, skipping",
                      (unsigned long long)session_id_, conn_id);
            continue;
        }
        if (!setup_tunnel_target(addr, conn_id)) {
            log_error("session %llx: reconnect: target %s conn_id=%u failed",
                      (unsigned long long)session_id_, addr.c_str(), conn_id);
            continue;
        }
        chain_ref_.in_fd[conn_id] = targets_[conn_id].fd;
        chain_ref_.in_writer[conn_id] = &targets_[conn_id].writer;
        int tfd = targets_[conn_id].fd;
        kernel_->add_fd_handler(tfd, [this, self, conn_id](int fd, uint32_t events) {
            if (events & EPOLLIN) {
                {
                    uint8_t *rbuf = (uint8_t*)malloc(MAX_PACKET_SIZE);
                    if (!rbuf) return;
                    ssize_t n = read(fd, rbuf + 1, MAX_PACKET_SIZE - 1);
                    if (n > 0) {
                        if (chain_ && state_ == RUNNING) {
                             rbuf[0] = conn_id;
                             chain_->push_packet(rbuf, 1 + (size_t)n, 0, 0);
                         } else {
                             free(rbuf);
                         }
                     } else {
                         free(rbuf);
                         if (n == 0) {
                             handle_target_eof(conn_id);
                         } else {
                             if (errno != EAGAIN && errno != EWOULDBLOCK)
                                 handle_target_eof(conn_id);
                         }
                     }
                 }
             }
            if (events & (EPOLLERR | EPOLLHUP)) {
                while (true) {
                    uint8_t *tmp = (uint8_t*)malloc(MAX_PACKET_SIZE);
                    if (!tmp) return;
                    ssize_t n = read(fd, tmp + 1, MAX_PACKET_SIZE - 1);
                    if (n > 0) {
                        if (chain_ && state_ == RUNNING) {
                            tmp[0] = conn_id;
                            chain_->push_packet(tmp, 1 + (size_t)n, 0, 0);
                        } else {
                            free(tmp);
                        }
                   } else {
                        free(tmp);
                        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                            handle_target_eof(conn_id);
                        }
                        break;
                   }
                }
            }
        });
    }
}

void Session::register_target_epollout(uint8_t conn_id, int tfd) {
    auto it = targets_.find(conn_id);
    if (it == targets_.end()) return;
    if (it->second.writer.registered) return;
    it->second.writer.registered = true;
    auto self = shared_from_this();
    kernel_->add_fd_handler(tfd, [this, self, conn_id](int fd, uint32_t events) {
        if (events & EPOLLOUT) {
            auto it2 = targets_.find(conn_id);
            if (it2 == targets_.end()) return;
            bool drained = it2->second.writer.flush(fd);
            if (drained) {
                it2->second.writer.registered = false;
                kernel_->mod_fd_events(fd, 0, EPOLLOUT);
                if (it2->second.shutdown_wr && !it2->second.shutdown_wr_sent) {
                    shutdown(fd, SHUT_WR);
                    it2->second.shutdown_wr_sent = true;
                }
                if (it2->second.pause_sent) {
                    it2->second.pause_sent = false;
                    this->chain_ref_.in_paused[conn_id] = false;
                    send_resume(conn_id);
                }
            }
        }
        if (events & (EPOLLERR | EPOLLHUP))
            targets_.erase(conn_id);
    }, EPOLLOUT);
}

void Session::send_pause(uint8_t conn_id) {
    Packet pkt = Protocol::make_msg(MSG_CONNECT_PAUSE, &conn_id, 1);
    send_control(pkt);
}

void Session::send_resume(uint8_t conn_id) {
    Packet pkt = Protocol::make_msg(MSG_CONNECT_RESUME, &conn_id, 1);
    send_control(pkt);
}

void Session::process_pending_io() {
    std::vector<std::function<void()>> batch;
    {
        std::lock_guard<std::mutex> lock(data_mtx_);
        batch.swap(pending_io_);
    }
    for (auto &fn : batch)
        fn();
    if (disconnect_pending_) {
        if (!chain_ || chain_->is_drained()) {
            send_pending_disconnects();
        }
    }
    // Handle client-initiated disconnects (just close target, no msg back)
    if (!pending_disconnect_targets_.empty()) {
        if (!chain_ || chain_->is_drained()) {
            for (uint8_t cid : pending_disconnect_targets_)
                close_target(cid);
            pending_disconnect_targets_.clear();
        }
    }
}

void Session::check_heartbeat() {
    if (state_ != RUNNING) return;
    auto now = std::chrono::steady_clock::now();
    auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_wire_activity_).count();

    if (idle_ms > heartbeat_interval_ms_ * 2) {
        log_error("session %llx: heartbeat timeout", (unsigned long long)session_id_);
        state_ = DISCONNECTED;
        return;
    }

    if (idle_ms > heartbeat_interval_ms_ && !heartbeating_) {
        heartbeating_ = true;
        uint8_t hb[2] = {1, WIRE_HEARTBEAT_PING};
        for (size_t i = 0; i < data_connections_.size(); i++) {
            if (data_connections_[i].fd < 0) continue;
            data_connections_[i].writer.write(data_connections_[i].fd, hb, 2);
            if (!data_connections_[i].writer.registered && data_connections_[i].writer.size() > 0)
                register_data_conn_epollout(i, data_connections_[i].fd);
        }
    }

    if (chain_) chain_->check_module_heartbeats(heartbeat_interval_ms_);
}
