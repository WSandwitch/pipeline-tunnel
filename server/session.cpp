#include "session.h"
#include "common/logger.h"
#include "common/utils.h"
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

// Session registry (declared in server/main.cpp)
extern std::unordered_map<uint64_t, std::weak_ptr<Session>> g_session_registry;
extern std::unordered_map<uint64_t, std::shared_ptr<Session>> g_paused_sessions;

static uint64_t generate_id() {
    static uint64_t counter = 0;
    return ++counter + ((uint64_t)time(nullptr) << 32);
}

Session::Session(int client_fd, const std::string &password,
                 std::shared_ptr<Kernel> kernel)
    : client_fd_(client_fd), password_(password),
      kernel_(std::move(kernel)), session_id_(generate_id()) {}

Session::~Session() {
    g_session_registry.erase(session_id_);
    g_paused_sessions.erase(session_id_);
    close_all_targets();
    if (chain_) {
        for (int fd : chain_->output_fds())
            kernel_->del_fd(fd);
    }
    if (chain_)
        kernel_->remove_chain(session_id_);
    // Close all data connections (data_connections_[0] is client_fd_, closed below)
    for (size_t i = 1; i < data_connections_.size(); i++) {
        if (data_connections_[i].fd >= 0) {
            kernel_->del_fd(data_connections_[i].fd);
            close(data_connections_[i].fd);
        }
    }
    if (client_fd_ >= 0) {
        kernel_->del_fd(client_fd_);
        close(client_fd_);
    }
}

void Session::send_packet(const Packet &pkt) {
    // Auth/setup packets are small; direct write is safe and avoids
    // EPOLLOUT handler churn on client_fd_ before transitioning to data_connection_reader.
    auto wire = proto_.serialize(pkt);
    ssize_t n = write(client_fd_, wire.data(), wire.size());
    if (n < 0 && errno != EAGAIN) {
        log_error("session %llx: send_packet write error: %s",
                  (unsigned long long)session_id_, strerror(errno));
    }
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
    if (state_ == AWAIT_CONNECT_REQ) {
        recv_buf_.insert(recv_buf_.end(), data, data + len);
        Packet pkt;
        size_t consumed = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), pkt);
        if (consumed > 0 && pkt.type == MSG_CONNECT_REQ) {
            recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + consumed);
            handle_connect_req(pkt);
            // Process remaining data (may be in same TCP segment)
            while (true) {
                Packet p;
                size_t c = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), p);
                if (c == 0) break;
                recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + c);
                switch (p.type) {
                    case MSG_DISCONNECT: handle_disconnect(p); break;
                    case MSG_CONNECT_REQ: handle_connect_req(p); break;
                    case MSG_CONNECT_PAUSE:
                        if (p.payload.size() >= 1) {
                            auto it = targets_.find(p.payload[0]);
                            if (it != targets_.end()) {
                                it->second.paused_by_client = true;
                                kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
                            }
                        }
                        break;
                    case MSG_CONNECT_RESUME:
                        if (p.payload.size() >= 1) {
                            auto it = targets_.find(p.payload[0]);
                            if (it != targets_.end()) {
                                it->second.paused_by_client = false;
                                kernel_->mod_fd_events(it->second.fd, EPOLLIN, 0);
                            }
                        }
                        break;
                    default: break;
                }
            }
            return;
        }
        return;
    }

    // If client_fd was transferred to another session (reconnect), ignore
    if (client_fd_ < 0)
        return;

    // Auth / setup phase: parse protocol messages
    recv_buf_.insert(recv_buf_.end(), data, data + len);

    while (true) {
        Packet pkt;
        size_t consumed = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), pkt);
        if (consumed == 0) break;

        recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + consumed);

        switch (pkt.type) {
            case MSG_AUTH_RESPONSE:
                if (state_ == AWAIT_AUTH1_CHALLENGE_RESP) {
                    handle_auth_challenge_response(pkt);
                } else if (state_ == AWAIT_AUTH2_RESPONSE) {
                    handle_auth2_response(pkt);
                }
                break;
            case MSG_AUTH_OK:
                if (state_ == AWAIT_AUTH2_RESPONSE) {
                    handle_auth2_response(pkt);
                }
                break;
            case MSG_AUTH_CHALLENGE:
                if (state_ == AWAIT_AUTH1_OK)
                    handle_auth2_challenge(pkt);
                break;
            case MSG_RECONNECT:
                if (state_ == AWAIT_MODULE_LIST_REQ)
                    handle_reconnect(pkt);
                break;
            case MSG_MODULE_LIST_REQ:
                if (state_ == AWAIT_MODULE_LIST_REQ)
                    handle_module_list_req(pkt);
                break;
            case MSG_CHAIN_CREATE:
                if (state_ == AWAIT_CHAIN_CREATE)
                    handle_chain_create(pkt);
                break;
            case MSG_CONNECT_REQ:
                if (state_ == AWAIT_CHAIN_CREATE || state_ == AWAIT_CONNECT_REQ)
                    handle_connect_req(pkt);
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
    Packet ok = Protocol::make_msg(MSG_AUTH_OK, "\x01", 1);
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
        state_ = AWAIT_MODULE_LIST_REQ;
    } else {
        log_error("session %llx: auth2 failed", (unsigned long long)session_id_);
        state_ = DISCONNECTED;
    }
}

void Session::handle_module_list_req(const Packet &pkt) {
    (void)pkt;
    extern std::unordered_map<std::string, std::string> g_module_registry;

    std::vector<uint8_t> res;
    // Count
    if (g_module_registry.size() > 255) {
        log_error("session %llx: too many modules", (unsigned long long)session_id_);
        Packet reply = Protocol::make_msg(MSG_MODULE_LIST_RES, "\x00", 1);
        send_packet(reply);
        state_ = AWAIT_CHAIN_CREATE;
        return;
    }
    res.push_back((uint8_t)g_module_registry.size());

    // Module names
    for (auto &entry : g_module_registry) {
        const std::string &name = entry.first;
        if (name.size() > 255) continue;
        res.push_back((uint8_t)name.size());
        res.insert(res.end(), name.begin(), name.end());
    }

    loaded_modules_.clear();
    size_t idx = 0;
    for (auto &entry : g_module_registry) {
        ModuleInfo mi;
        mi.id = (uint8_t)idx++;
        mi.name = entry.first;
        loaded_modules_.push_back(mi);
    }

    Packet reply = Protocol::make_msg(MSG_MODULE_LIST_RES, res);
    send_packet(reply);
    state_ = AWAIT_CHAIN_CREATE;
    log_debug("session %llx: module list (%zu modules)",
              (unsigned long long)session_id_, loaded_modules_.size());
}

void Session::handle_reconnect(const Packet &pkt) {
    if (pkt.payload.size() != 8) {
        log_debug("session %llx: reconnect: bad payload size %zu",
                  (unsigned long long)session_id_, pkt.payload.size());
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }

    uint64_t sid;
    memcpy(&sid, pkt.payload.data(), 8);

    auto it = g_session_registry.find(sid);
    if (it == g_session_registry.end() || it->second.expired()) {
        log_debug("session %llx: reconnect: session %llx not found",
                  (unsigned long long)session_id_, (unsigned long long)sid);
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }

    auto old_session = it->second.lock();
    if (!old_session->reconnect(client_fd_)) {
        log_error("session %llx: reconnect to %llx failed",
                  (unsigned long long)session_id_, (unsigned long long)sid);
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }

    log_info("session %llx: reconnected to session %llx",
             (unsigned long long)session_id_, (unsigned long long)sid);
    Packet ok = Protocol::make_msg(MSG_AUTH_OK, "\x01", 1);
    send_packet(ok);

    // Transfer succeeded — release our client fd (old session owns it now)
    client_fd_ = -1;
    state_ = DISCONNECTED;
}

void Session::handle_connect_req(const Packet &pkt) {
    // Payload: {connection_id[1], addr_len[1], addr[addr_len]}
    if (pkt.payload.size() < 2) {
        log_error("session %llx: MSG_CONNECT_REQ too short",
                  (unsigned long long)session_id_);
        return;
    }
    uint8_t conn_id = pkt.payload[0];
    uint8_t addr_len = pkt.payload[1];
    if (2 + addr_len > pkt.payload.size()) {
        log_error("session %llx: MSG_CONNECT_REQ addr length mismatch",
                  (unsigned long long)session_id_);
        return;
    }
    std::string target_addr((const char *)pkt.payload.data() + 2, addr_len);
    log_info("session %llx: MSG_CONNECT_REQ conn_id=%u target='%s'",
             (unsigned long long)session_id_, conn_id, target_addr.c_str());

    if (targets_.count(conn_id)) {
        log_error("session %llx: duplicate conn_id %u",
                  (unsigned long long)session_id_, conn_id);
        return;
    }

    if (!setup_tunnel_target(target_addr, conn_id)) {
        std::vector<uint8_t> fail_payload = {conn_id, 0x00};
        Packet fail = Protocol::make_msg(MSG_CONNECT_FAIL, fail_payload);
        send_control(fail);
        return;
    }

    // Register target fd handler — reads target data, routes through chain
    int tfd = targets_[conn_id].fd;
        kernel_->add_fd_handler(tfd, [this, conn_id](int fd, uint32_t events) {
        try {
            if (events & EPOLLIN) {
            int in_fd = chain_ ? chain_->input_fd() : -1;
            uint8_t rbuf[65536];
            ssize_t n = read(fd, rbuf, sizeof(rbuf));
            if (n > 0) {
                std::vector<uint8_t> pkt;
                pkt.push_back(0);  // TYPE_DATA
                pkt.push_back(conn_id);
                pkt.insert(pkt.end(), rbuf, rbuf + n);
                if (chain_ && chain_->valid() && in_fd >= 0) {
                    auto framed = make_varint_packet(pkt.data(), pkt.size());
                    size_t frame_sz = framed.size();
                    int ret = chain_in_writer_.write(in_fd, framed.data(), frame_sz);
                    if (ret > 0 && !chain_in_writer_.registered) {
                        register_chain_input_out();
                    }
                    if (chain_in_writer_.size() > 0) {
                        auto tit = targets_.find(conn_id);
                        if (tit != targets_.end() && !tit->second.paused_by_backpressure) {
                            tit->second.paused_by_backpressure = true;
                            kernel_->mod_fd_events(tit->second.fd, 0, EPOLLIN);
                        }
                    }
                } else {
                    // No chain: send raw varint over data connection 0
                    auto framed = make_varint_packet_with_conn_id(conn_id, rbuf, (size_t)n);
                    if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
                        int dc_fd = data_connections_[0].fd;
                        int ret = data_connections_[0].writer.write(dc_fd, framed.data(), framed.size());
                        if (ret > 0 && !data_connections_[0].writer.registered)
                            register_data_conn_epollout(0, dc_fd);
                    }
                }
            } else if (n == 0) {
                if (chain_ && chain_->valid()) {
                    std::vector<uint8_t> marker = {1, conn_id};  // TYPE_DISCONNECT + conn_id
                    auto framed = make_varint_packet(marker.data(), marker.size());
                    chain_in_writer_.write(chain_->input_fd(), framed.data(), framed.size());
                    if (chain_in_writer_.size() > 0 && !chain_in_writer_.registered)
                        register_chain_input_out();
                    close_target(conn_id);
                } else {
                    close_target(conn_id);
                    std::vector<uint8_t> disconnect_payload = {conn_id};
                    Packet d = Protocol::make_msg(MSG_DISCONNECT, disconnect_payload);
                    send_control(d);
                }
            }
        }
        } catch (const std::exception &e) {
            log_error("session %llx: exception in target handler fd=%d: %s", (unsigned long long)session_id_, fd, e.what());
        } catch (...) {
            log_error("session %llx: exception in target handler fd=%d (unknown)", (unsigned long long)session_id_, fd);
        }
    });

    std::vector<uint8_t> ok_payload = {conn_id, 0x01};
    Packet ok = Protocol::make_msg(MSG_CONNECT_OK, ok_payload);
    send_control(ok);

    state_ = RUNNING;
    log_info("session %llx: tunnel connected conn_id=%u -> %s",
             (unsigned long long)session_id_, conn_id, target_addr.c_str());
}

void Session::handle_disconnect(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    close_target(conn_id);
}

void Session::handle_chain_create(const Packet &pkt) {
    extern std::unordered_map<std::string, std::string> g_module_registry;

    auto resolver = [](const std::string &name) -> std::string {
        auto it = g_module_registry.find(name);
        if (it != g_module_registry.end())
            return it->second;
        return "";
    };

    // Parse module specs from packet
    size_t offset = 0;
    ChainConfig cfg;
    cfg.valid = true;

    while (offset < pkt.payload.size()) {
        if (offset + 2 > pkt.payload.size()) break;
        uint8_t mod_id = pkt.payload[offset];
        uint8_t config_len = pkt.payload[offset + 1];
        offset += 2;
        if (offset + config_len > pkt.payload.size()) break;
        std::string config_str((const char *)pkt.payload.data() + offset, config_len);
        offset += config_len;

        ModuleSpec ms;
        ms.name = "mod_" + std::to_string(mod_id);
        ms.params = config_str;
        cfg.modules.push_back(std::move(ms));
    }

    // Resolve module names from loaded_modules_
    for (auto &ms : cfg.modules) {
        // ms.name is "mod_N" format from the parser; look up by index
        // Actually, the packet sends module_id (index into loaded_modules_)
        // and we set ms.name = "mod_N" as a placeholder.
        // We need to replace with actual name from loaded_modules_
        if (ms.name.size() > 4 && ms.name.substr(0, 4) == "mod_") {
            int idx = atoi(ms.name.c_str() + 4);
            if (idx >= 0 && idx < (int)loaded_modules_.size()) {
                ms.name = loaded_modules_[idx].name;
            }
        }
    }

    chain_ = std::make_shared<Chain>(session_id_, cfg, resolver);
    if (!chain_->build()) {
        log_error("session %llx: chain build failed", (unsigned long long)session_id_);
        Packet fail = Protocol::make_msg(MSG_CHAIN_READY, "\x00", 1);
        send_packet(fail);
        return;
    }
    chain_->set_kernel(kernel_.get());

    // Make chain fds non-blocking for epoll safety
    for (int out_fd : chain_->output_fds()) set_nonblock(out_fd);
    set_nonblock(chain_->input_fd());
    // Increase pipe buffer to 1MB for large data bursts
    fcntl(chain_->input_fd(), F_SETPIPE_SZ, 1048576);
    log_debug("session %llx: chain fds: input_fd=%d nout=%zu",
              (unsigned long long)session_id_, chain_->input_fd(), chain_->output_fds().size());

    // Set up data connections — one per chain output
    num_outputs_ = (uint8_t)chain_->output_fds().size();
    data_connections_.resize(num_outputs_);
    data_connections_[0].fd = client_fd_;
    chain_out_writers_.resize(num_outputs_);
    log_debug("session %llx: chain_out_writers_ size=%zu, num_outputs=%u",
              (unsigned long long)session_id_, chain_out_writers_.size(), num_outputs_);

    // Register chain output handler — RAW PIPE: reads bytes from chain
    // (already varint-framed with TYPE byte) and writes directly to data connection wire.
    auto chain_out_fds = chain_->output_fds();
    for (size_t i = 0; i < chain_out_fds.size(); i++) {
        int out_fd = chain_out_fds[i];
        kernel_->add_fd_handler(out_fd, [this, i](int fd, uint32_t events) {
            try {
            if (events & EPOLLIN) {
                uint8_t tmp[65536];
                ssize_t n = read(fd, tmp, sizeof(tmp));
                if (n > 0) {
                    if (i < data_connections_.size() && data_connections_[i].fd >= 0) {
                        int dc_fd = data_connections_[i].fd;
                        int ret = data_connections_[i].writer.write(dc_fd, tmp, n);
                        if (ret > 0 && !data_connections_[i].writer.registered)
                            register_data_conn_epollout(i, dc_fd);
                    }
                }
            }
            } catch (const std::exception &e) {
                log_error("session %llx: exception in chain_out handler fd=%d: %s", (unsigned long long)session_id_, fd, e.what());
            } catch (...) {
                log_error("session %llx: exception in chain_out handler fd=%d (unknown)", (unsigned long long)session_id_, fd);
            }
        });
        log_debug("session %llx: chain_OUT registered for out_fd=%d",
                  (unsigned long long)session_id_, out_fd);
    }

    // Register chain input read handler — reads varint-framed {conn_id, data} from
    // the reverse direction (target → chain → client). Data arrives on chain_in_fd
    // after modules process in reverse.
    if (chain_->input_fd() >= 0) {
        int cfd = chain_->input_fd();
        log_debug("session %llx: register chain_in_fd handler: chain_in_fd=%d",
                  (unsigned long long)session_id_, cfd);
        kernel_->add_fd_handler(cfd, [this](int fd, uint32_t events) {
            try {
            if (events & EPOLLIN) {
                uint8_t tmp[65536];
                ssize_t n = read(fd, tmp, sizeof(tmp));
                if (n > 0)
                    chain_in_read_buf_.insert(chain_in_read_buf_.end(), tmp, tmp + n);

                while (true) {
                    if (chain_in_read_buf_.size() < 1) break;
                    size_t pos = 0;
                    size_t val = 0;
                    int shift = 0;
                    while (pos < chain_in_read_buf_.size() && shift < 56) {
                        uint8_t byte = chain_in_read_buf_[pos++];
                        val |= (size_t)(byte & 0x7F) << shift;
                        if (!(byte & 0x80)) break;
                        shift += 7;
                    }
                    if (pos >= 10 || shift >= 56) { chain_in_read_buf_.clear(); break; }
                    if (pos > chain_in_read_buf_.size() || pos + val > chain_in_read_buf_.size()) break;

                    if (val < 2) { chain_in_read_buf_.clear(); break; }
                    uint8_t type = chain_in_read_buf_[pos];
                    uint8_t conn_id = chain_in_read_buf_[pos + 1];
                    if (type == TYPE_DATA) {
                        auto it = targets_.find(conn_id);
                        if (it != targets_.end()) {
                            WriteBuffer &w = it->second.writer;
                            int tfd = it->second.fd;
                            int ret = w.write(tfd, chain_in_read_buf_.data() + pos + 2, val - 2);
                            if (ret > 0 && !w.registered)
                                register_target_epollout(conn_id, tfd);
                            if (w.size() >= w.high_water && !it->second.pause_sent) {
                                it->second.pause_sent = true;
                                send_pause(conn_id);
                            }
                        } else {
                            log_debug("session %llx: chain input TYPE_DATA for unknown conn_id %u",
                                      (unsigned long long)session_id_, conn_id);
                        }
                    } else if (type == TYPE_DISCONNECT) {
                        close_target(conn_id);
                    } else if (type == TYPE_PAUSE) {
                        send_pause(conn_id);
                    } else if (type == TYPE_RESUME) {
                        send_resume(conn_id);
                    }
                    chain_in_read_buf_.erase(chain_in_read_buf_.begin(),
                                             chain_in_read_buf_.begin() + pos + val);
                }
                if (chain_) chain_->retry_buffered();
            }
            } catch (const std::exception &e) {
                log_error("session %llx: exception in chain_in handler fd=%d: %s",
                          (unsigned long long)session_id_, fd, e.what());
            } catch (...) {
                log_error("session %llx: exception in chain_in handler fd=%d (unknown)",
                          (unsigned long long)session_id_, fd);
            }
        });
    }

    // Register all module input fds with kernel
    for (auto &mf : chain_->module_fds()) {
        int in_fd = mf.first;
        int mod_idx = mf.second;
        kernel_->add_fd(in_fd, chain_, mod_idx);
    }

    // Send session_id + num_outputs in CHAIN_READY
    std::vector<uint8_t> ready;
    ready.push_back(0x01);
    ready.resize(9);
    memcpy(ready.data() + 1, &session_id_, 8);
    ready.push_back(num_outputs_);
    Packet pkt_ready = Protocol::make_msg(MSG_CHAIN_READY, ready);
    send_packet(pkt_ready);

    // Transition the original TCP connection to data connection reader mode
    if (client_fd_ >= 0) {
        kernel_->del_fd(client_fd_);
        register_data_connection_reader(0);
    }

    state_ = AWAIT_CONNECT_REQ;
    log_info("session %llx: chain ready, awaiting MSG_CONNECT_REQ, %zu modules, %u outputs",
             (unsigned long long)session_id_, cfg.modules.size(), num_outputs_);
}

void Session::add_data_connection(uint8_t output_idx, int fd) {
    if (output_idx >= data_connections_.size()) {
        log_error("session %llx: add_data_connection idx=%u >= size=%zu",
                  (unsigned long long)session_id_, output_idx, data_connections_.size());
        close(fd);
        return;
    }
    if (data_connections_[output_idx].fd >= 0) {
        log_error("session %llx: add_data_connection idx=%u already has fd %d",
                  (unsigned long long)session_id_, output_idx, data_connections_[output_idx].fd);
        close(fd);
        return;
    }
    data_connections_[output_idx].fd = fd;
    register_data_connection_reader(output_idx);
    log_info("session %llx: data connection %u added (fd=%d)",
             (unsigned long long)session_id_, output_idx, fd);
}

void Session::send_control(const Packet &pkt) {
    auto serialized = proto_.serialize(pkt);
    auto framed = make_varint_packet_with_conn_id(255, serialized.data(), serialized.size());
    if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
        int fd = data_connections_[0].fd;
        int ret = data_connections_[0].writer.write(fd, framed.data(), framed.size());
        if (ret > 0 && !data_connections_[0].writer.registered)
            register_data_conn_epollout(0, fd);
    }
}

void Session::dispatch_data_conn_packet(uint8_t conn_id, const uint8_t *payload, size_t len) {
    if (conn_id == 255) {
        // Control message — parse as protocol packet and dispatch
        Packet pkt;
        size_t consumed = proto_.try_parse(payload, len, pkt);
        if (consumed == 0) return;
        switch (pkt.type) {
            case MSG_CONNECT_REQ:
                handle_connect_req(pkt);
                break;
            case MSG_DISCONNECT:
                handle_disconnect(pkt);
                break;
            case MSG_CONNECT_PAUSE:
                if (pkt.payload.size() >= 1) {
                    uint8_t cid = pkt.payload[0];
                    auto it = targets_.find(cid);
                    if (it != targets_.end()) {
                        it->second.paused_by_client = true;
                        kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
                    }
                }
                break;
            case MSG_CONNECT_RESUME:
                if (pkt.payload.size() >= 1) {
                    uint8_t cid = pkt.payload[0];
                    auto it = targets_.find(cid);
                    if (it != targets_.end()) {
                        it->second.paused_by_client = false;
                        kernel_->mod_fd_events(it->second.fd, EPOLLIN, 0);
                    }
                }
                break;
            default:
                log_debug("session %llx: unexpected control msg %d via data conn",
                          (unsigned long long)session_id_, (int)pkt.type);
                break;
        }
        return;
    }

    // No-chain fallback: write directly to target (old-format data)
    auto it = targets_.find(conn_id);
    if (it != targets_.end()) {
        int ret = it->second.writer.write(it->second.fd, payload, len);
        if (ret > 0 && !it->second.writer.registered)
            register_target_epollout(conn_id, it->second.fd);
    } else {
        log_debug("session %llx: data for unknown conn_id %u",
                  (unsigned long long)session_id_, conn_id);
    }
}

void Session::register_data_connection_reader(size_t idx) {
    if (idx >= data_connections_.size()) return;
    int fd = data_connections_[idx].fd;
    if (fd < 0) return;
    auto self = shared_from_this();
    kernel_->add_fd_handler(fd, [this, self, idx](int ev_fd, uint32_t events) {
        (void)ev_fd;
        if (events & EPOLLIN) {
            auto &dc = data_connections_[idx];
            uint8_t tmp[65536];
            ssize_t n = read(dc.fd, tmp, sizeof(tmp));
            if (n > 0)
                dc.read_buf.insert(dc.read_buf.end(), tmp, tmp + n);

            while (true) {
                auto &buf = dc.read_buf;
                if (buf.size() < 1) break;
                size_t pos = 0;
                size_t val = 0;
                int shift = 0;
                while (pos < buf.size() && shift < 56) {
                    uint8_t byte = buf[pos++];
                    val |= (size_t)(byte & 0x7F) << shift;
                    if (!(byte & 0x80)) break;
                    shift += 7;
                }
                if (pos >= 10 || shift >= 56) { buf.clear(); break; }
                if (pos > buf.size() || pos + val > buf.size()) break;

                uint8_t first = buf[pos];
                if (first == 255) {
                    dispatch_data_conn_packet(255, buf.data() + pos + 1, val - 1);
                } else if (chain_ && chain_->valid() && idx < chain_out_writers_.size()) {
                    int out_fd = chain_->output_fds()[idx];
                    int ret = chain_out_writers_[idx].write(out_fd, buf.data(), pos + val);
                    if (ret > 0 && !chain_out_writers_[idx].registered)
                        register_chain_out_epollout(idx, out_fd);
                } else {
                    // No chain: old-format data, fall back to dispatch as conn_id
                    dispatch_data_conn_packet(first, buf.data() + pos + 1, val - 1);
                }
                buf.erase(buf.begin(), buf.begin() + pos + val);
                }
                }
        if (events & (EPOLLERR | EPOLLHUP)) {
            log_debug("session %llx: data connection %zu closed",
                      (unsigned long long)session_id_, idx);
        }
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
            bool drained = data_connections_[idx].writer.flush(data_connections_[idx].fd);
            if (drained) {
                data_connections_[idx].writer.registered = false;
                kernel_->mod_fd_events(data_connections_[idx].fd, 0, EPOLLOUT);
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

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    targets_[conn_id] = {fd, target_addr};
    log_info("session %llx: connected to target %s:%s (fd=%d, conn_id=%u)",
             (unsigned long long)session_id_, host.c_str(), port.c_str(), fd, conn_id);
    return true;
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
    log_info("session %llx: client disconnected, pausing chain",
             (unsigned long long)session_id_);

    saved_targets_.clear();
    for (auto &kv : targets_)
        saved_targets_.emplace_back(kv.first, kv.second.addr);

    if (chain_) {
        for (auto &mf : chain_->module_fds())
            kernel_->del_fd(mf.first);
        for (int out_fd : chain_->output_fds())
            kernel_->del_fd(out_fd);
        if (chain_->input_fd() >= 0)
            kernel_->del_fd(chain_->input_fd());
    }
    close_all_targets();

    // Close and clear data connection fds so add_data_connection works on reconnect
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
    // data_connections_[0] (client_fd_) closed below; keep it for ~Session cleanup
    // but mark it invalid so add_data_connection can reassign.
    // Actually data_connections_[0].fd is client_fd_; we already called del_fd above.
    // client_fd_ itself is closed in reconnect() when replaced.

    paused_ = true;
    log_debug("session %llx: chain paused, waiting for reconnect",
              (unsigned long long)session_id_);
}

bool Session::reconnect(int new_client_fd) {
    if (!paused_ || !chain_) {
        log_error("session %llx: reconnect failed — not paused or no chain",
                  (unsigned long long)session_id_);
        return false;
    }

    log_info("session %llx: client reconnected", (unsigned long long)session_id_);

    // Close old client fd if still open
    if (client_fd_ >= 0 && client_fd_ != new_client_fd) {
        kernel_->del_fd(client_fd_);
        close(client_fd_);
    }
    client_fd_ = new_client_fd;

    // Keep ourselves alive during reconnection setup
    auto self = shared_from_this();

    // Remove from paused set (session kept alive by local self)
    g_paused_sessions.erase(session_id_);

    // Re-register chain output handlers — RAW PIPE: reads bytes from chain
    // and writes directly to data connection wire.

    auto chain_out_fds = chain_->output_fds();
    for (size_t i = 0; i < chain_out_fds.size(); i++) {
        int out_fd = chain_out_fds[i];
        set_nonblock(out_fd);
        kernel_->add_fd_handler(out_fd, [this, i](int fd, uint32_t events) {
            if (events & EPOLLIN) {
                uint8_t tmp[65536];
                ssize_t n = read(fd, tmp, sizeof(tmp));
                if (n > 0) {
                    if (i < data_connections_.size() && data_connections_[i].fd >= 0) {
                        int dc_fd = data_connections_[i].fd;
                        int ret = data_connections_[i].writer.write(dc_fd, tmp, n);
                        if (ret > 0 && !data_connections_[i].writer.registered)
                            register_data_conn_epollout(i, dc_fd);
                    }
                }
            }
        });
    }

    // Register chain input read handler for reverse direction (target → chain → client)
    chain_in_read_buf_.clear();
    if (chain_->input_fd() >= 0) {
        set_nonblock(chain_->input_fd());
        kernel_->add_fd_handler(chain_->input_fd(), [this](int fd, uint32_t events) {
            if (events & EPOLLIN) {
                uint8_t tmp[65536];
                ssize_t n = read(fd, tmp, sizeof(tmp));
                if (n > 0)
                    chain_in_read_buf_.insert(chain_in_read_buf_.end(), tmp, tmp + n);

                while (true) {
                    if (chain_in_read_buf_.size() < 1) break;
                    size_t pos = 0;
                    size_t val = 0;
                    int shift = 0;
                    while (pos < chain_in_read_buf_.size() && shift < 56) {
                        uint8_t byte = chain_in_read_buf_[pos++];
                        val |= (size_t)(byte & 0x7F) << shift;
                        if (!(byte & 0x80)) break;
                        shift += 7;
                    }
                    if (pos >= 10 || shift >= 56) { chain_in_read_buf_.clear(); break; }
                    if (pos > chain_in_read_buf_.size() || pos + val > chain_in_read_buf_.size()) break;

                    if (val < 2) { chain_in_read_buf_.clear(); break; }
                    uint8_t type = chain_in_read_buf_[pos];
                    uint8_t conn_id = chain_in_read_buf_[pos + 1];
                    if (type == TYPE_DATA) {
                        auto it = targets_.find(conn_id);
                        if (it != targets_.end()) {
                            WriteBuffer &w = it->second.writer;
                            int tfd = it->second.fd;
                            int ret = w.write(tfd, chain_in_read_buf_.data() + pos + 2, val - 2);
                            if (ret > 0 && !w.registered)
                                register_target_epollout(conn_id, tfd);
                            if (w.size() >= w.high_water && !it->second.pause_sent) {
                                it->second.pause_sent = true;
                                send_pause(conn_id);
                            }
                        } else {
                            log_debug("session %llx: reconnect chain input TYPE_DATA for unknown conn_id %u",
                                      (unsigned long long)session_id_, conn_id);
                        }
                    } else if (type == TYPE_DISCONNECT) {
                        close_target(conn_id);
                    } else if (type == TYPE_PAUSE) {
                        send_pause(conn_id);
                    } else if (type == TYPE_RESUME) {
                        send_resume(conn_id);
                    }
                    chain_in_read_buf_.erase(chain_in_read_buf_.begin(),
                                             chain_in_read_buf_.begin() + pos + val);
                }
            }
        });
    }

    // Restore all target connections
    for (auto &saved : saved_targets_) {
        uint8_t conn_id = saved.first;
        std::string addr = saved.second;
        if (!setup_tunnel_target(addr, conn_id)) {
            log_error("session %llx: reconnect: target %s conn_id=%u failed",
                      (unsigned long long)session_id_, addr.c_str(), conn_id);
            continue;
        }
        int tfd = targets_[conn_id].fd;
        kernel_->add_fd_handler(tfd, [this, conn_id](int fd, uint32_t events) {
            if (events & EPOLLIN) {
                int in_fd = chain_ ? chain_->input_fd() : -1;
                uint8_t rbuf[65536];
                ssize_t n = read(fd, rbuf, sizeof(rbuf));
                if (n > 0) {
                    if (chain_ && chain_->valid() && in_fd >= 0) {
                        std::vector<uint8_t> pkt = {TYPE_DATA, conn_id};
                        pkt.insert(pkt.end(), rbuf, rbuf + n);
                        auto framed = make_varint_packet(pkt.data(), pkt.size());
                        int ret = chain_in_writer_.write(in_fd, framed.data(), framed.size());
                        if (ret > 0 && !chain_in_writer_.registered)
                            register_chain_input_out();
                        if (chain_in_writer_.size() > 0) {
                            auto tit = targets_.find(conn_id);
                            if (tit != targets_.end() && !tit->second.paused_by_backpressure) {
                                tit->second.paused_by_backpressure = true;
                                kernel_->mod_fd_events(tit->second.fd, 0, EPOLLIN);
                            }
                        }
                    } else {
                        auto framed = make_varint_packet_with_conn_id(conn_id, rbuf, (size_t)n);
                        if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
                            int dc_fd = data_connections_[0].fd;
                            int ret = data_connections_[0].writer.write(dc_fd, framed.data(), framed.size());
                            if (ret > 0 && !data_connections_[0].writer.registered)
                                register_data_conn_epollout(0, dc_fd);
                        }
                    }
                } else if (n == 0) {
                    if (chain_ && chain_->valid()) {
                        std::vector<uint8_t> marker = {TYPE_DISCONNECT, conn_id};
                        auto framed = make_varint_packet(marker.data(), marker.size());
                        chain_in_writer_.write(chain_->input_fd(), framed.data(), framed.size());
                        if (chain_in_writer_.size() > 0 && !chain_in_writer_.registered)
                            register_chain_input_out();
                        close_target(conn_id);
                    } else {
                        close_target(conn_id);
                        std::vector<uint8_t> d = {conn_id};
                        Packet dpkt = Protocol::make_msg(MSG_DISCONNECT, d);
                        send_control(dpkt);
                    }
                }
            }
        });
    }
    saved_targets_.clear();

    // Re-register module input fds
    for (auto &mf : chain_->module_fds())
        kernel_->add_fd(mf.first, chain_, mf.second);

    // Register data connection reader on client_fd_ (data_connections_[0])
    data_connections_[0].fd = client_fd_;
    register_data_connection_reader(0);

    paused_ = false;
    state_ = RUNNING;

    log_info("session %llx: chain resumed after reconnect", (unsigned long long)session_id_);
    return true;
}

void Session::register_chain_input_out() {
    if (!chain_ || !chain_->valid()) return;
    int fd = chain_->input_fd();
    if (fd < 0) return;
    if (chain_in_writer_.registered) return;
    chain_in_writer_.registered = true;
    auto self = shared_from_this();
    kernel_->add_fd_handler(fd, [this, self](int, uint32_t events) {
        if (events & EPOLLOUT) flush_write_buf();
        if (events & (EPOLLERR | EPOLLHUP)) chain_in_writer_.clear();
    }, EPOLLOUT);
}

void Session::flush_write_buf() {
    int fd = chain_->input_fd();
    if (fd < 0) {
        chain_in_writer_.clear();
        return;
    }
    bool drained = chain_in_writer_.flush(fd);
    if (drained) {
        if (chain_in_writer_.registered) {
            chain_in_writer_.registered = false;
            kernel_->mod_fd_events(fd, 0, EPOLLOUT);
        }
        resume_paused_targets();
    }
}

void Session::resume_paused_targets() {
    for (auto &kv : targets_) {
        if (kv.second.paused_by_backpressure) {
            kv.second.paused_by_backpressure = false;
            kernel_->mod_fd_events(kv.second.fd, EPOLLIN, 0);
        }
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
                if (it2->second.pause_sent) {
                    it2->second.pause_sent = false;
                    send_resume(conn_id);
                }
            }
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            targets_.erase(conn_id);
        }
    }, EPOLLOUT);
}

void Session::register_chain_out_epollout(size_t idx, int out_fd) {
    if (idx >= chain_out_writers_.size()) {
        log_error("session %llx: chain_out_epollout idx=%zu >= size=%zu",
                  (unsigned long long)session_id_, idx, chain_out_writers_.size());
        return;
    }
    if (chain_out_writers_[idx].registered) return;
    chain_out_writers_[idx].registered = true;
    auto self = shared_from_this();
    kernel_->add_fd_handler(out_fd, [this, self, idx, out_fd](int fd, uint32_t events) {
        if (events & EPOLLOUT) {
            if (idx >= chain_out_writers_.size()) return;
            size_t before = chain_out_writers_[idx].size();
            bool drained = chain_out_writers_[idx].flush(fd);
            size_t after = chain_out_writers_[idx].size();
            if (drained) {
                chain_out_writers_[idx].registered = false;
                kernel_->mod_fd_events(fd, 0, EPOLLOUT);
            }
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            if (idx < chain_out_writers_.size())
                chain_out_writers_[idx].clear();
        }
    }, EPOLLOUT);
}

void Session::send_pause(uint8_t conn_id) {
    std::vector<uint8_t> payload = {conn_id};
    Packet pkt = Protocol::make_msg(MSG_CONNECT_PAUSE, payload);
    send_control(pkt);
}

void Session::send_resume(uint8_t conn_id) {
    std::vector<uint8_t> payload = {conn_id};
    Packet pkt = Protocol::make_msg(MSG_CONNECT_RESUME, payload);
    send_control(pkt);
}
