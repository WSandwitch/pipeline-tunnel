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
    if (state_ == AWAIT_CONNECT_REQ) {
        recv_buf_.insert(recv_buf_.end(), data, data + len);
        Packet pkt;
        size_t consumed = proto_.try_parse(recv_buf_.data(), recv_buf_.size(), pkt);
        if (consumed > 0 && pkt.type == MSG_CONNECT_REQ) {
            recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + consumed);
            handle_connect_req(pkt);
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
        }
        return;
    }

    if (client_fd_ < 0) return;

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
                if (state_ == AWAIT_CONNECT_REQ)
                    handle_reconnect(pkt);
                break;
            case MSG_CONNECT_REQ:
                if (state_ == AWAIT_CONNECT_REQ || state_ == RUNNING)
                    handle_connect_req(pkt);
                break;
            case MSG_DISCONNECT:
                if (state_ == RUNNING || state_ == AWAIT_CONNECT_REQ)
                    handle_disconnect(pkt);
                break;
            case MSG_CONNECT_PAUSE:
                if (state_ == RUNNING || state_ == AWAIT_CONNECT_REQ) {
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
                if (state_ == RUNNING || state_ == AWAIT_CONNECT_REQ) {
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
        data_connections_.resize(1);
        data_connections_[0].fd = client_fd_;
        register_data_connection_reader(0);
        state_ = AWAIT_CONNECT_REQ;
    } else {
        log_error("session %llx: auth2 failed", (unsigned long long)session_id_);
        state_ = DISCONNECTED;
    }
}

void Session::handle_reconnect(const Packet &pkt) {
    if (pkt.payload.size() != 8) {
        Packet fail = Protocol::make_msg(MSG_AUTH_OK, "\x00", 1);
        send_packet(fail);
        return;
    }
    uint64_t sid;
    memcpy(&sid, pkt.payload.data(), 8);
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

void Session::handle_connect_req(const Packet &pkt) {
    if (pkt.payload.size() < 2) {
        log_error("session %llx: MSG_CONNECT_REQ too short", (unsigned long long)session_id_);
        return;
    }
    uint8_t conn_id = pkt.payload[0];
    uint8_t addr_len = pkt.payload[1];
    if (2 + addr_len > pkt.payload.size()) {
        log_error("session %llx: MSG_CONNECT_REQ addr length mismatch", (unsigned long long)session_id_);
        return;
    }
    std::string target_addr((const char *)pkt.payload.data() + 2, addr_len);
    log_info("session %llx: MSG_CONNECT_REQ conn_id=%u target='%s'",
             (unsigned long long)session_id_, conn_id, target_addr.c_str());

    if (targets_.count(conn_id)) {
        log_error("session %llx: duplicate conn_id %u", (unsigned long long)session_id_, conn_id);
        return;
    }

    if (!setup_tunnel_target(target_addr, conn_id))
        return;

    int tfd = targets_[conn_id].fd;
    auto self = shared_from_this();
    kernel_->add_fd_handler(tfd, [this, self, conn_id](int fd, uint32_t events) {
        try {
            if (events & EPOLLIN) {
                uint8_t rbuf[65536];
                ssize_t n = read(fd, rbuf, sizeof(rbuf));
                if (n > 0) {
                    auto framed = make_varint_packet_with_conn_id(conn_id, rbuf, (size_t)n);
                    if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
                        int dc_fd = data_connections_[0].fd;
                        int ret = data_connections_[0].writer.write(dc_fd, framed.data(), framed.size());
                        if (ret > 0 && !data_connections_[0].writer.registered)
                            register_data_conn_epollout(0, dc_fd);
                    }
                } else if (n == 0) {
                    close_target(conn_id);
                    std::vector<uint8_t> disconnect_payload = {conn_id};
                    Packet d = Protocol::make_msg(MSG_DISCONNECT, disconnect_payload);
                    send_control(d);
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

    state_ = RUNNING;
    log_info("session %llx: tunnel connected conn_id=%u -> %s",
             (unsigned long long)session_id_, conn_id, target_addr.c_str());
}

void Session::handle_disconnect(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    close_target(conn_id);
}

void Session::add_data_connection(uint8_t output_idx, int fd) {
    if (output_idx >= data_connections_.size()) {
        close(fd);
        return;
    }
    if (data_connections_[output_idx].fd >= 0) {
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
                log_debug("session %llx: PAUSE recv — pausing data conn reader",
                          (unsigned long long)session_id_);
                if (!data_connections_.empty())
                    data_connections_[0].paused = true;
                break;
            case MSG_CONNECT_RESUME:
                log_debug("session %llx: RESUME recv — resuming data conn reader",
                          (unsigned long long)session_id_);
                if (!data_connections_.empty() && data_connections_[0].paused) {
                    data_connections_[0].paused = false;
                }
                break;
            default:
                log_debug("session %llx: unexpected control msg %d via data conn",
                          (unsigned long long)session_id_, (int)pkt.type);
                break;
        }
        return;
    }

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
        try {
        if (events & EPOLLIN) {
            auto &dc = data_connections_[idx];
            if (dc.paused)
                log_debug("session %llx: reader called while paused fd=%d",
                          (unsigned long long)session_id_, dc.fd);
            uint8_t tmp[65536];
            ssize_t n = read(dc.fd, tmp, sizeof(tmp));
            if (n > 0) {
                dc.read_buf.insert(dc.read_buf.end(), tmp, tmp + n);
                // Prepend any data buffered during pause
                if (!dc.paused_data.empty()) {
                    dc.read_buf.insert(dc.read_buf.begin() + dc.read_offset,
                                       dc.paused_data.begin(), dc.paused_data.end());
                    dc.paused_data.clear();
                }
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
                    if (dc.paused && ptr[pos] != 255) {
                        // Buffer data messages for later when resumed
                        dc.paused_data.insert(dc.paused_data.end(),
                                              ptr, ptr + pos + val);
                    } else {
                        dispatch_data_conn_packet(ptr[pos], ptr + pos + 1, val - 1);
                    }
                    off += pos + val;
                }
                if (off > 65536) {
                    buf.erase(buf.begin(), buf.begin() + off);
                    off = 0;
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

    int bufsz = 1048576;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

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
    log_info("session %llx: client disconnected", (unsigned long long)session_id_);

    saved_targets_.clear();
    for (auto &kv : targets_)
        saved_targets_.emplace_back(kv.first, kv.second.addr);

    close_all_targets();

    // Clear data connection state
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

    // Restore data connection
    data_connections_[0].fd = client_fd_;
    register_data_connection_reader(0);

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
        auto self = shared_from_this();
        kernel_->add_fd_handler(tfd, [this, self, conn_id](int fd, uint32_t events) {
            if (events & EPOLLIN) {
                uint8_t rbuf[65536];
                ssize_t n = read(fd, rbuf, sizeof(rbuf));
                if (n > 0) {
                    auto framed = make_varint_packet_with_conn_id(conn_id, rbuf, (size_t)n);
                    if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
                        int dc_fd = data_connections_[0].fd;
                        int ret = data_connections_[0].writer.write(dc_fd, framed.data(), framed.size());
                        if (ret > 0 && !data_connections_[0].writer.registered)
                            register_data_conn_epollout(0, dc_fd);
                    }
                } else if (n == 0) {
                    close_target(conn_id);
                }
            }
        });
    }
    saved_targets_.clear();

    paused_ = false;
    state_ = RUNNING;

    log_info("session %llx: resumed after reconnect", (unsigned long long)session_id_);
    return true;
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
