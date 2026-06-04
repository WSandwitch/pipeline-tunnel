#include "client.h"
#include "common/logger.h"
#include "common/utils.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
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
               const std::string &mod_dir)
    : server_host_(server_host), server_port_(server_port),
      password_(password),
      listen_addr_(listen_addr), listen_port_(listen_port),
      target_addr_(target_addr),
      modules_(modules),
      mod_dir_(mod_dir) {
    kernel_ = std::make_shared<Kernel>();
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
    auto framed = make_varint_packet_with_conn_id(255, serialized.data(), serialized.size());
    if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
        int fd = data_connections_[0].fd;
        int ret = data_connections_[0].writer.write(fd, framed.data(), framed.size());
        if (ret > 0 && !data_connections_[0].writer.registered)
            register_data_conn_epollout(0, fd);
        if (ret < 0)
            log_error("client: send_control pkt_type=%d failed (ret=%d)", (int)pkt.type, ret);
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
            uint8_t tmp[65536];
            ssize_t n = read(dc.fd, tmp, sizeof(tmp));
            if (n > 0) {
                dc.read_buf.insert(dc.read_buf.end(), tmp, tmp + n);
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
                    try {
                        dispatch_data_conn_packet(ptr[pos], ptr + pos + 1, val - 1);
                    } catch (const std::exception &e) {
                        log_error("client: dispatch exception: %s (val=%zu, buf_sz=%zu)", e.what(), val, buf.size());
                        buf.clear(); off = 0;
                        break;
                    }
                    off += pos + val;
                }
                if (off > 65536) {
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

void Client::dispatch_data_conn_packet(uint8_t conn_id, const uint8_t *payload, size_t len) {
    if (conn_id == 255) {
        Packet pkt;
        size_t consumed = proto_.try_parse(payload, len, pkt);
        if (consumed == 0) return;
        switch (pkt.type) {
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
            default:
                log_debug("client: unexpected control msg %d via data conn", (int)pkt.type);
                break;
        }
        return;
    }
    send_raw_to_external(conn_id, payload, len);
}

void Client::register_data_conn_epollout(size_t idx, int fd) {
    if (idx >= data_connections_.size()) return;
    if (data_connections_[idx].writer.registered) return;
    data_connections_[idx].writer.registered = true;
    kernel_->add_fd_handler(fd, [this, idx](int ev_fd, uint32_t events) {
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
    uint8_t conn_id = next_conn_id_++;
    log_info("client: external connection conn_id=%u from %s",
             conn_id, sockaddr_to_str(addr).c_str());

    set_nonblock(cfd);
    int bufsz = 1048576;
    setsockopt(cfd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    conns_.emplace(conn_id, ExternalConn{cfd, addr, false});

    std::string target = target_addr_;
    if (target.empty()) {
        log_error("client: no target address for conn_id=%u", conn_id);
        close(cfd);
        conns_.erase(conn_id);
        return;
    }

    std::vector<uint8_t> payload = {conn_id, (uint8_t)target.size()};
    payload.insert(payload.end(), target.begin(), target.end());
    Packet pkt = Protocol::make_msg(MSG_CONNECT_REQ, payload);
    send_control(pkt);

    kernel_->add_fd_handler(cfd, [this, conn_id](int fd, uint32_t events) {
        if (events & EPOLLIN) {
            uint8_t buf[65536];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0)
                on_external_recv(conn_id, buf, (size_t)n);
            else if (n == 0)
                on_external_disconnect(conn_id);
        }
        if (events & (EPOLLERR | EPOLLHUP))
            on_external_disconnect(conn_id);
    }, EPOLLIN);
}

void Client::on_external_recv(int conn_id, const uint8_t *data, size_t len) {
    if (data_connections_.empty() || data_connections_[0].fd < 0) return;
    auto framed = make_varint_packet_with_conn_id((uint8_t)conn_id, data, len);
    int dc_fd = data_connections_[0].fd;
    int ret = data_connections_[0].writer.write(dc_fd, framed.data(), framed.size());
    if (ret > 0 && !data_connections_[0].writer.registered)
        register_data_conn_epollout(0, dc_fd);
}

void Client::on_external_disconnect(uint8_t conn_id) {
    log_info("client: external conn_id=%u disconnected", conn_id);
    int fd = -1;
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    fd = it->second.fd;
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
    if (len > 1024 * 1024) {
        log_error("client: send_raw_to_external huge len=%zu, conn_id=%u", len, conn_id);
    }
    int ret = w.write(fd, data, len);
    if (ret > 0 && !w.registered)
        need_epollout = true;
    if (w.size() >= w.high_water && !it->second.pause_sent) {
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
        log_debug("client: pause_sent conn_id=%u (writer=%zu)", conn_id, w.size());
        send_pause(conn_id);
    }
    if (should_resume) {
        log_debug("client: RESUME sent conn_id=%u (writer=%zu via send_raw)", conn_id, w.size());
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
                if (state_ == AWAIT_CONNECT_OK || state_ == RUNNING) handle_connect_ok(pkt);
                break;
            case MSG_CONNECT_FAIL:
                if (state_ == AWAIT_CONNECT_OK || state_ == RUNNING) handle_connect_fail(pkt);
                break;
            case MSG_DISCONNECT:
                if (state_ == RUNNING || state_ == AWAIT_CONNECT_OK) handle_disconnect(pkt);
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
    log_info("client: auth1 OK");
    client_challenge_ = std::to_string(rand()) + std::to_string(time(nullptr));
    Packet chal = Protocol::make_msg(MSG_AUTH_CHALLENGE, client_challenge_.data(), client_challenge_.size());
    send_packet(chal);
    state_ = AWAIT_AUTH2_OK;
}

void Client::handle_auth2_challenge(const Packet &pkt) {
    std::string got((const char *)pkt.payload.data(), pkt.payload.size());
    std::string expected = hex_sha256(client_challenge_ + password_);
    if (got == expected) {
        log_info("client: mutual auth done");
        send_packet(Protocol::make_msg(MSG_AUTH_OK, "\x01", 1));
        data_connections_.resize(1);
        data_connections_[0].fd = tcp_fd_;
        register_data_connection_reader(0);
        state_ = RUNNING;
        setup_ok_ = true;
        if (listen_port_ > 0) {
            log_info("client: starting listener on %s:%d",
                     listen_addr_.c_str(), listen_port_);
            start_listener();
        }
    } else {
        log_error("client: auth2 failed");
        state_ = DISCONNECTED;
        Kernel::request_stop();
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
            it2->second.writer.flush(it2->second.fd);
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
    if (state_ == AWAIT_CONNECT_OK) {
        state_ = RUNNING;
        setup_ok_ = true;
        if (listen_port_ > 0) {
            log_info("client: starting listener on %s:%d",
                     listen_addr_.c_str(), listen_port_);
            start_listener();
        }
    }
    auto it = conns_.find(conn_id);
    if (it != conns_.end()) {
        it->second.connected = true;
        log_info("client: conn_id=%u connected to target", conn_id);
    }
}

void Client::handle_connect_fail(const Packet &pkt) {
    uint8_t conn_id = pkt.payload[0];
    log_error("client: MSG_CONNECT_FAIL conn_id=%u", conn_id);
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    int fd = it->second.fd;
    conns_.erase(it);
    if (fd >= 0) {
        kernel_->del_fd(fd);
        close(fd);
    }
}

void Client::handle_disconnect(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    log_info("client: server disconnected conn_id=%u", conn_id);
    auto it = conns_.find(conn_id);
    if (it == conns_.end()) return;
    int fd = it->second.fd;
    if (it->second.writer.empty()) {
        conns_.erase(it);
    } else {
        it->second.disconnecting = true;
        if (!it->second.writer.registered) {
            it->second.writer.registered = true;
            kernel_->add_fd_handler(fd, [this, conn_id](int, uint32_t events) {
                if (events & EPOLLOUT)
                    finish_disconnect(conn_id);
                if (events & (EPOLLERR | EPOLLHUP))
                    conns_.erase(conn_id);
            }, EPOLLOUT);
        }
        return;
    }
    if (fd >= 0) {
        kernel_->del_fd(fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

void Client::send_raw(const uint8_t *data, size_t len) {
    (void)data; (void)len;
}

bool Client::start() {
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
    return setup_ok_;
}
