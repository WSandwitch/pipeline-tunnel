#include "client.h"
#include "common/logger.h"
#include "common/utils.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <dirent.h>
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

void Client::load_module_registry(const std::string &dir) {
    if (dir.empty()) return;
    DIR *d = opendir(dir.c_str());
    if (!d) {
        log_error("client: cannot open module dir %s: %m", dir.c_str());
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != nullptr) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len > 3 && strcmp(name + len - 3, ".so") == 0) {
            Module m;
            std::string so_path = dir + "/" + name;
            if (m.load(so_path)) {
                module_registry_[m.name()] = so_path;
                log_info("client: registered module %s -> %s",
                         m.name(), so_path.c_str());
            }
        }
    }
    closedir(d);
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
      mod_dir_(mod_dir),
      thread_count_(thread_count) {
    kernel_ = std::make_shared<Kernel>();
    load_module_registry(mod_dir_);
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
    }
}

void Client::open_additional_connections() {
    for (uint8_t i = 1; i < num_outputs_; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            log_error("client: data connection socket %u failed", i);
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port_);
        inet_pton(AF_INET, server_host_.c_str(), &addr.sin_addr);
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("client: data connection %u connect failed: %s", i, strerror(errno));
            close(fd);
            continue;
        }
        // Send handshake: session_id (8 LE) + output_index (1)
        uint8_t handshake[9];
        memcpy(handshake, &session_id_, 8);
        handshake[8] = i;
        ssize_t n = write(fd, handshake, 9);
        if (n != 9) {
            log_error("client: data connection %u handshake write failed", i);
            close(fd);
            continue;
        }
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        data_connections_[i].fd = fd;
        register_data_connection_reader(i);
        log_info("client: data connection %u opened (fd=%d)", i, fd);
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
                } else if (chain_ && chain_->valid()) {
                    auto out_fds = chain_->output_fds();
                    if (idx < out_fds.size()) {
                        int out_fd = out_fds[idx];
                        int ret = chain_out_writer_.write(out_fd, buf.data(), pos + val);
                        if (ret > 0 && !chain_out_writer_.registered)
                            register_chain_out_epollout(out_fd);
                        if (chain_out_writer_.size() > 0 && !dc.paused) {
                            dc.paused = true;
                            kernel_->mod_fd_events(dc.fd, 0, EPOLLIN);
                        }
                    }
                } else {
                    dispatch_data_conn_packet(first, buf.data() + pos + 1, val - 1);
                }
                buf.erase(buf.begin(), buf.begin() + pos + val);
            }
            if (chain_) chain_->retry_buffered();
        }
        if (events & (EPOLLERR | EPOLLHUP)) {
            log_debug("client: data connection %zu closed", idx);
        }
    }, EPOLLIN);
}

void Client::dispatch_data_conn_packet(uint8_t conn_id, const uint8_t *payload, size_t len) {
    if (conn_id == 255) {
        // Control message — parse as protocol packet and dispatch
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

    // No-chain fallback: write directly to external (old-format data)
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
    std::lock_guard<std::mutex> lock(conns_mtx_);
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
    // Close data connections (except index 0 which is tcp_fd_)
    for (size_t i = 1; i < data_connections_.size(); i++) {
        if (data_connections_[i].fd >= 0) {
            kernel_->del_fd(data_connections_[i].fd);
            close(data_connections_[i].fd);
        }
    }
    data_connections_.clear();
    if (chain_) {
        for (int fd : chain_->output_fds())
            kernel_->del_fd(fd);
        kernel_->remove_chain(session_id_);
        if (chain_->input_fd() >= 0) {
            kernel_->del_fd(chain_->input_fd());
        }
        chain_.reset();
    }
    if (kernel_) {
        kernel_->stop();
    }
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

    std::thread([this] {
        while (listen_fd_ >= 0) {
            struct sockaddr_in caddr;
            socklen_t alen = sizeof(caddr);
            int cfd = accept(listen_fd_, (struct sockaddr *)&caddr, &alen);
            if (cfd < 0) { if (errno == EINTR) continue; break; }
            on_listener_accept(cfd, caddr);
        }
    }).detach();
}

void Client::on_listener_accept(int cfd, const struct sockaddr_in &addr) {
    uint8_t conn_id = next_conn_id_++;
    log_info("client: external connection conn_id=%u from %s",
             conn_id, sockaddr_to_str(addr).c_str());

    set_nonblock(cfd);
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        conns_.emplace(conn_id, ExternalConn{cfd, addr, false});
    }

    // Send MSG_CONNECT_REQ with conn_id + target addr (use addr from -L)
    std::string target = target_addr_;
    if (target.empty()) {
        log_error("client: no target address for conn_id=%u", conn_id);
        close(cfd);
        {
            std::lock_guard<std::mutex> lock(conns_mtx_);
            conns_.erase(conn_id);
        }
        return;
    }
    std::vector<uint8_t> payload;
    payload.push_back(conn_id);
    payload.push_back((uint8_t)target.size());
    payload.insert(payload.end(), target.begin(), target.end());
    Packet req = Protocol::make_msg(MSG_CONNECT_REQ, payload);
    send_control(req);

    // Register in epoll instead of creating a thread
    kernel_->add_fd_handler(cfd, [this, conn_id](int fd, uint32_t events) {
        if (events & EPOLLIN) {
            uint8_t buf[65536];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                on_external_recv(conn_id, buf, (size_t)n);
            } else if (n == 0) {
                on_external_disconnect(conn_id);
            }
        }
        if (events & (EPOLLERR | EPOLLHUP))
            on_external_disconnect(conn_id);
    }, EPOLLIN);
}

void Client::on_external_recv(int conn_id, const uint8_t *data, size_t len) {
    if (chain_ && chain_->valid()) {
        std::vector<uint8_t> payload = {TYPE_DATA, (uint8_t)conn_id};
        payload.insert(payload.end(), data, data + len);
        auto framed = make_varint_packet(payload.data(), payload.size());
        int in_fd = chain_->input_fd();
        if (in_fd >= 0) {
            int ret = chain_in_writer_.write(in_fd, framed.data(), framed.size());
            if (ret > 0 && !chain_in_writer_.registered)
                register_chain_in_epollout(in_fd);
            if (chain_in_writer_.size() > 0) {
                std::lock_guard<std::mutex> lock(conns_mtx_);
                auto it = conns_.find((uint8_t)conn_id);
                if (it != conns_.end() && !it->second.paused_by_backpressure) {
                    it->second.paused_by_backpressure = true;
                    kernel_->mod_fd_events(it->second.fd, 0, EPOLLIN);
                }
            }
        }
    } else {
        // No chain: send raw varint over data connection 0
        auto framed = make_varint_packet_with_conn_id((uint8_t)conn_id, data, len);
        if (!data_connections_.empty() && data_connections_[0].fd >= 0) {
            int dc_fd = data_connections_[0].fd;
            int ret = data_connections_[0].writer.write(dc_fd, framed.data(), framed.size());
            if (ret > 0 && !data_connections_[0].writer.registered)
                register_data_conn_epollout(0, dc_fd);
        }
    }
}

void Client::on_external_disconnect(uint8_t conn_id) {
    log_info("client: external conn_id=%u disconnected", conn_id);
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        fd = it->second.fd;
        conns_.erase(it);
    }
    if (fd >= 0) {
        kernel_->del_fd(fd);
        close(fd);
    }
    if (chain_ && chain_->valid()) {
        std::vector<uint8_t> marker = {TYPE_DISCONNECT, conn_id};
        auto framed = make_varint_packet(marker.data(), marker.size());
        chain_in_writer_.write(chain_->input_fd(), framed.data(), framed.size());
        if (chain_in_writer_.size() > 0 && !chain_in_writer_.registered)
            register_chain_in_epollout(chain_->input_fd());
    } else {
        std::vector<uint8_t> payload = {conn_id};
        Packet dpkt = Protocol::make_msg(MSG_DISCONNECT, payload);
        send_control(dpkt);
    }
}

void Client::finish_disconnect(uint8_t conn_id) {
    int fd = -1;
    bool drained = false;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        fd = it->second.fd;
        it->second.writer.flush(fd);
        if (it->second.writer.empty()) {
            drained = true;
            it->second.writer.registered = false;
            conns_.erase(it);
        }
    }
    if (drained && fd >= 0) {
        kernel_->del_fd(fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

void Client::send_raw_to_external(uint8_t conn_id, const uint8_t *data, size_t len) {
    bool should_pause = false;
    bool need_epollout = false;
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) {
            log_debug("client: send_raw_to_external conn_id=%u NOT FOUND", conn_id);
            return;
        }
        auto &w = it->second.writer;
        fd = it->second.fd;
        if (fd < 0) return;
        int ret = w.write(fd, data, len);
        if (ret > 0 && !w.registered)
            need_epollout = true;
        if (w.size() >= w.high_water && !it->second.pause_sent) {
            it->second.pause_sent = true;
            should_pause = true;
        }
    }
    if (need_epollout)
        register_external_epollout(conn_id, fd);
    if (should_pause)
        send_pause(conn_id);
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
            case MSG_MODULE_LIST_RES:
                if (state_ == AWAIT_MODULE_LIST_RES) handle_module_list_res(pkt);
                break;
            case MSG_CHAIN_READY:
                if (state_ == AWAIT_CHAIN_READY) handle_chain_ready(pkt);
                break;
            case MSG_CONNECT_OK:
                if (state_ == AWAIT_CONNECT_OK) handle_connect_ok(pkt);
                break;
            case MSG_CONNECT_FAIL:
                if (state_ == AWAIT_CONNECT_OK) handle_connect_fail(pkt);
                break;
            case MSG_DISCONNECT:
                if (state_ == AWAIT_CONNECT_OK) handle_disconnect(pkt);
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
        { std::lock_guard<std::mutex> lock(ready_mutex_); failed_ = true; }
        ready_cv_.notify_one();
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
        state_ = AWAIT_MODULE_LIST_RES;
        send_packet(Protocol::make_msg(MSG_MODULE_LIST_REQ));
    } else {
        log_error("client: auth2 failed");
        state_ = DISCONNECTED;
    }
}

void Client::handle_module_list_res(const Packet &pkt) {
    std::vector<std::string> server_mods;
    size_t pos = 0;
    if (pos < pkt.payload.size()) {
        uint8_t count = pkt.payload[pos++];
        for (int i = 0; i < count && pos < pkt.payload.size(); i++) {
            uint8_t nl = pkt.payload[pos++];
            if (pos + nl > pkt.payload.size()) break;
            server_mods.emplace_back((const char *)pkt.payload.data() + pos, nl);
            pos += nl;
        }
    }
    std::vector<uint8_t> chain_data;
    for (auto &ms : modules_) {
        uint8_t mod_id = 0;
        for (size_t i = 0; i < server_mods.size(); i++) {
            if (server_mods[i] == ms.name) {
                mod_id = (uint8_t)i;
                break;
            }
        }
        chain_data.push_back(mod_id);
        chain_data.push_back((uint8_t)ms.params.size());
        chain_data.insert(chain_data.end(), ms.params.begin(), ms.params.end());
    }
    send_packet(Protocol::make_msg(MSG_CHAIN_CREATE, chain_data));
    state_ = AWAIT_CHAIN_READY;
}

void Client::handle_chain_ready(const Packet &pkt) {
    if (pkt.payload.size() < 1 || pkt.payload[0] != 0x01) {
        log_error("client: chain creation failed");
        { std::lock_guard<std::mutex> lock(ready_mutex_); failed_ = true; }
        ready_cv_.notify_one();
        return;
    }
    if (pkt.payload.size() >= 9)
        memcpy(&session_id_, pkt.payload.data() + 1, 8);

    // Parse num_outputs (1 byte after session_id)
    num_outputs_ = (pkt.payload.size() >= 10) ? pkt.payload[9] : 1;

    log_info("client: chain ready, session=%llx outputs=%u listen=%s:%d",
             (unsigned long long)session_id_, num_outputs_,
             listen_addr_.c_str(), listen_port_);

    build_client_chain();

    // Set up data connections
    data_connections_.resize(num_outputs_);
    data_connections_[0].fd = tcp_fd_;

    // Switch tcp_fd_ from protocol reader to data connection reader
    kernel_->del_fd(tcp_fd_);
    register_data_connection_reader(0);

    // Open additional connections for outputs 1..N-1
    open_additional_connections();

    state_ = RUNNING;
    if (listen_port_ > 0) {
        log_info("client: starting listener on %s:%d",
                 listen_addr_.c_str(), listen_port_);
        start_listener();
    }
    { std::lock_guard<std::mutex> lock(ready_mutex_); ready_ = true; }
    ready_cv_.notify_one();
}

void Client::build_client_chain() {
    auto resolver = [this](const std::string &name) -> std::string {
        auto it = module_registry_.find(name);
        if (it != module_registry_.end())
            return it->second;
        return "";
    };

    ChainConfig cfg;
    cfg.valid = true;
    cfg.modules = modules_;

    chain_ = std::make_shared<Chain>(session_id_, cfg, resolver);
    if (!chain_->build()) {
        log_error("client: chain build failed");
        chain_.reset();
        return;
    }
    chain_->set_kernel(kernel_.get());

    for (int out_fd : chain_->output_fds()) set_nonblock(out_fd);
    set_nonblock(chain_->input_fd());
    fcntl(chain_->input_fd(), F_SETPIPE_SZ, 1048576);

    // Register chain output handler — RAW PIPE: reads bytes from chain
    // and writes directly to data connection wire.
    auto chain_out_fds = chain_->output_fds();
    for (size_t i = 0; i < chain_out_fds.size(); i++) {
        int out_fd = chain_out_fds[i];
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
            if (chain_) chain_->retry_buffered();
        });
    }

    // Register chain input handler — reads varint {TYPE, conn_id, data} from chain,
    // dispatches by TYPE to external fd, disconnect, or pause/resume.
    int chain_in = chain_->input_fd();
    if (chain_in >= 0) {
        kernel_->add_fd_handler(chain_in, [this](int fd, uint32_t events) {
            if (events & EPOLLIN) {
                uint8_t tmp[65536];
                ssize_t n = read(fd, tmp, sizeof(tmp));
                if (n > 0)
                    chain_in_read_buf_.insert(chain_in_read_buf_.end(), tmp, tmp + n);

                while (true) {
                    auto &buf = chain_in_read_buf_;
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
                    if (val < 2) { buf.clear(); break; }

                    uint8_t type = buf[pos];
                    uint8_t conn_id = buf[pos + 1];
                    if (type == TYPE_DATA) {
                        send_raw_to_external(conn_id, buf.data() + pos + 2, val - 2);
                    } else if (type == TYPE_DISCONNECT) {
                        handle_disconnect(Protocol::make_msg(MSG_DISCONNECT, std::vector<uint8_t>{conn_id}));
                    } else if (type == TYPE_PAUSE) {
                        handle_connect_pause(Protocol::make_msg(MSG_CONNECT_PAUSE, std::vector<uint8_t>{conn_id}));
                    } else if (type == TYPE_RESUME) {
                        handle_connect_resume(Protocol::make_msg(MSG_CONNECT_RESUME, std::vector<uint8_t>{conn_id}));
                    }
                    buf.erase(buf.begin(), buf.begin() + pos + val);
                }
            }
            if (chain_) chain_->retry_buffered();
        });
    }

    // Register all module input fds with kernel
    for (auto &mf : chain_->module_fds()) {
        int mod_in_fd = mf.first;
        int mod_idx = mf.second;
        kernel_->add_fd(mod_in_fd, chain_, mod_idx);
    }

    log_info("client: chain built with %zu modules, dir=1", modules_.size());
}

// ── Epollout registration helpers ──

void Client::register_chain_in_epollout(int fd) {
    if (chain_in_writer_.registered) return;
    chain_in_writer_.registered = true;
    kernel_->add_fd_handler(fd, [this, fd](int, uint32_t events) {
        if (events & EPOLLOUT) {
            bool drained = chain_in_writer_.flush(fd);
            if (drained) {
                if (chain_in_writer_.registered) {
                    chain_in_writer_.registered = false;
                    kernel_->mod_fd_events(fd, 0, EPOLLOUT);
                }
                resume_paused_cfds();
            }
        }
        if (events & (EPOLLERR | EPOLLHUP))
            chain_in_writer_.clear();
    }, EPOLLOUT);
}

void Client::resume_paused_cfds() {
    std::lock_guard<std::mutex> lock(conns_mtx_);
    for (auto &kv : conns_) {
        if (kv.second.paused_by_backpressure) {
            kv.second.paused_by_backpressure = false;
            kernel_->mod_fd_events(kv.second.fd, EPOLLIN, 0);
        }
    }
}

void Client::resume_paused_dcfds() {
    for (size_t i = 0; i < data_connections_.size(); i++) {
        if (data_connections_[i].paused) {
            data_connections_[i].paused = false;
            kernel_->mod_fd_events(data_connections_[i].fd, EPOLLIN, 0);
        }
    }
}

void Client::register_chain_out_epollout(int fd) {
    if (chain_out_writer_.registered) return;
    chain_out_writer_.registered = true;
    kernel_->add_fd_handler(fd, [this, fd](int, uint32_t events) {
        if (events & EPOLLOUT) {
            bool drained = chain_out_writer_.flush(fd);
            if (drained && chain_out_writer_.registered) {
                chain_out_writer_.registered = false;
                kernel_->mod_fd_events(fd, 0, EPOLLOUT);
                resume_paused_dcfds();
            }
        }
        if (events & (EPOLLERR | EPOLLHUP))
            chain_out_writer_.clear();
    }, EPOLLOUT);
}

void Client::register_external_epollout(uint8_t conn_id, int fd) {
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end() || it->second.writer.registered) return;
        it->second.writer.registered = true;
    }
    kernel_->add_fd_handler(fd, [this, conn_id](int, uint32_t events) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            std::lock_guard<std::mutex> lock(conns_mtx_);
            conns_.erase(conn_id);
            return;
        }
        if (events & EPOLLOUT) {
            bool need_close = false;
            bool need_resume = false;
            int close_fd = -1;
            uint8_t resume_cid = 0;
            {
                std::lock_guard<std::mutex> lock(conns_mtx_);
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
            }
            if (need_close && close_fd >= 0) {
                kernel_->del_fd(close_fd);
                shutdown(close_fd, SHUT_RDWR);
                close(close_fd);
            }
            if (need_resume)
                send_resume(resume_cid);
        }
    }, EPOLLOUT);
}

// ── Pause/resume helpers ──

void Client::send_pause(uint8_t conn_id) {
    std::vector<uint8_t> payload = {conn_id};
    Packet pkt = Protocol::make_msg(MSG_CONNECT_PAUSE, payload);
    send_control(pkt);
}

void Client::send_resume(uint8_t conn_id) {
    std::vector<uint8_t> payload = {conn_id};
    Packet pkt = Protocol::make_msg(MSG_CONNECT_RESUME, payload);
    send_control(pkt);
}

void Client::handle_connect_pause(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        it->second.paused = true;
        fd = it->second.fd;
    }
    if (fd >= 0)
        kernel_->mod_fd_events(fd, 0, EPOLLIN);
}

void Client::handle_connect_resume(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        it->second.paused = false;
        fd = it->second.fd;
    }
    if (fd >= 0)
        kernel_->mod_fd_events(fd, EPOLLIN, 0);
}

// ── Connection management ──

void Client::handle_connect_ok(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    if (state_ == AWAIT_CONNECT_OK) {
        state_ = RUNNING;
        { std::lock_guard<std::mutex> lock(ready_mutex_); ready_ = true; }
        ready_cv_.notify_one();
    }
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it != conns_.end()) {
            it->second.connected = true;
            log_info("client: conn_id=%u connected to target", conn_id);
        }
    }
}

void Client::handle_connect_fail(const Packet &pkt) {
    uint8_t conn_id = pkt.payload[0];
    log_error("client: MSG_CONNECT_FAIL conn_id=%u", conn_id);
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        fd = it->second.fd;
        conns_.erase(it);
    }
    if (fd >= 0) {
        kernel_->del_fd(fd);
        close(fd);
    }
}

void Client::handle_disconnect(const Packet &pkt) {
    if (pkt.payload.size() < 1) return;
    uint8_t conn_id = pkt.payload[0];
    log_info("client: server disconnected conn_id=%u", conn_id);
    int fd = -1;
    bool drain = false;
    {
        std::lock_guard<std::mutex> lock(conns_mtx_);
        auto it = conns_.find(conn_id);
        if (it == conns_.end()) return;
        fd = it->second.fd;
        if (it->second.writer.empty()) {
            conns_.erase(it);
        } else {
            it->second.disconnecting = true;
            drain = true;
            if (!it->second.writer.registered) {
                it->second.writer.registered = true;
                kernel_->add_fd_handler(fd, [this, conn_id](int, uint32_t events) {
                    if (events & EPOLLOUT)
                        finish_disconnect(conn_id);
                    if (events & (EPOLLERR | EPOLLHUP)) {
                        std::lock_guard<std::mutex> l(conns_mtx_);
                        conns_.erase(conn_id);
                    }
                }, EPOLLOUT);
            }
        }
    }
    if (!drain && fd >= 0) {
        kernel_->del_fd(fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

bool Client::start() {
    if (!connect_to_server()) return false;
    state_ = AWAIT_AUTH1_CHALLENGE;

    // Register initial protocol reader via kernel
    kernel_->add_fd_handler(tcp_fd_, [this](int fd, uint32_t events) {
        if (events & EPOLLIN) {
            uint8_t buf[4096];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                on_server_data(buf, (size_t)n);
            } else if (n == 0) {
                log_info("client: server disconnected");
                state_ = DISCONNECTED;
                { std::lock_guard<std::mutex> lock(ready_mutex_); failed_ = true; }
                ready_cv_.notify_one();
            } else if (n < 0 && errno != EAGAIN) {
                log_info("client: server read error");
                state_ = DISCONNECTED;
                { std::lock_guard<std::mutex> lock(ready_mutex_); failed_ = true; }
                ready_cv_.notify_one();
            }
        }
    }, EPOLLIN);

    kernel_->start(thread_count_);
    return true;
}

bool Client::wait_ready() {
    std::unique_lock<std::mutex> lock(ready_mutex_);
    ready_cv_.wait(lock, [this] { return ready_ || failed_; });
    return ready_;
}
