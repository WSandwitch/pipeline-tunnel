#include "server.h"
#include "session.h"
#include "common/logger.h"
#include "common/utils.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

extern std::unordered_map<uint64_t, std::weak_ptr<Session>> g_session_registry;
extern std::unordered_map<uint64_t, std::shared_ptr<Session>> g_paused_sessions;

Server::Server(const std::string &addr, uint16_t port,
               const std::string &password, int thread_count,
               int heartbeat_interval_ms)
    : listen_addr_(addr), listen_port_(port), password_(password),
      thread_count_(thread_count),
      heartbeat_interval_ms_(heartbeat_interval_ms) {}

Server::~Server() {
    stop();
}

bool Server::start() {
    kernel_ = std::make_shared<Kernel>();
    kernel_->start_workers(thread_count_);

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        log_error("server socket: %s", strerror(errno));
        return false;
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port_);
    inet_pton(AF_INET, listen_addr_.c_str(), &addr.sin_addr);

    if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("server bind %s:%d: %s",
                  listen_addr_.c_str(), listen_port_, strerror(errno));
        close(listen_fd_);
        return false;
    }

    if (listen(listen_fd_, 16) < 0) {
        log_error("server listen: %s", strerror(errno));
        close(listen_fd_);
        return false;
    }

    set_nonblock(listen_fd_);

    auto k = kernel_;
    kernel_->add_fd_handler(listen_fd_, [this, k](int fd, uint32_t events) {
        if (!(events & EPOLLIN)) return;
        while (true) {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int cfd = accept(fd, (struct sockaddr *)&client_addr, &addrlen);
            if (cfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                log_error("accept: %s", strerror(errno));
                break;
            }

            set_nonblock(cfd);

            // Try immediate read — data connections send 9-byte handshake right away
            uint8_t hdr[9];
            ssize_t nread = read(cfd, hdr, 9);

            // Shared handler for pending handshake accumulation (partial or EAGAIN)
            auto pending_handler = [this, k](int ev_fd, uint32_t events) {
                if (!(events & EPOLLIN)) return;
                size_t idx = pending_handshakes_.size();
                for (size_t i = 0; i < pending_handshakes_.size(); i++) {
                    if (pending_handshakes_[i].fd == ev_fd) { idx = i; break; }
                }
                if (idx >= pending_handshakes_.size()) return;
                auto &ph = pending_handshakes_[idx];
                ssize_t nr = read(ev_fd, ph.buf + ph.got, 9 - ph.got);
                if (nr > 0) {
                    ph.got += (size_t)nr;
                    if (ph.got == 9) {
                        finish_handshake(ev_fd, ph.buf, 9);
                        pending_handshakes_.erase(pending_handshakes_.begin() + idx);
                        return;
                    }
                    return; // still partial
                }
                if (nr == 0 || (nr < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    close(ev_fd);
                    k->del_fd(ev_fd);
                    pending_handshakes_.erase(pending_handshakes_.begin() + idx);
                }
            };

            if (nread > 0 && (size_t)nread < 9) {
                // Partial — register EPOLLIN to accumulate the rest
                pending_handshakes_.push_back({cfd, {}, 0, std::chrono::steady_clock::now()});
                memcpy(pending_handshakes_.back().buf, hdr, (size_t)nread);
                pending_handshakes_.back().got = (size_t)nread;
                kernel_->add_fd_handler(cfd, pending_handler, EPOLLIN);
            } else if (nread == 9) {
                // Full 9 bytes — check for data connection
                finish_handshake(cfd, hdr, 9);
            } else if (nread < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // No data yet — wait for EPOLLIN (could be data connection handshake)
                pending_handshakes_.push_back({cfd, {}, 0, std::chrono::steady_clock::now()});
                kernel_->add_fd_handler(cfd, pending_handler, EPOLLIN);
            } else if (nread > 0) {
                // nread > 0 but not 9 (shouldn't happen, but handle gracefully)
                finish_handshake(cfd, hdr, (size_t)nread);
            } else {
                // nread == 0 (EOF) or read error — close
                close(cfd);
            }
        }
    }, EPOLLIN);

    // Tick callback to process pending I/O for all sessions + handshake timeouts
    kernel_->set_tick_callback([this]() {
        check_handshake_timeout();
        std::vector<std::shared_ptr<Session>> alive;
        for (auto &[sid, wptr] : g_session_registry) {
            (void)sid;
            auto sess = wptr.lock();
            if (sess) alive.push_back(sess);
        }
        for (auto &sess : alive) {
            sess->process_pending_io();
            sess->check_heartbeat();
        }
    });

    log_info("server started on %s:%d", listen_addr_.c_str(), listen_port_);
    kernel_->start();
    return true;
}

void Server::stop() {
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
    for (auto &ph : pending_handshakes_) {
        kernel_->del_fd(ph.fd);
        close(ph.fd);
    }
    pending_handshakes_.clear();
    if (kernel_) {
        kernel_->stop();
        kernel_.reset();
    }
}

void Server::check_handshake_timeout() {
    auto now = std::chrono::steady_clock::now();
    auto it = pending_handshakes_.begin();
    while (it != pending_handshakes_.end()) {
        auto elapsed = now - it->accepted_at;
        if (it->got > 0 && elapsed > std::chrono::milliseconds(HANDSHAKE_TIMEOUT_MS)) {
            // Partial data received but stalled — close
            log_debug("server: partial handshake timeout on fd=%d got=%zu", it->fd, it->got);
            close(it->fd);
            kernel_->del_fd(it->fd);
            it = pending_handshakes_.erase(it);
        } else if (it->got == 0 && elapsed > std::chrono::milliseconds(HANDSHAKE_SHORT_TIMEOUT_MS)) {
            // No data received — likely a control connection (new session)
            log_debug("server: pending handshake timeout on fd=%d — treating as new session", it->fd);
            int pending_fd = it->fd;
            kernel_->del_fd(pending_fd);
            finish_handshake(pending_fd, it->buf, 0);
            it = pending_handshakes_.erase(it);
        } else {
            ++it;
        }
    }
}

void Server::finish_handshake(int fd, const uint8_t *buf, size_t len) {
    uint64_t sid = 0;
    uint8_t output_idx = 0;
    bool is_data_conn = false;

    if (len == 9) {
        memcpy(&sid, buf, 8);
        output_idx = buf[8];
        auto it = g_session_registry.find(sid);
        if (it != g_session_registry.end()) {
            auto session = it->second.lock();
            if (session) {
                log_info("data connection for session %llx output %u (fd=%d)",
                         (unsigned long long)sid, output_idx, fd);
                session->add_data_connection(output_idx, fd);
                is_data_conn = true;
            }
        }
    }

    if (!is_data_conn) {
        log_info("client connected (fd=%d), new session", fd);
        auto session = std::make_shared<Session>(fd, password_, kernel_, heartbeat_interval_ms_);
        g_session_registry[session->session_id()] = session;

        std::string challenge = std::to_string(rand()) + std::to_string(time(nullptr));
        session->set_challenge(challenge);
        Packet challenge_pkt = Protocol::make_msg(MSG_AUTH_CHALLENGE,
                                                  challenge.data(), challenge.size());
        session->send_packet(challenge_pkt);

        if (len > 0) {
            session->on_data(buf, len);
        }

        auto k = kernel_;
        kernel_->add_fd_handler(fd, [session, k](int ev_fd, uint32_t events) {
            if (session->client_fd() < 0) return;
            uint8_t rbuf[65536];
            ssize_t n;
            TRACE("SVR OLD HANDLER events=0x%x", events);
            while ((n = read(session->client_fd(), rbuf, sizeof(rbuf))) > 0) {
                TRACE("SVR OLD READ n=%zd state=%d", n, (int)session->state());
                session->on_data(rbuf, (size_t)n);
                if (session->client_fd() < 0) break;
                if (session->state() >= Session::AUTH_DONE) break;
            }
            if (n == 0) {
                k->del_fd(ev_fd);
                session->on_disconnect();
                g_paused_sessions[session->session_id()] = session;
            } else if (n < 0 && errno != EAGAIN) {
                k->del_fd(ev_fd);
                session->on_disconnect();
                g_paused_sessions[session->session_id()] = session;
            }
        });
    }
}
