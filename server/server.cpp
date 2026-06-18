#include "server.h"
#include "session.h"
#include "common/logger.h"
#include "common/utils.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <poll.h>

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

    // Register listen fd with kernel for accept
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

            char client_ip[64];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

            int fl = fcntl(cfd, F_GETFL, 0);
            if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
            // Let kernel auto-tune socket buffers

            // Try to read up to 9 bytes — data connections send 9-byte handshake immediately
            uint8_t header[9];
            ssize_t nread = read(cfd, header, 9);

            {
                uint64_t sid = 0;
                uint8_t output_idx = 0;
                bool is_data_conn = false;

                if (nread == 9) {
                    memcpy(&sid, header, 8);
                    output_idx = header[8];
                    is_data_conn = true;
                } else if (nread < 0 && errno == EAGAIN) {
                    struct pollfd pfd = {cfd, POLLIN, 0};
                    int pret = poll(&pfd, 1, 200);
                    if (pret > 0 && (pfd.revents & POLLIN)) {
                        nread = read(cfd, header, 9);
                        if (nread == 9) {
                            memcpy(&sid, header, 8);
                            output_idx = header[8];
                            is_data_conn = true;
                        }
                    }
                } else if (nread > 0 && nread < 9) {
                    // Partial read: temporarily switch to blocking to get remaining bytes
                    int fl = fcntl(cfd, F_GETFL, 0);
                    if (fl >= 0) fcntl(cfd, F_SETFL, fl & ~O_NONBLOCK);
                    ssize_t n2 = read(cfd, header + nread, 9 - (size_t)nread);
                    if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
                    if (n2 == 9 - nread) {
                        nread = 9;
                        memcpy(&sid, header, 8);
                        output_idx = header[8];
                        is_data_conn = true;
                    }
                }

                if (is_data_conn) {
                    auto it = g_session_registry.find(sid);
                    if (it != g_session_registry.end()) {
                        auto session = it->second.lock();
                        if (session) {
                            log_info("data connection for session %llx output %u (fd=%d)",
                                     (unsigned long long)sid, output_idx, cfd);
                            session->add_data_connection(output_idx, cfd);
                            continue;
                        }
                    }
                    log_error("data connection handshake for unknown session %llx, closing",
                              (unsigned long long)sid);
                    close(cfd);
                    continue;
                }
            }

            log_info("client connected: %s:%d", client_ip, ntohs(client_addr.sin_port));

            auto session = std::make_shared<Session>(cfd, password_, kernel_, heartbeat_interval_ms_);
            g_session_registry[session->session_id()] = session;

            std::string challenge = std::to_string(rand()) + std::to_string(time(nullptr));
            session->set_challenge(challenge);
            Packet challenge_pkt = Protocol::make_msg(MSG_AUTH_CHALLENGE,
                                                      challenge.data(), challenge.size());
            session->send_packet(challenge_pkt);

            kernel_->add_fd_handler(cfd, [session, k](int ev_fd, uint32_t events) {
                if (session->client_fd() < 0) return;
                uint8_t buf[65536];
                ssize_t n;
                TRACE("SVR OLD HANDLER events=0x%x", events);
                while ((n = read(session->client_fd(), buf, sizeof(buf))) > 0) {
                    TRACE("SVR OLD READ n=%zd state=%d", n, (int)session->state());
                    session->on_data(buf, (size_t)n);
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
    }, EPOLLIN);

    // Tick callback to process pending I/O for all sessions
    kernel_->set_tick_callback([]() {
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
    if (kernel_) {
        kernel_->stop();
        kernel_.reset();
    }
}
