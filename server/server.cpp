#include "server.h"
#include "session.h"
#include "common/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

extern std::unordered_map<uint64_t, std::weak_ptr<Session>> g_session_registry;
extern std::unordered_map<uint64_t, std::shared_ptr<Session>> g_paused_sessions;

Server::Server(const std::string &addr, uint16_t port,
               const std::string &password)
    : listen_addr_(addr), listen_port_(port), password_(password) {}

Server::~Server() {
    stop();
}

bool Server::start(int thread_count) {
    kernel_ = std::make_shared<Kernel>();

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

    kernel_->start(thread_count);

    std::thread([this] { accept_loop(); }).detach();

    log_info("server started on %s:%d", listen_addr_.c_str(), listen_port_);
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

void Server::accept_loop() {
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int fd = accept(listen_fd_, (struct sockaddr *)&client_addr, &addrlen);
        if (fd < 0) {
            if (errno == EINTR) continue;
            log_error("accept: %s", strerror(errno));
            break;
        }

        char client_ip[64];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        // Set non-blocking
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);

        // Try to read up to 9 bytes — data connections send 9-byte handshake immediately.
        // New sessions wait for server's challenge, so no data arrives first.
        uint8_t header[9];
        ssize_t nread = read(fd, header, 9);

        if (nread == 9) {
            // Possible data connection: check session_id registry
            uint64_t sid;
            memcpy(&sid, header, 8);
            uint8_t output_idx = header[8];

            auto it = g_session_registry.find(sid);
            if (it != g_session_registry.end()) {
                auto session = it->second.lock();
                if (session) {
                    log_info("data connection for session %llx output %u (fd=%d)",
                             (unsigned long long)sid, output_idx, fd);
                    session->add_data_connection(output_idx, fd);
                    continue;
                }
            }
            // Session not found — close
            log_error("data connection handshake for unknown session %llx, closing",
                      (unsigned long long)sid);
            close(fd);
            continue;
        }

        if (nread > 0 && nread < 9) {
            // Partial read — unexpected, close
            close(fd);
            continue;
        }

        // nread < 0 (EAGAIN) or nread == 0: no data from client yet → new session
        log_info("client connected: %s:%d", client_ip, ntohs(client_addr.sin_port));

        auto session = std::make_shared<Session>(fd, password_, kernel_);
        g_session_registry[session->session_id()] = session;

        // Generate challenge
        std::string challenge = std::to_string(rand()) + std::to_string(time(nullptr));
        session->set_challenge(challenge);
        Packet challenge_pkt = Protocol::make_msg(MSG_AUTH_CHALLENGE,
                                                  challenge.data(), challenge.size());
        session->send_packet(challenge_pkt);

        // Register fd with kernel for read events
        auto k = kernel_;
        kernel_->add_fd_handler(fd, [session, k](int ev_fd, uint32_t events) {
            (void)events;
            if (session->client_fd() < 0)
                return;
            uint8_t buf[65536];
            ssize_t n;
            while ((n = read(session->client_fd(), buf, sizeof(buf))) > 0) {
                session->on_data(buf, (size_t)n);
                if (session->client_fd() < 0) break;
            }
            if (n == 0) {
                k->del_fd(ev_fd);
                session->on_disconnect();
                g_paused_sessions[session->session_id()] = session;
            } else if (n < 0 && errno != EAGAIN) {
                log_debug("session %llx: read error fd=%d errno=%d",
                          (unsigned long long)session->session_id(), ev_fd, errno);
                k->del_fd(ev_fd);
                session->on_disconnect();
                g_paused_sessions[session->session_id()] = session;
            }
        });
    }
}
