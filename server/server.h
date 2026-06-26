#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <chrono>
#include "core/kernel.h"

class Server {
public:
    Server(const std::string &listen_addr, uint16_t listen_port,
           const std::string &password, int thread_count = 1,
           int heartbeat_interval_ms = 30000);
    ~Server();

    bool start();
    void stop();

private:
    std::string listen_addr_;
    uint16_t listen_port_;
    std::string password_;
    std::shared_ptr<Kernel> kernel_;

    int listen_fd_ = -1;
    int thread_count_;
    int heartbeat_interval_ms_;

    struct PendingHandshake {
        int fd;
        uint8_t buf[9];
        size_t got;
        std::chrono::steady_clock::time_point accepted_at;
    };
    static constexpr int HANDSHAKE_TIMEOUT_MS = 5000;
    std::vector<PendingHandshake> pending_handshakes_;

    void check_handshake_timeout();
    void finish_handshake(int fd, const uint8_t *buf, size_t len);
};

#endif
