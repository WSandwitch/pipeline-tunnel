#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include "core/kernel.h"

class Server {
public:
    Server(const std::string &listen_addr, uint16_t listen_port,
           const std::string &password);
    ~Server();

    bool start(int thread_count = 4);
    void stop();

private:
    std::string listen_addr_;
    uint16_t listen_port_;
    std::string password_;
    std::shared_ptr<Kernel> kernel_;

    int listen_fd_ = -1;

    void accept_loop();
};

#endif
