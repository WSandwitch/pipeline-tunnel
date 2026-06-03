#ifndef LISTENER_H
#define LISTENER_H

#include <cstdint>
#include <string>

class Listener {
public:
    Listener(const std::string &addr, uint16_t port);
    ~Listener();

    bool start();

private:
    std::string addr_;
    uint16_t port_;
    int fd_ = -1;
};

#endif
