#ifndef UTILS_H
#define UTILS_H

#include <cstdint>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

bool parse_hostport(const std::string &str, std::string &host, uint16_t &port);

inline void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

// Wire protocol type byte values
constexpr uint8_t TYPE_DATA = 0;         // [varint(2+len)][0][conn_id][payload] → dispatch → Chain
constexpr uint8_t TYPE_HEARTBEAT1 = 1;   // [varint(1)][1] — empty, ping
constexpr uint8_t TYPE_HEARTBEAT2 = 2;   // [varint(1)][2] — empty, pong

std::vector<uint8_t> make_varint_packet(const uint8_t *data, size_t len);
std::vector<uint8_t> make_varint_packet_with_conn_id(uint8_t conn_id, const uint8_t *data, size_t len);
std::vector<std::string> scan_modules(const std::string &dir);

#endif
