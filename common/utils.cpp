#include "utils.h"
#include <cstdlib>
#include <cstring>
#include <dirent.h>

bool parse_hostport(const std::string &str, std::string &host, uint16_t &port) {
    auto colon = str.rfind(':');
    if (colon == std::string::npos)
        return false;

    host = str.substr(0, colon);
    int p = atoi(str.c_str() + colon + 1);
    if (p <= 0 || p > 65535)
        return false;
    port = (uint16_t)p;
    return true;
}

std::vector<uint8_t> make_varint_packet(const uint8_t *data, size_t len) {
    std::vector<uint8_t> buf;
    size_t val = len;
    while (val > 0x7F) {
        buf.push_back((uint8_t)((val & 0x7F) | 0x80));
        val >>= 7;
    }
    buf.push_back((uint8_t)(val & 0x7F));
    buf.insert(buf.end(), data, data + len);
    return buf;
}

std::vector<uint8_t> make_varint_packet_with_conn_id(uint8_t conn_id, const uint8_t *data, size_t len) {
    // Wraps {conn_id, data} as a varint-framed packet
    size_t inner_len = 1 + len;
    std::vector<uint8_t> buf;
    size_t val = inner_len;
    while (val > 0x7F) {
        buf.push_back((uint8_t)((val & 0x7F) | 0x80));
        val >>= 7;
    }
    buf.push_back((uint8_t)(val & 0x7F));
    buf.push_back(conn_id);
    buf.insert(buf.end(), data, data + len);
    return buf;
}

std::vector<std::string> scan_modules(const std::string &dir) {
    std::vector<std::string> paths;
    DIR *d = opendir(dir.c_str());
    if (!d)
        return paths;
    struct dirent *entry;
    while ((entry = readdir(d)) != nullptr) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        if (len > 3 && strcmp(name + len - 3, ".so") == 0)
            paths.push_back(dir + "/" + name);
    }
    closedir(d);
    return paths;
}
