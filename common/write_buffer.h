#ifndef WRITE_BUFFER_H
#define WRITE_BUFFER_H

#include <cstdint>
#include <vector>
#include <cstring>
#include <unistd.h>

struct WriteBuffer {
    std::vector<uint8_t> buf;
    size_t read_offset = 0;
    bool registered = false;
    size_t high_water = 262144;
    size_t low_water = 131072;

    WriteBuffer() {
        buf.reserve(1048576);
    }

    int write(int fd, const uint8_t *data, size_t len) {
        if (read_offset > 65536 && !buf.empty()) {
            buf.erase(buf.begin(), buf.begin() + read_offset);
            read_offset = 0;
        }
        // If we have unflushed data, always buffer new data to maintain ordering
        if (!buf.empty()) {
            buf.insert(buf.end(), data, data + len);
            return 1;
        }
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                buf.insert(buf.end(), data, data + len);
                return 1;
            }
            return -1;
        }
        if ((size_t)n < len) {
            buf.insert(buf.end(), data + (size_t)n, data + len);
            return 1;
        }
        return 0;
    }

    bool flush(int fd) {
        if (buf.empty()) return true;
        size_t chunk = buf.size() - read_offset;
        ssize_t n = ::write(fd, buf.data() + read_offset, chunk);
        if (n > 0) {
            read_offset += (size_t)n;
            if (read_offset >= buf.size()) {
                buf.clear();
                read_offset = 0;
            }
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return false;
        return read_offset >= buf.size();
    }

    void clear() {
        buf.clear();
        read_offset = 0;
    }

    bool empty() const {
        return buf.empty();
    }

    size_t size() const {
        return buf.size();
    }
};

#endif
