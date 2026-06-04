#ifndef WRITE_BUFFER_H
#define WRITE_BUFFER_H

#include <cstdint>
#include <vector>
#include <unistd.h>

struct WriteBuffer {
    std::vector<uint8_t> buf;
    size_t read_offset = 0;
    bool registered = false;
    size_t high_water = 262144;
    size_t low_water = 131072;

    int write(int fd, const uint8_t *data, size_t len) {
        size_t pending = buf.size() - read_offset;
        if (pending > 0) {
            buf.insert(buf.end(), data, data + len);
            return 1;
        }
        if (read_offset > 0) {
            buf.clear();
            read_offset = 0;
        }
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                buf.assign(data, data + len);
                return 1;
            }
            return -1;
        }
        if ((size_t)n < len) {
            buf.assign(data + n, data + len);
            return 1;
        }
        return 0;
    }

    bool flush(int fd) {
        size_t pending = buf.size() - read_offset;
        if (pending == 0) return true;
        ssize_t n = ::write(fd, buf.data() + read_offset, pending);
        if (n > 0) {
            read_offset += n;
            if (read_offset >= buf.size()) {
                buf.clear();
                read_offset = 0;
            } else if (read_offset > 65536) {
                buf.erase(buf.begin(), buf.begin() + read_offset);
                read_offset = 0;
            }
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return false;
        }
        return buf.empty() && read_offset == 0;
    }

    void clear() {
        buf.clear();
        read_offset = 0;
    }

    bool empty() {
        return buf.empty() || read_offset == buf.size();
    }

    size_t size() {
        return buf.size() - read_offset;
    }
};

#endif
