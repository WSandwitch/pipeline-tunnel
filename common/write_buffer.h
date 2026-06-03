#ifndef WRITE_BUFFER_H
#define WRITE_BUFFER_H

#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <unistd.h>

struct WriteBuffer {
    std::vector<uint8_t> buf;
    std::unique_ptr<std::mutex> mtx = std::make_unique<std::mutex>();
    bool registered = false;
    size_t high_water = 262144;
    size_t low_water = 131072;

    int write(int fd, const uint8_t *data, size_t len) {
        std::lock_guard<std::mutex> lock(*mtx);
        if (!buf.empty()) {
            buf.insert(buf.end(), data, data + len);
            return 1;
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
            buf.assign(data + n, data + len - n);
            return 1;
        }
        return 0;
    }

    bool flush(int fd) {
        std::lock_guard<std::mutex> lock(*mtx);
        if (buf.empty()) return true;
        ssize_t n = ::write(fd, buf.data(), buf.size());
        if (n > 0) {
            buf.erase(buf.begin(), buf.begin() + n);
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return false;
        }
        return buf.empty();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(*mtx);
        buf.clear();
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(*mtx);
        return buf.empty();
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(*mtx);
        return buf.size();
    }
};

#endif
