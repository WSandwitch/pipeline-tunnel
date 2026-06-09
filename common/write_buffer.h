#ifndef WRITE_BUFFER_H
#define WRITE_BUFFER_H

#include <cstdint>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <cerrno>
#include <mutex>
#include <memory>

struct WriteBuffer {
    std::vector<uint8_t> buf;
    size_t read_offset = 0;
    bool registered = false;
    size_t high_water = 262144;
    size_t low_water = 131072;

    WriteBuffer() {
        buf.reserve(1048576);
        mtx_ = std::make_unique<std::mutex>();
    }

    WriteBuffer(WriteBuffer &&other) noexcept
        : buf(std::move(other.buf)),
          read_offset(other.read_offset),
          registered(other.registered),
          high_water(other.high_water),
          low_water(other.low_water),
          mtx_(std::move(other.mtx_))
    {
        other.read_offset = 0;
        other.registered = false;
    }

    WriteBuffer &operator=(WriteBuffer &&other) noexcept {
        if (this != &other) {
            buf = std::move(other.buf);
            read_offset = other.read_offset;
            registered = other.registered;
            high_water = other.high_water;
            low_water = other.low_water;
            mtx_ = std::move(other.mtx_);
            other.read_offset = 0;
            other.registered = false;
        }
        return *this;
    }

    int write(int fd, const uint8_t *data, size_t len) {
        std::lock_guard<std::mutex> lock(*mtx_);
        if (read_offset > 65536 && !buf.empty()) {
            buf.erase(buf.begin(), buf.begin() + read_offset);
            read_offset = 0;
        }
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
        std::lock_guard<std::mutex> lock(*mtx_);
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
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return false;
            return true;
        }
        return read_offset >= buf.size();
    }

    void clear() {
        std::lock_guard<std::mutex> lock(*mtx_);
        buf.clear();
        read_offset = 0;
    }

    bool empty() const {
        return buf.empty();
    }

    size_t size() const {
        return buf.size();
    }

    std::unique_ptr<std::mutex> mtx_;
};

#endif
