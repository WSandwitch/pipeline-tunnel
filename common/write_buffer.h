#ifndef WRITE_BUFFER_H
#define WRITE_BUFFER_H

#include <cstdint>
#include <deque>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <cerrno>
#include <mutex>
#include <memory>

struct WriteBuffer {
    std::deque<std::vector<uint8_t>> chunks;
    size_t read_offset = 0;
    size_t total_size = 0;
    bool registered = false;
    size_t high_water = 262144;
    size_t low_water = 131072;

    WriteBuffer() {
        mtx_ = std::make_unique<std::mutex>();
    }

    WriteBuffer(WriteBuffer &&other) noexcept
        : chunks(std::move(other.chunks)),
          read_offset(other.read_offset),
          total_size(other.total_size),
          registered(other.registered),
          high_water(other.high_water),
          low_water(other.low_water),
          mtx_(std::move(other.mtx_))
    {
        other.read_offset = 0;
        other.total_size = 0;
        other.registered = false;
    }

    WriteBuffer &operator=(WriteBuffer &&other) noexcept {
        if (this != &other) {
            chunks = std::move(other.chunks);
            read_offset = other.read_offset;
            total_size = other.total_size;
            registered = other.registered;
            high_water = other.high_water;
            low_water = other.low_water;
            mtx_ = std::move(other.mtx_);
            other.read_offset = 0;
            other.total_size = 0;
            other.registered = false;
        }
        return *this;
    }

    int write(int fd, const uint8_t *data, size_t len) {
        std::lock_guard<std::mutex> lock(*mtx_);
        if (!chunks.empty()) {
            chunks.emplace_back(data, data + len);
            total_size += len;
            return 1;
        }
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                chunks.emplace_back(data, data + len);
                total_size += len;
                return 1;
            }
            return -1;
        }
        if ((size_t)n < len) {
            chunks.emplace_back(data + (size_t)n, data + len);
            total_size += (len - (size_t)n);
            return 1;
        }
        return 0;
    }

    bool flush(int fd) {
        std::lock_guard<std::mutex> lock(*mtx_);
        if (chunks.empty()) return true;
        while (!chunks.empty()) {
            auto &front = chunks.front();
            size_t remaining = front.size() - read_offset;
            ssize_t n = ::write(fd, front.data() + read_offset, remaining);
            if (n > 0) {
                read_offset += (size_t)n;
                total_size -= (size_t)n;
                if (read_offset >= front.size()) {
                    chunks.pop_front();
                    read_offset = 0;
                }
            }
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return false;
                return true;
            }
        }
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(*mtx_);
        chunks.clear();
        read_offset = 0;
        total_size = 0;
    }

    bool empty() const {
        return chunks.empty();
    }

    size_t size() const {
        return total_size;
    }

    std::unique_ptr<std::mutex> mtx_;
};

#endif
