#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <random>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "core/kernel.h"
#include "core/chain.h"
#include "core/config.h"
#include "core/module.h"
#include "common/logger.h"
#include "common/utils.h"

struct TesterState {
    std::vector<uint8_t> result;
    std::mutex mtx;
    std::condition_variable cv;
    bool error = false;
};

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -M <moddir> [-s <size>] [chain_config]\n"
        "\n"
        "Options:\n"
        "  -M <moddir>     Path to directory with .so modules (required)\n"
        "  -s <size>       Size of test data in bytes (default: 4096)\n"
        "  -h              Show this help\n"
        "\n"
        "Without chain_config: list available modules.\n"
        "With chain_config:   run round-trip test through two chains.\n",
        prog);
}

int main(int argc, char *argv[]) {
    std::string mod_dir;
    size_t data_size = 4096;
    std::string chain_str;
    bool show_help = false;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'M': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    mod_dir = val;
                    break;
                }
                case 's': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    if (val[0]) data_size = (size_t)atol(val);
                    break;
                }
                case 'h':
                    show_help = true;
                    break;
            }
        } else {
            chain_str = argv[i];
        }
    }

    if (show_help || mod_dir.empty()) {
        print_usage(argv[0]);
        return mod_dir.empty() ? 1 : 0;
    }

    // Mode: list modules
    if (chain_str.empty()) {
        auto paths = scan_modules(mod_dir);
        fprintf(stderr, "Modules in %s:\n", mod_dir.c_str());
        for (auto &p : paths) {
            Module m;
            if (m.load(p))
                fprintf(stderr, "  %-20s %s\n", m.name(), m.desc() ? m.desc() : "");
        }
        return 0;
    }

    // Mode: run test — parse chain config (host:port,password is optional)
    ChainConfig cfg;
    {
        std::vector<std::string> blocks;
        size_t start = 0;
        while (start < chain_str.size()) {
            auto semicolon = chain_str.find(';', start);
            if (semicolon == std::string::npos) {
                blocks.push_back(chain_str.substr(start));
                break;
            }
            blocks.push_back(chain_str.substr(start, semicolon - start));
            start = semicolon + 1;
        }
        size_t first = 0;
        // Skip address block if present (host:port,password or host:port)
        if (!blocks.empty() && blocks[0].find('|') == std::string::npos) {
            bool has_colon = blocks[0].find(':') != std::string::npos;
            bool has_comma = blocks[0].find(',') != std::string::npos;
            if (has_comma || (has_colon && !blocks[0].empty()))
                first = 1;
        }
        for (size_t i = first; i < blocks.size(); i++) {
            ModuleSpec ms;
            auto pipe = blocks[i].find('|');
            if (pipe == std::string::npos)
                ms.name = blocks[i];
            else {
                ms.name = blocks[i].substr(0, pipe);
                ms.params = blocks[i].substr(pipe + 1);
            }
            cfg.modules.push_back(ms);
        }
        cfg.valid = !cfg.modules.empty();
    }
    if (!cfg.valid) {
        fprintf(stderr, "Invalid chain config (need at least one module)\n");
        return 1;
    }

    auto resolver = [&](const std::string &name) -> std::string {
        auto paths = scan_modules(mod_dir);
        for (auto &p : paths) {
            Module m;
            if (m.load(p) && name == m.name())
                return p;
        }
        return "";
    };

    // Build two chains
    auto chain_a = std::make_shared<Chain>(1, cfg, resolver);
    auto chain_b = std::make_shared<Chain>(2, cfg, resolver);

    if (!chain_a->build() || !chain_b->build()) {
        fprintf(stderr, "Chain build failed\n");
        return 1;
    }

    auto kernel = std::make_shared<Kernel>();
    chain_a->set_kernel(kernel.get());
    chain_b->set_kernel(kernel.get());

    // Set non-blocking and increase buffer
    for (int fd : chain_a->output_fds()) set_nonblock(fd);
    set_nonblock(chain_a->input_fd());
    fcntl(chain_a->input_fd(), F_SETPIPE_SZ, 1048576);
    for (int fd : chain_b->output_fds()) set_nonblock(fd);
    set_nonblock(chain_b->input_fd());
    fcntl(chain_b->input_fd(), F_SETPIPE_SZ, 1048576);

    int A_in = chain_a->input_fd();
    int B_in = chain_b->input_fd();

    // Register module fds with kernel
    for (auto &mf : chain_a->module_fds())
        kernel->add_fd(mf.first, chain_a, mf.second);
    for (auto &mf : chain_b->module_fds())
        kernel->add_fd(mf.first, chain_b, mf.second);

    // Per-output-pair forward state
    struct PairBuf { std::vector<uint8_t> buf; };
    auto a_fds = chain_a->output_fds();
    auto b_fds = chain_b->output_fds();
    size_t n_pairs = std::min(a_fds.size(), b_fds.size());
    auto pair_bufs = std::make_shared<std::vector<PairBuf>>(n_pairs);

    fprintf(stderr, "[tester] A_in=%d A_out=[", chain_a->input_fd());
    for (size_t i = 0; i < a_fds.size(); i++) fprintf(stderr, "%s%d", i?",":"", a_fds[i]);
    fprintf(stderr, "] B_in=%d B_out=[", chain_b->input_fd());
    for (size_t i = 0; i < b_fds.size(); i++) fprintf(stderr, "%s%d", i?",":"", b_fds[i]);
    fprintf(stderr, "]\n");
    fprintf(stderr, "[tester] chain_a module_fds: ");
    for (auto &mf : chain_a->module_fds()) fprintf(stderr, "fd=%d(idx=%d) ", mf.first, mf.second);
    fprintf(stderr, "\n[tester] chain_b module_fds: ");
    for (auto &mf : chain_b->module_fds()) fprintf(stderr, "fd=%d(idx=%d) ", mf.first, mf.second);
    fprintf(stderr, "\n");

    // Forward handlers: each A_out[i] → B_out[i]
    for (size_t i = 0; i < n_pairs; i++) {
        int a_fd = a_fds[i];
        int b_fd = b_fds[i];

        kernel->add_fd_handler(a_fd, [kernel, pair_bufs, b_fd, i](int fd, uint32_t events) {
            fprintf(stderr, "[tester pair=%zu a_fd=%d events=%u]\n", i, fd, events);
            if (events & EPOLLIN) {
                uint8_t buf[65536];
                auto &pbuf = (*pair_bufs)[i].buf;
                size_t before = pbuf.size();
                for (;;) {
                    ssize_t n = read(fd, buf, sizeof(buf));
                    if (n <= 0) break;
                    pbuf.insert(pbuf.end(), buf, buf + n);
                }
                fprintf(stderr, "[tester pair=%zu read %zu bytes, buf=%zu]\n", i, pbuf.size() - before, pbuf.size());
                if (!pbuf.empty()) {
                    ssize_t w = write(b_fd, pbuf.data(), pbuf.size());
                    if (w > 0) {
                        fprintf(stderr, "[tester pair=%zu wrote %zd/%zu]\n", i, w, pbuf.size());
                        pbuf.erase(pbuf.begin(), pbuf.begin() + w);
                    }
                    if (w < 0) {
                        fprintf(stderr, "[tester pair=%zu write errno=%d]\n", i, errno);
                    }
                    if (!pbuf.empty())
                        kernel->mod_fd_events(b_fd, EPOLLOUT, 0);
                }
            }
        });

        kernel->add_fd_handler(b_fd, [kernel, pair_bufs, i](int fd, uint32_t events) {
            fprintf(stderr, "[tester pair=%zu b_fd=%d events=%u]\n", i, fd, events);
            if (events & EPOLLOUT) {
                auto &pbuf = (*pair_bufs)[i].buf;
                if (!pbuf.empty()) {
                    ssize_t w = write(fd, pbuf.data(), pbuf.size());
                    if (w > 0) {
                        fprintf(stderr, "[tester pair=%zu b wrote %zd/%zu]\n", i, w, pbuf.size());
                        pbuf.erase(pbuf.begin(), pbuf.begin() + w);
                    }
                }
                if (pbuf.empty())
                    kernel->mod_fd_events(fd, 0, EPOLLOUT);
            }
        }, EPOLLIN | EPOLLOUT);
    }

    auto state = std::make_shared<TesterState>();

    // Result handler: read from B_in, accumulate data
    kernel->add_fd_handler(B_in, [state](int fd, uint32_t events) {
        if (events & EPOLLIN) {
            uint8_t buf[65536];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                std::lock_guard<std::mutex> lock(state->mtx);
                state->result.insert(state->result.end(), buf, buf + n);
                state->cv.notify_one();
            }
        }
        if (events & EPOLLHUP) {
            std::lock_guard<std::mutex> lock(state->mtx);
            state->error = true;
            state->cv.notify_one();
        }
    });

    kernel->start(4);

    // Generate test data
    std::vector<uint8_t> test_data(data_size);
    std::mt19937 rng(42);
    for (auto &b : test_data)
        b = (uint8_t)(rng() & 0xFF);

    // Frame as varint packet
    auto framed = make_varint_packet(test_data.data(), test_data.size());

    // Write to chain A input (retry loop for partial writes / EAGAIN)
    {
        size_t written_total = 0;
        const uint8_t *p = framed.data();
        size_t remain = framed.size();
        while (remain > 0) {
            ssize_t n = write(A_in, p, remain);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    usleep(1000);
                    continue;
                }
                fprintf(stderr, "Write to chain A input failed: %s\n", strerror(errno));
                kernel->stop();
                return 1;
            }
            p += n;
            remain -= (size_t)n;
            written_total += (size_t)n;
        }
        fprintf(stderr, "[tester] wrote %zu bytes to chain A\n", written_total);
    }

    // Wait for result — poll until a complete varint packet is available
    bool ok = false;
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        std::unique_lock<std::mutex> lock(state->mtx);
        for (;;) {
            // Try to parse a complete varint packet
            auto &res = state->result;
            size_t pos = 0;
            size_t val = 0;
            int shift = 0;
            while (pos < res.size()) {
                uint8_t byte = res[pos++];
                val |= (size_t)(byte & 0x7F) << shift;
                if (!(byte & 0x80)) break;
                shift += 7;
            }
            if (pos > 0 && pos <= res.size() && pos + val <= res.size()) {
                // Complete packet
                std::vector<uint8_t> decoded(res.begin() + pos, res.begin() + pos + val);
                ok = (decoded == test_data);
                if (!ok)
                    fprintf(stderr, "FAIL: data mismatch (%zu bytes expected, %zu got)\n",
                            test_data.size(), decoded.size());
                break;
            }
            if (state->error) {
                fprintf(stderr, "FAIL: handler reported error\n");
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                fprintf(stderr, "FAIL: timeout waiting for result (%zu bytes accumulated)\n",
                        res.size());
                break;
            }
            state->cv.wait_for(lock, std::chrono::milliseconds(100));
        }
    }

    kernel->stop();

    if (ok) {
        fprintf(stderr, "PASS: %zu bytes round-trip OK\n", test_data.size());
        return 0;
    }
    return 1;
}
