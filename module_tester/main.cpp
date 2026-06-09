#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <memory>
#include <random>
#include <unistd.h>

#include "core/chain.h"
#include "core/config.h"
#include "core/module_base.h"
#include "core/kernel_api.h"

struct TesterKernel {
    std::vector<uint8_t> captured;
    int next_id = 0;
};

static int alloc_id(void *ctx) {
    auto *tk = (TesterKernel *)ctx;
    return tk->next_id++;
}

static int wire_write(void *ctx, int dst, const uint8_t *data, size_t len) {
    (void)dst;
    auto *tk = (TesterKernel *)ctx;
    tk->captured.insert(tk->captured.end(), data, data + len);
    return (int)len;
}

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

    // Load all modules
    ModuleBase::load(mod_dir);

    // Mode: list modules
    if (chain_str.empty()) {
        fprintf(stderr, "Modules in %s:\n", mod_dir.c_str());
        for (auto &kv : ModuleBase::bases) {
            auto &b = kv.second;
            fprintf(stderr, "  %-20s %s\n", b.name.c_str(),
                    b.desc_fn ? b.desc_fn() : "");
        }
        return 0;
    }

    // Parse chain config
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

    // Create two chains with custom kernel API
    TesterKernel tk_a{}, tk_b{};
    KernelAPI kapi_a{&tk_a, alloc_id, wire_write};
    KernelAPI kapi_b{&tk_b, alloc_id, wire_write};

    auto chain_a = std::make_shared<Chain>(cfg, &kapi_a);
    auto chain_b = std::make_shared<Chain>(cfg, &kapi_b);

    if (!chain_a->valid() || !chain_b->valid()) {
        fprintf(stderr, "Chain build failed\n");
        return 1;
    }

    // Generate random test data (malloc'd — push_packet takes ownership)
    uint8_t *test_data = (uint8_t *)malloc(data_size);
    std::vector<uint8_t> original(data_size);
    std::mt19937 rng(42);
    for (size_t i = 0; i < data_size; i++) {
        uint8_t v = (uint8_t)(rng() & 0xFF);
        test_data[i] = v;
        original[i] = v;
    }

    // Encode: push through chain A (dir=1, trigger_idx=0)
    chain_a->push_packet(test_data, data_size, 0, 1);

    if (tk_a.captured.empty()) {
        fprintf(stderr, "FAIL: chain A produced no output\n");
        return 1;
    }

    fprintf(stderr, "[tester] chain A output: %zu bytes\n", tk_a.captured.size());
    fprintf(stderr, "[tester] original hex: ");
    for (size_t i = 0; i < original.size() && i < 64; i++)
        fprintf(stderr, "%02x", original[i]);
    fprintf(stderr, "\n[tester] encoded hex: ");
    for (size_t i = 0; i < tk_a.captured.size() && i < 64; i++)
        fprintf(stderr, "%02x", tk_a.captured[i]);
    fprintf(stderr, "\n");

    // Decode: push through chain B (dir=0, trigger_idx=1)
    // Must malloc for push_packet ownership
    uint8_t *chain_a_out = (uint8_t *)malloc(tk_a.captured.size());
    memcpy(chain_a_out, tk_a.captured.data(), tk_a.captured.size());
    chain_b->push_packet(chain_a_out, tk_a.captured.size(), 1, 0);

    fprintf(stderr, "[tester] chain B output: %zu bytes\n", tk_b.captured.size());
    fprintf(stderr, "[tester] decoded hex: ");
    for (size_t i = 0; i < tk_b.captured.size() && i < 64; i++)
        fprintf(stderr, "%02x", tk_b.captured[i]);
    fprintf(stderr, "\n");

    // Compare (test_data was already freed by chain A's module — don't free it here)
    bool ok = (tk_b.captured.size() == data_size &&
               memcmp(tk_b.captured.data(), original.data(), data_size) == 0);
    if (!ok) {
        fprintf(stderr, "FAIL: data mismatch (%zu bytes expected, %zu got)\n",
                data_size, tk_b.captured.size());
        if (data_size == tk_b.captured.size()) {
            size_t mismatches = 0;
            for (size_t i = 0; i < data_size; i++) {
                if (original[i] != tk_b.captured[i]) {
                    if (mismatches < 10)
                        fprintf(stderr, "  byte %zu: expected 0x%02x got 0x%02x\n",
                                i, original[i], tk_b.captured[i]);
                    mismatches++;
                }
            }
            fprintf(stderr, "  total mismatches: %zu\n", mismatches);
        }
        return 1;
    }

    fprintf(stderr, "PASS: %zu bytes round-trip OK\n", data_size);
    return 0;
}
