#include "config.h"
#include "common/utils.h"
#include <cstdlib>

ChainConfig parse_chain(const std::string &str) {
    ChainConfig cfg;

    size_t start = 0;
    std::vector<std::string> blocks;

    while (start < str.size()) {
        auto semicolon = str.find(';', start);
        if (semicolon == std::string::npos) {
            blocks.push_back(str.substr(start));
            break;
        }
        blocks.push_back(str.substr(start, semicolon - start));
        start = semicolon + 1;
    }

    if (blocks.empty())
        return cfg;

    // first block: host:port,password
    auto comma = blocks[0].find(',');
    if (comma == std::string::npos) {
        if (!parse_hostport(blocks[0], cfg.host, cfg.port))
            return cfg;
    } else {
        std::string addr = blocks[0].substr(0, comma);
        cfg.password = blocks[0].substr(comma + 1);
        if (!parse_hostport(addr, cfg.host, cfg.port))
            return cfg;
    }

    // remaining blocks: name|params (skip empty blocks)
    for (size_t i = 1; i < blocks.size(); i++) {
        std::string &b = blocks[i];
        if (b.empty()) continue;
        ModuleSpec ms;
        auto pipe = b.find('|');
        if (pipe == std::string::npos) {
            ms.name = b;
        } else {
            ms.name = b.substr(0, pipe);
            ms.params = b.substr(pipe + 1);
        }
        cfg.modules.push_back(std::move(ms));
    }

    cfg.modules.insert(cfg.modules.begin(), ModuleSpec{"copy", ""});
    cfg.modules.emplace_back("copy", "");
    std::reverse(cfg.modules.begin(), cfg.modules.end());
    cfg.valid = true;
    return cfg;
}
