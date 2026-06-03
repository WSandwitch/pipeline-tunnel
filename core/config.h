#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>

struct ModuleSpec {
    std::string name;
    std::string params;
};

struct ChainConfig {
    std::string host;
    uint16_t port = 0;
    std::string password;

    std::vector<ModuleSpec> modules;

    bool valid = false;
};

ChainConfig parse_chain(const std::string &str);

#endif
