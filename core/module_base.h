#ifndef MODULE_BASE_H
#define MODULE_BASE_H

#include <string>
#include <unordered_map>
#include <vector>
#include "modules/include/module_api.h"

struct ModuleBase {
    std::string name;
    void *handle = nullptr;
    void *(*init_fn)(ModuleChain *, const char *config) = nullptr;
    int   (*process_fn)(void *, int dir, int trigger_idx) = nullptr;
    const char *(*name_fn)() = nullptr;
    const char *(*desc_fn)() = nullptr;
    const char *(*help_fn)() = nullptr;

    static std::unordered_map<std::string, ModuleBase> bases;
    static void load(const std::string &directory);
    static const ModuleBase *find(const std::string &name);
};

#endif
