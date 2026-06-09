#ifndef MODULE_INSTANCE_H
#define MODULE_INSTANCE_H

#include <mutex>
#include <vector>
#include "modules/include/module_api.h"
#include "module_base.h"

class Chain;

struct Module {
    ModuleBase *base = nullptr;
    ModuleChain api;
    Chain *chain = nullptr;
    int id = -1;
    std::vector<Module *> outputs;  // outputs[dst] → next module, null = wire/kernel
    void *ctx = nullptr;
    std::mutex dir_mutex[2];        // per-direction serialization
};

#endif
