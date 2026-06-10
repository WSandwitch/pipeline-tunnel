#ifndef MODULE_INSTANCE_H
#define MODULE_INSTANCE_H

#include <mutex>
#include <vector>
#include <chrono>
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

    // Heartbeat
    int heartbeat_interval_sec = 0; // 0=not requested, -1=system, >0=own
    std::chrono::steady_clock::time_point last_activity;
    std::mutex hb_mutex;
};

#endif
