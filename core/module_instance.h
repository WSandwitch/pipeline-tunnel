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
    std::vector<Module *> near;     // near[0]=к ext, near[1]=к wire, near[2+]=доп выходы
    int wire_dst = -1;              // порт для wire_write на конце цепочки (-1=не крайний)
    size_t cfg_idx = SIZE_MAX;      // индекс в cfg.modules (для построения подцепочек)
    void *ctx = nullptr;
    std::mutex dir_mutex[2];        // per-direction serialization
    std::atomic<int> pending[2]{0, 0}; // tasks queued + processing for this module, per direction
    std::atomic<uint64_t> dir_bytes[2]{0, 0}; // total data bytes pending per direction

    // Heartbeat
    int heartbeat_interval_sec = 0; // 0=not requested, -1=system, >0=own
    std::chrono::steady_clock::time_point last_activity;
    std::mutex hb_mutex;
};

#endif
