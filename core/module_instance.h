#ifndef MODULE_INSTANCE_H
#define MODULE_INSTANCE_H

#include "modules/include/module_api.h"
#include "module_base.h"

class Chain;

struct Module {
    ModuleBase *base = nullptr;
    ModuleChain api;
    Chain *chain = nullptr;
    int id = -1;
    int outputs = 1;
    void *ctx = nullptr;
};

#endif
