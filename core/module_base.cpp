#include "module_base.h"
#include "common/logger.h"
#include "common/utils.h"
#include <dlfcn.h>
#include <cstdlib>

std::unordered_map<std::string, ModuleBase> ModuleBase::bases;

void ModuleBase::load(const std::string &directory) {
    auto paths = scan_modules(directory);
    for (auto &p : paths) {
        void *handle = dlopen(p.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            log_error("dlopen(%s): %s", p.c_str(), dlerror());
            continue;
        }

        auto name_fn = (const char *(*)())dlsym(handle, "modulename");
        auto desc_fn = (const char *(*)())dlsym(handle, "moduledesc");
        auto help_fn = (const char *(*)())dlsym(handle, "modulehelp");
        auto init_fn = (void *(*)(ModuleChain *, const char *))dlsym(handle, "init");
        auto process_fn = (int (*)(void *, int, int))dlsym(handle, "process");

        if (!init_fn || !process_fn || !name_fn || !desc_fn || !help_fn) {
            log_error("module %s: missing required symbol (init/process/modulename/moduledesc/modulehelp)", p.c_str());
            dlclose(handle);
            continue;
        }

        std::string mod_name = name_fn();
        if (bases.count(mod_name)) {
            log_error("duplicate module name '%s' (%s conflicts with %s)",
                      mod_name.c_str(), p.c_str(), bases[mod_name].name.c_str());
            dlclose(handle);
            std::exit(1);
        }

        ModuleBase base;
        base.name = mod_name;
        base.handle = handle;
        base.init_fn = init_fn;
        base.process_fn = process_fn;
        base.name_fn = name_fn;
        base.desc_fn = desc_fn;
        base.help_fn = help_fn;

        bases[mod_name] = std::move(base);
        log_info("loaded module: %s (%s)", mod_name.c_str(), desc_fn());
    }
}

const ModuleBase *ModuleBase::find(const std::string &name) {
    auto it = bases.find(name);
    if (it == bases.end()) return nullptr;
    return &it->second;
}
