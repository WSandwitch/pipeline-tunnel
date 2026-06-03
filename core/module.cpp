#include "module.h"
#include "common/logger.h"
#include <cstring>

Module::Module() {}

Module::~Module() {
    if (handle_)
        dlclose(handle_);
}

bool Module::load(const std::string &so_path) {
    handle_ = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle_) {
        log_error("dlopen(%s): %s", so_path.c_str(), dlerror());
        return false;
    }

    auto sym = [&](const char *name) -> void * {
        return dlsym(handle_, name);
    };

    init_fn_ = (InitFn)sym("init");
    process_fn_ = (ProcessFn)sym("process");
    name_fn_ = (NameFn)sym("modulename");
    desc_fn_ = (DescFn)sym("moduledesc");
    help_fn_ = (HelpFn)sym("modulehelp");

    if (!init_fn_ || !process_fn_ || !name_fn_) {
        log_error("module %s: missing required symbol (init/process/modulename)", so_path.c_str());
        dlclose(handle_);
        handle_ = nullptr;
        return false;
    }

    log_debug("loaded module: %s (%s)", name(), desc() ? desc() : "");
    return true;
}

const char *Module::name() const {
    return name_fn_ ? name_fn_() : "";
}

const char *Module::desc() const {
    return desc_fn_ ? desc_fn_() : "";
}

const char *Module::help_text() const {
    return help_fn_ ? help_fn_() : "";
}

bool Module::init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config) {
    ctx_ = init_fn_(in_fd, out_fd, kapi, config);
    if (!ctx_) {
        log_error("module %s: init failed", name());
        return false;
    }
    log_debug("module %s: initialized", name());
    return true;
}

int Module::process(int dir, int trigger_fd) {
    return process_fn_(ctx_, dir, trigger_fd);
}
