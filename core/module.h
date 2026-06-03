#ifndef MODULE_H
#define MODULE_H

#include <string>
#include <memory>
#include <dlfcn.h>
#include "modules/include/module_api.h"

class Module {
public:
    Module();
    ~Module();

    bool load(const std::string &so_path);
    void *context() const { return ctx_; }

    bool init(int in_fd, int out_fd, ModuleKernel *kapi, const char *config);
    int process(int dir, int trigger_fd);

    const char *name() const;
    const char *desc() const;
    const char *help_text() const;

    bool loaded() const { return handle_ != nullptr; }

private:
    void *handle_ = nullptr;
    void *ctx_ = nullptr;

    using InitFn = void *(*)(int, int, ModuleKernel *, const char *);
    using ProcessFn = int (*)(void *, int, int);
    using NameFn = const char *(*)();
    using DescFn = const char *(*)();
    using HelpFn = const char *(*)();

    InitFn init_fn_ = nullptr;
    ProcessFn process_fn_ = nullptr;
    NameFn name_fn_ = nullptr;
    DescFn desc_fn_ = nullptr;
    HelpFn help_fn_ = nullptr;
};

#endif
