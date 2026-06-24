#include "modules.h"
#include "core/module_base.h"
#include "common/logger.h"
#include "common/utils.h"
#include <openssl/sha.h>

static std::string hex_sha256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data.data(), data.size(), hash);
    char hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = 0;
    return std::string(hex);
}

extern "C" {
    void *builtin_copy_init(ModuleChain *, const char *);
    int   builtin_copy_process(void *, int, int, const uint8_t *, size_t);
    const char *builtin_copy_modulename();
    const char *builtin_copy_moduledesc();
    const char *builtin_copy_modulehelp();
    const char *builtin_copy_moduleversion();
}

void register_builtin_modules() {
    ModuleBase base;

    base.name = builtin_copy_modulename();
    base.version = builtin_copy_moduleversion();
    base.mid = hex_sha256(base.name + "|" + base.version + "|" + builtin_copy_moduledesc());
    base.handle = nullptr;
    base.init_fn = &builtin_copy_init;
    base.process_fn = &builtin_copy_process;
    base.name_fn = &builtin_copy_modulename;
    base.desc_fn = &builtin_copy_moduledesc;
    base.help_fn = &builtin_copy_modulehelp;
    base.version_fn = &builtin_copy_moduleversion;
    ModuleBase::register_builtin(base);
}
