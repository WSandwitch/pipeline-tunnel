#include "server.h"
#include "core/module_base.h"
#include "common/logger.h"
#include "common/utils.h"
#include <cstring>
#include <cstdlib>
#include <vector>
#include <unordered_map>
#include <memory>
#include <signal.h>
#include <thread>

class Session;

// Session registry for reconnection: session_id -> weak_ptr<Session>
std::unordered_map<uint64_t, std::weak_ptr<Session>> g_session_registry;

// Paused sessions kept alive during disconnect (awaiting reconnect)
std::unordered_map<uint64_t, std::shared_ptr<Session>> g_paused_sessions;

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -l<host:port> -A<password> [-M<modpath>] [-t<N>] [-h] [-v[vv]]\n"
        "\n"
        "Options:\n"
        "  -l <host:port>       Listen address and port\n"
        "  -A <password>        Authentication password\n"
        "  -M <modpath>         Path to directory with .so modules\n"
        "  -t [<N>]             Worker threads (default: 1, auto-detect cores when no value)\n"
        "  -H, --heartbeat <s>  Heartbeat idle interval in seconds (default 30)\n"
        "  -h                   Show this help\n"
        "  -v, -vv, -vvv        Verbosity level (v=info, vv=debug, vvv=trace)\n"
        "  --module-help <name>  Show help for a module\n"
        "  --module-list         List available modules\n"
        "\n"
        "Examples:\n"
        "  %s -l 0.0.0.0:8080 -A mypass -M ./test_modules\n"
        "  %s -l :8080 -A mypass\n"
        "\n",
        prog, prog, prog);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stderr, NULL, _IONBF, 0);
    std::string listen_addr = "0.0.0.0";
    uint16_t listen_port = 0;
    std::string password;
    std::string mod_dir;
    bool show_help = false;
    bool show_module_list = false;
    std::string module_help_name;
    int thread_count = 1;

    int verbosity = 0;
    int heartbeat_sec = 30;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == '-' && strcmp(argv[i], "--module-help") == 0) {
            if (i + 1 < argc) module_help_name = argv[++i];
            continue;
        }
        if (argv[i][0] == '-' && argv[i][1] == '-' && strcmp(argv[i], "--module-list") == 0) {
            show_module_list = true;
            continue;
        }
        if (argv[i][0] == '-' && argv[i][1] == '-' && strcmp(argv[i], "--heartbeat") == 0) {
            const char *val = argv[i] + 11;
            if (!val[0] && i + 1 < argc) val = argv[++i];
            if (val[0]) heartbeat_sec = atoi(val);
            if (heartbeat_sec < 1) heartbeat_sec = 1;
            continue;
        }
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'l': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    auto colon = strchr(val, ':');
                    if (colon) {
                        listen_addr = std::string(val, colon - val);
                        listen_port = (uint16_t)atoi(colon + 1);
                    }
                    break;
                }
                case 'A': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    password = val;
                    break;
                }
                case 'M': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    mod_dir = val;
                    break;
                }
                case 'v':
                    verbosity = strlen(argv[i]) - 1;
                    break;
                case 'H': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    if (val[0]) heartbeat_sec = atoi(val);
                    if (heartbeat_sec < 1) heartbeat_sec = 1;
                    break;
                }
                case 'h':
                    show_help = true;
                    break;
                case 't': {
                    const char *val = argv[i] + 2;
                    if (val[0]) {
                        thread_count = atoi(val);
                    } else if (i + 1 < argc && argv[i+1][0] >= '0' && argv[i+1][0] <= '9') {
                        val = argv[++i];
                        thread_count = atoi(val);
                    } else {
                        thread_count = std::thread::hardware_concurrency();
                    }
                    if (thread_count < 1) thread_count = 1;
                    break;
                }
            }
        }
    }

    if (show_help) {
        print_usage(argv[0]);
        return 0;
    }

    if (!module_help_name.empty()) {
        if (mod_dir.empty()) {
            fprintf(stderr, "Use -M <modpath> to specify module directory\n");
            return 1;
        }
        ModuleBase::load(mod_dir);
        auto *base = ModuleBase::find(module_help_name);
        if (base) {
            fprintf(stderr, "Module: %s\n", base->name.c_str());
            fprintf(stderr, "Description: %s\n", base->desc_fn());
            const char *help = base->help_fn();
            if (help && help[0])
                fprintf(stderr, "\n%s\n", help);
            else
                fprintf(stderr, "(no help available)\n");
        } else {
            fprintf(stderr, "Module '%s' not found in %s\n", module_help_name.c_str(), mod_dir.c_str());
        }
        return 0;
    }

    if (show_module_list) {
        if (mod_dir.empty()) {
            fprintf(stderr, "Use -M <modpath> to specify module directory\n");
            return 1;
        }
        ModuleBase::load(mod_dir);
        fprintf(stderr, "Modules in %s:\n", mod_dir.c_str());
        for (auto &kv : ModuleBase::bases)
            fprintf(stderr, "  %-20s %s\n", kv.first.c_str(), kv.second.desc_fn());
        return 0;
    }

    if (listen_port == 0 || password.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    if (verbosity >= 3) Logger::instance().set_level(LOG_TRACE);
    else if (verbosity >= 2) Logger::instance().set_level(LOG_DEBUG);
    else if (verbosity >= 1) Logger::instance().set_level(LOG_INFO);

    // Load modules from directory
    if (!mod_dir.empty()) {
        ModuleBase::load(mod_dir);
    }

    Server server(listen_addr, listen_port, password, thread_count, heartbeat_sec * 1000);
    if (!server.start()) {
        log_error("server failed to start");
        return 1;
    }

    log_info("server running. press Ctrl+C to stop.");
    server.stop();
    return 0;
}
