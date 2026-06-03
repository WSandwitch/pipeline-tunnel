#include "server.h"
#include "core/module.h"
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

// Global module registry: module_name -> .so path
std::unordered_map<std::string, std::string> g_module_registry;

// Session registry for reconnection: session_id -> weak_ptr<Session>
std::unordered_map<uint64_t, std::weak_ptr<Session>> g_session_registry;

// Paused sessions kept alive during disconnect (awaiting reconnect)
std::unordered_map<uint64_t, std::shared_ptr<Session>> g_paused_sessions;

static void load_modules(const std::string &dir) {
    auto paths = scan_modules(dir);
    for (auto &p : paths) {
        Module m;
        if (m.load(p)) {
            std::string mod_name = m.name();
            g_module_registry[mod_name] = p;
            log_info("registered module: %s -> %s", mod_name.c_str(), p.c_str());
        }
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -l<host:port> -A<password> [-M<modpath>] [-t<N>] [-h] [-v[vv]]\n"
        "\n"
        "Options:\n"
        "  -l <host:port>       Listen address and port\n"
        "  -A <password>        Authentication password\n"
        "  -M <modpath>         Path to directory with .so modules\n"
        "  -t [<N>]             Worker threads (default: 1, auto-detect cores when no value)\n"
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

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == '-' && strcmp(argv[i], "--module-help") == 0) {
            if (i + 1 < argc) module_help_name = argv[++i];
            continue;
        }
        if (argv[i][0] == '-' && argv[i][1] == '-' && strcmp(argv[i], "--module-list") == 0) {
            show_module_list = true;
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
        Module m;
        std::string so_path = mod_dir + "/" + module_help_name + ".so";
        if (m.load(so_path)) {
            fprintf(stderr, "Module: %s\n", m.name());
            fprintf(stderr, "Description: %s\n", m.desc());
            const char *help = m.help_text();
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
        auto paths = scan_modules(mod_dir);
        fprintf(stderr, "Modules in %s:\n", mod_dir.c_str());
        for (auto &p : paths) {
            Module m;
            if (m.load(p)) {
                fprintf(stderr, "  %-20s %s\n", m.name(), m.desc());
            }
        }
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
        load_modules(mod_dir);
    }

    Server server(listen_addr, listen_port, password);
    if (!server.start(thread_count)) {
        log_error("server failed to start");
        return 1;
    }

    log_info("server running. press Ctrl+C to stop.");
    pause();
    server.stop();
    return 0;
}
