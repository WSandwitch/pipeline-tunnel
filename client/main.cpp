#include "client.h"
#include "common/logger.h"
#include "common/utils.h"
#include "core/config.h"
#include "core/module.h"
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <signal.h>
#include <vector>
#include <string>

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -L[bind_addr:]port:target_host:target_port [-h] [-v[vv]] <chain_config>\n"
        "\n"
        "Options:\n"
        "  -L <spec>            Listen specification\n"
        "                       Examples:\n"
        "                         -L 8080:example.com:80\n"
        "                         -L 127.0.0.1:8080:10.0.0.1:3000\n"
        "  -M <modpath>         Path to directory with .so modules (for --module-*)\n"
        "  -t<N>                Number of worker threads (default 4)\n"
        "  -h                   Show this help\n"
        "  -v, -vv, -vvv        Verbosity level\n"
        "  --module-help <name> Show help for a module\n"
        "  --module-list        List available modules\n"
        "\n"
        "Arguments:\n"
        "  chain_config         Format: server_host:port,password[;module|params]...\n"
        "                       Examples:\n"
        "                         myhost:8080,mypass\n"
        "                         myhost:8080,mypass;compress|gzip:6;crypt|mykey\n"
        "\n"
        "Chain config syntax:\n"
        "  server:port,password              - simple tunnel (no modules)\n"
        "  server:port,password;module|param - single module\n"
        "  server:port,password;mod1|p1;mod2|p2 - multi-module chain\n"
        "\n",
        prog);
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    std::string listen_addr = "0.0.0.0";
    uint16_t listen_port = 0;
    std::string target_addr;
    int verbosity = 0;
    int thread_count = 4;
    bool show_help = false;
    bool show_module_list = false;
    std::string module_help_name;
    std::string mod_dir;
    std::string chain_str;

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
                case 'L': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    // Format: [bind_addr:]port:target_host:target_port
                    std::string s(val);
                    // Count colons: 2 → "port:target_host:target_port"
                    //              3 → "bind_addr:port:target_host:target_port"
                    size_t first = s.find(':');
                    size_t last = s.rfind(':');
                    if (first == std::string::npos || last == std::string::npos || first == last) {
                        fprintf(stderr, "Invalid -L format. Use: [bind_addr:]port:target_host:target_port\n");
                        return 1;
                    }
                    size_t second = s.find(':', first + 1);
                    size_t third = s.find(':', second + 1);
                    if (third == std::string::npos) {
                        // 2 colons: listen_port:target_host:target_port
                        listen_port = (uint16_t)atoi(s.substr(0, first).c_str());
                        target_addr = s.substr(first + 1);
                    } else {
                        // 3+ colons: bind_addr:listen_port:target_host:target_port
                        listen_addr = s.substr(0, first);
                        listen_port = (uint16_t)atoi(s.substr(first + 1, second - first - 1).c_str());
                        target_addr = s.substr(second + 1, third - second - 1) + ":" + s.substr(third + 1);
                    }
                    break;
                }
                case 'v':
                    verbosity = strlen(argv[i]) - 1;
                    break;
                case 'M': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    mod_dir = val;
                    break;
                }
                case 't': {
                    const char *val = argv[i] + 2;
                    if (!val[0] && i + 1 < argc) val = argv[++i];
                    if (val[0]) thread_count = atoi(val);
                    if (thread_count < 1) thread_count = 1;
                    break;
                }
                case 'h':
                    show_help = true;
                    break;
            }
        } else {
            chain_str = argv[i];
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
            if (m.load(p))
                fprintf(stderr, "  %-20s %s\n", m.name(), m.desc());
        }
        return 0;
    }

    if (chain_str.empty()) {
        print_usage(argv[0]);
        return 1;
    }

    if (verbosity >= 3) Logger::instance().set_level(LOG_TRACE);
    else if (verbosity >= 2) Logger::instance().set_level(LOG_DEBUG);
    else if (verbosity >= 1) Logger::instance().set_level(LOG_INFO);

    ChainConfig cfg = parse_chain(chain_str);
    if (!cfg.valid) {
        fprintf(stderr, "Invalid chain config\n");
        return 1;
    }

    Client client(cfg.host, cfg.port, cfg.password,
                  listen_addr, listen_port,
                  target_addr,
                  cfg.modules,
                  mod_dir,
                  thread_count);

    if (!client.start()) {
        log_error("client failed to start");
        return 1;
    }

    log_info("client: waiting for chain...");
    if (!client.wait_ready()) {
        log_error("client: tunnel setup failed");
        return 1;
    }

    log_info("client running. Listening on %s:%d, forwarding to %s",
             listen_addr.c_str(), listen_port, target_addr.c_str());
    log_info("press Ctrl+C to stop.");
    pause();

    client.stop();
    return 0;
}
