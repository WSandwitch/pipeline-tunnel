#include "logger.h"
#include <cstdio>
#include <cstdlib>
#include <ctime>

Logger &Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::set_level(LogLevel lvl) {
    level_ = lvl;
}

LogLevel Logger::level() const {
    return level_;
}

const char *Logger::level_str(LogLevel lvl) {
    switch (lvl) {
        case LOG_ERROR: return "ERROR";
        case LOG_INFO:  return "INFO";
        case LOG_DEBUG: return "DEBUG";
        case LOG_TRACE: return "TRACE";
        default:        return "?????";
    }
}

void Logger::vlog(LogLevel lvl, const char *fmt, va_list args) {
    if (lvl > level_) return;

    time_t now = time(nullptr);
    struct tm *tm = localtime(&now);

    fprintf(stderr, "[%02d:%02d:%02d] [%s] ",
            tm->tm_hour, tm->tm_min, tm->tm_sec,
            level_str(lvl));
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
}

void Logger::log(LogLevel lvl, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vlog(lvl, fmt, args);
    va_end(args);
}

void Logger::hex_dump(const char *prefix, const uint8_t *data, size_t len) {
    if (LOG_TRACE > level_) return;

    fprintf(stderr, "[%s] %s size=%zu\n", level_str(LOG_TRACE), prefix, len);
    if (len == 0) return;

    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, "       %04zx: ", i);
        for (size_t j = 0; j < 16 && i + j < len; j++)
            fprintf(stderr, "%02x ", data[i + j]);
        fprintf(stderr, "\n");
    }
}
