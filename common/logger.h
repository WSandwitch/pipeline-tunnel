#ifndef LOGGER_H
#define LOGGER_H

#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstring>

enum LogLevel {
    LOG_ERROR = 0,
    LOG_INFO = 1,
    LOG_DEBUG = 2,
    LOG_TRACE = 3,
};

class Logger {
public:
    static Logger &instance();

    void set_level(LogLevel level);
    LogLevel level() const;

    void vlog(LogLevel lvl, const char *fmt, va_list args);
    void log(LogLevel lvl, const char *fmt, ...);

    void hex_dump(const char *prefix, const uint8_t *data, size_t len);

private:
    Logger() : level_(LOG_ERROR) {}
    LogLevel level_;

    static const char *level_str(LogLevel lvl);
};

#define log_error(...)   Logger::instance().log(LOG_ERROR, __VA_ARGS__)
#define log_info(...)    Logger::instance().log(LOG_INFO, __VA_ARGS__)
#define log_debug(...)   Logger::instance().log(LOG_DEBUG, __VA_ARGS__)
#define log_trace(...)   Logger::instance().log(LOG_TRACE, __VA_ARGS__)
#define log_hex_dump(p, d, l) Logger::instance().hex_dump(p, d, l)

#endif
