#pragma once

#include <mkbktr.hpp>

#define LOG(fmt, ...) mk::log::write(__FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define LOG_ASSERT(expr, fmt, ...)                                             \
  do {                                                                         \
    if (!(expr)) {                                                             \
      mk::log::write(__FILE__, __LINE__, fmt, ##__VA_ARGS__);                  \
      MKASSERT(false);                                                         \
    }                                                                          \
  } while (0)

#define LOG_FATAL(fmt, ...)                                                    \
  do {                                                                         \
    mk::log::write(__FILE__, __LINE__, fmt, ##__VA_ARGS__);                    \
    MKASSERT(false);                                                           \
  } while (0)

namespace mk {
namespace log {
void write(const char *filename, int line, const char *fmt, ...);
}
} // namespace mk
