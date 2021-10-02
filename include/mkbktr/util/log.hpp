#pragma once

#include <mkbktr.hpp>

#define LOG(fmt, ...)                                                          \
  mkbktr::log::write(__FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define LOG_ASSERT(expr, fmt, ...)                                             \
  do {                                                                         \
    if (!(expr)) {                                                             \
      mkbktr::log::write(__FILE__, __LINE__, fmt, ##__VA_ARGS__);              \
      MKASSERT(false);                                                         \
    }                                                                          \
  } while (0)

#define LOG_FATAL(fmt, ...)                                                    \
  do {                                                                         \
    mkbktr::log::write(__FILE__, __LINE__, fmt, ##__VA_ARGS__);                \
    MKASSERT(false);                                                           \
  } while (0)

namespace mkbktr {
namespace log {
void write(const char *filename, int line, const char *fmt, ...);
}
} // namespace mkbktr
