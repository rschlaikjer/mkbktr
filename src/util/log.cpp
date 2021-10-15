#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <mkbktr/util/log.hpp>

namespace mk {
namespace log {

void write(const char *filename, int line, const char *fmt, ...) {
  // Generate timestamp
  char time_buf[32];
  time_t system_time;
  time(&system_time);
  struct tm *timeinfo;
  timeinfo = localtime(&system_time);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", timeinfo);

  // Write log line
  fprintf(stderr, "%s: %d: ", filename, line);
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

} // namespace log
} // namespace mk
