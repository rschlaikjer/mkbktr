#include <chrono>

#include <mkbktr/util/log.hpp>
#include <mkbktr/util/time.hpp>

namespace mk {
namespace time {

int64_t ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

Timer::~Timer() {
  const int64_t elapsed_ms = ms() - _start;
  if (elapsed_ms < 5'000) {
    LOG("Timer(%s): %lums\n", _msg.c_str(), elapsed_ms);
    return;
  }

  const int64_t elapsed_s = elapsed_ms / 1000;
  if (elapsed_s < 300) {
    LOG("Timer(%s): %lus\n", _msg.c_str(), elapsed_s);
    return;
  }

  const int64_t elapsed_m = elapsed_s / 60;
  if (elapsed_m < 300) {
    LOG("Timer(%s): %lumin\n", _msg.c_str(), elapsed_m);
    return;
  }

  const int64_t elapsed_h = elapsed_m / 60;
  LOG("Timer(%s): %luhr\n", _msg.c_str(), elapsed_h);
}

} // namespace time
} // namespace mk
