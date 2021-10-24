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

Timer::~Timer() { LOG("Timer(%s): %lums\n", _msg.c_str(), ms() - _start); }

} // namespace time
} // namespace mk
