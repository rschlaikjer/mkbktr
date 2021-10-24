#pragma once

#include <stdint.h>

#include <string>

namespace mk {
namespace time {

int64_t ms();

class Timer {
public:
  Timer(const std::string &msg) : _msg(msg), _start(ms()) {}
  ~Timer();

private:
  const std::string _msg;
  const int64_t _start;
};

} // namespace time
} // namespace mk
