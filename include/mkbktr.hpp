#pragma once

#define MKASSERT(expr)                                                         \
  do {                                                                         \
    if (!(expr)) {                                                             \
      asm volatile("ud2");                                                     \
    }                                                                          \
  } while (0)
