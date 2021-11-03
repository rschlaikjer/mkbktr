cmake_minimum_required(VERSION 3.1)
project(mkbktr LANGUAGES C CXX)

set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/;/usr/local/")

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(SEND_ERROR "In-source builds are not allowed.")
endif ()

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE ON)

set(CMAKE_CXX_STANDARD 17)

if (CMAKE_BUILD_TYPE MATCHES Debug)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -gdwarf-4 -g3 -g -rdynamic")
  set(GCC_OPTIMIZATION "-O0")
endif ()

set(GCC_COVERAGE_COMPILE_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-unknown-pragmas -Werror -Wno-error=unused-variable -Wno-error=unused-but-set-variable -Wno-error=pragmas -Wno-error=unused-local-typedefs")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS} ${GCC_OPTIMIZATION}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")

include_directories(include)

include_directories(vendor/mbedtls/include)
add_subdirectory(vendor/mbedtls/library)
add_subdirectory(vendor/mbedtls/include)

add_library(util
  src/util/log.cpp
  src/util/string.cpp
  src/util/time.cpp
  src/util/mem.cpp
)

add_library(core
  src/aes.cpp
  src/delta.cpp
  src/keys.cpp
  src/mapped_nca.cpp
  src/mapped_nca.cpp
  src/rsa.cpp
)
target_link_libraries(core
  util
  mbedcrypto
  mbedx509
  mbedtls
  z
)

add_executable(mkbktr
  src/mkbktr.cpp
)
target_link_libraries(mkbktr
  core
)

add_executable(parse_cnmt
  src/tools/parse_cnmt.cpp
)
target_link_libraries(parse_cnmt
  core
)

add_executable(patch_cnmt
  src/tools/patch_cnmt.cpp
)
target_link_libraries(patch_cnmt
  core
)

add_executable(nca_parse
  src/tools/nca_parse.cpp
)
target_link_libraries(nca_parse
  core
)

add_executable(generate_diff
  src/tools/generate_diff.cpp
)
target_link_libraries(generate_diff
  core
)
