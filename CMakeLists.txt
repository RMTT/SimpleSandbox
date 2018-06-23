cmake_minimum_required(VERSION 2.8)

project(imcoder-judger)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build/lib)

include_directories(src/core/logger)
include_directories(src/core/compile)
include_directories(src/common)
add_subdirectory(src)

add_executable(judger test.c)
target_link_libraries(judger core)
target_link_libraries(judger seccomp)